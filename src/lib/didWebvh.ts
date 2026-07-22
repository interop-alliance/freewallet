/**
 * did:webvh hosting: provisions and publishes a hash-chained, self-certifying
 * did:webvh DID log alongside the did:web document, in the same `id`
 * collection of the user's WAS Space, with the log's update key held in the
 * user's WebKMS keystore.
 *
 * The log (`did.jsonl`) is one more world-readable WAS Resource, so hosting
 * needs zero server changes:
 * `did:webvh:<scid>:<host>:space:<spaceId>:id` resolves to
 * `https://<host>/space/<spaceId>/id/did.jsonl`. Adopting the parallel
 * `webDoc` (`did:web:` projection with `alsoKnownAs` cross-links) as the new
 * `did.json` makes the log the single source of truth.
 *
 * All protocol logic lives in `@interop/did-method-webvh`; this module is the
 * WebKMS <-> library glue: a `Signer` bridge over a KMS `AsymmetricKey`, the
 * update-key provisioning, the idempotent, crash-resumable provisioning flow
 * (`ensureDidWebvh`), and the lost-`keys.json` recovery path
 * (`repairKeyBindings`, which rediscovers key bindings from the published
 * artifacts plus a WebKMS key listing). Signing is fully injected -- no raw
 * private key ever leaves the keystore.
 */
import {
  createDID,
  deriveNextKeyHash,
  logToJsonlString,
  readLogFromString,
  resolveDIDFromLog,
  SCID_PLACEHOLDER,
  signerFromExternalKey,
  updateDID
} from '@interop/did-method-webvh'
import type {
  DIDLog,
  Signer,
  VerificationMethod
} from '@interop/did-method-webvh'
import type { KeystoreAgent } from '@interop/webkms-client'
import {
  DID_DOCUMENT_RESOURCE,
  DID_KEYS_RESOURCE,
  DID_LOG_RESOURCE,
  ID_COLLECTION
} from '@/app.config'
import { multibaseOf } from '@/lib/didWeb'
import type { DidWebKey, DidWebKeyMap } from '@/lib/didWeb'
import { getKmsSignFunction } from '@/lib/kms'
import type { Session } from '@/types/auth'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

/**
 * The Multikey verification-method type the did:webvh data model uses for both
 * the Ed25519 (authentication/assertionMethod) and X25519 (keyAgreement) keys.
 * Adopting `webDoc` as `did.json` (decision 5) flips the Phase 1 2020-suite VM
 * types to this single type; the same key material and multibase are carried,
 * only `type` and `@context` change, and `@digitalcredentials/verifier-core`
 * verifies `Ed25519Signature2020` / `eddsa-rdfc-2022` proofs against it.
 */
const MULTIKEY_VM_TYPE = 'Multikey'

/**
 * The publicAliasTemplate placeholder the WebKMS server expands to a generated
 * key's multibase fingerprint. Reused from Phase 1: the update key's alias is a
 * self-describing `did:key:z6Mk...#z6Mk...` string, so the bare
 * `publicKeyMultibase` (for `parameters.updateKeys`) falls out of the fragment.
 */
const PUBLIC_KEY_MULTIBASE_PLACEHOLDER = '{publicKeyMultibase}'

/**
 * The log's update authority: a dedicated KMS-held Ed25519 key, never a
 * document verification method and never the root did:key. `kmsKeyId` invokes
 * signing; `publicKeyMultibase` goes in `parameters.updateKeys`.
 */
export interface WebvhUpdateKey {
  kmsKeyId: string
  publicKeyMultibase: string
}

/**
 * A pre-rotation (staged) update key: an update key plus the
 * `deriveNextKeyHash` value committed in `parameters.nextKeyHashes`, so the
 * next log update must reveal this key and it signs its own activation.
 */
export interface WebvhStagedKey extends WebvhUpdateKey {
  nextKeyHash: string
}

/**
 * The `webvh` block added to `keys.json` v2 (decision 4), a sibling of the
 * Phase 1 relationship map. Absent block = pre-Phase-2 record; everything
 * degrades to did:web behavior, no format-version bump (additive convention).
 * The current update key and committed next key are written here before the log
 * that references them is published, so a lost `kmsKeyId` can never freeze the
 * log.
 */
export interface DidWebvhBlock {
  // Set only after the log is published (step 6); its absence with the keys
  // present is the torn-resume signal.
  did?: string
  updateKey: WebvhUpdateKey
  stagedKey: WebvhStagedKey
  // Prior update keys, an audit trail grown by the rotation ceremony (F2.d).
  retiredKeys?: WebvhUpdateKey[]
  // A rotation-in-flight anchor (F2.d): the freshly generated NEXT staged key,
  // written here BEFORE the log that commits it is published (the decision 4
  // invariant), keeping the current `updateKey`/`stagedKey` roles intact until
  // the ceremony finalizes. Its presence means a rotation was interrupted; both
  // the current and pending kmsKeyIds stay recorded throughout, so a re-run can
  // re-derive which key satisfies the published log. Cleared on finalize (it
  // becomes the new `stagedKey`). Additive; absent on every steady-state record.
  pendingStagedKey?: WebvhStagedKey
}

/**
 * `keys.json` v2: the Phase 1 key map plus the optional `webvh` block. The
 * did:web parse/guard tolerates and preserves the block, so a round-trip
 * through `ensureDidWeb` never strips it.
 */
export type DidWebKeyMapV2 = DidWebKeyMap & { webvh?: DidWebvhBlock }

/**
 * The `did:webvh:{SCID}:<host>:space:<spaceId>:id` controller template, with
 * the literal `{SCID}` placeholder the library replaces at creation. The host
 * segment percent-encodes a port (`localhost:8080` becomes `localhost%3A8080`),
 * matching the library's `toDidDomainComponent`.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @returns {string}
 */
export function didWebvhControllerTemplate({
  wasServerUrl,
  spaceId
}: {
  wasServerUrl: string
  spaceId: string
}): string {
  const { host } = new URL(wasServerUrl)
  return `did:webvh:${SCID_PLACEHOLDER}:${encodeURIComponent(host)}:space:${spaceId}:id`
}

/**
 * Bridges a WebKMS `AsymmetricKey`-like signer to the did:webvh `Signer`
 * interface via the library's `signerFromExternalKey`. The only freewallet
 * seam is the shape adapter: a WebKMS `AsymmetricKey.sign({ data })` matches
 * the factory's `sign({ data })` bridge exactly, so the proof-value multibase
 * encoding and the load-bearing `did:key:<pkm>#<pkm>` verification-method id
 * (which the resolver matches against the entry's authorized `updateKeys`) are
 * owned by the library, not duplicated here.
 *
 * @param options {object}
 * @param options.key {object}   a `{ sign({ data }): Promise<Uint8Array> }`
 *   (a WebKMS `AsymmetricKey`, or any key with the same `sign` shape).
 * @param options.publicKeyMultibase {string}   the update key's bare multibase.
 * @returns {Signer}
 */
export function kmsUpdateKeySigner({
  key,
  publicKeyMultibase
}: {
  key: { sign(input: { data: Uint8Array }): Promise<Uint8Array> }
  publicKeyMultibase: string
}): Signer {
  return signerFromExternalKey({
    publicKeyMultibase,
    sign: async ({ data }) => {
      const signature = await key.sign({ data })
      // Re-wrap as a plain Uint8Array: a signer may return a Node Buffer (or
      // a cross-realm view), which the library's strict byte check rejects.
      return new Uint8Array(
        signature.buffer,
        signature.byteOffset,
        signature.byteLength
      )
    }
  })
}

/**
 * Generates one KMS update key (active or staged) with the did:key
 * publicAliasTemplate, returning its durable binding. The bare multibase is
 * recovered from the alias fragment; no separate key-description read.
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}
 * @returns {Promise<WebvhUpdateKey>}
 */
async function generateUpdateKey({
  keystoreAgent
}: {
  keystoreAgent: KeystoreAgent
}): Promise<WebvhUpdateKey> {
  const key = await keystoreAgent.generateKey({
    category: 'asymmetric',
    publicAliasTemplate: `did:key:${PUBLIC_KEY_MULTIBASE_PLACEHOLDER}#${PUBLIC_KEY_MULTIBASE_PLACEHOLDER}`
  })
  if (!key.id || !key.kmsId) {
    throw new Error('KMS generateKey returned no id for a webvh update key.')
  }
  return { kmsKeyId: key.kmsId, publicKeyMultibase: multibaseOf(key.id) }
}

/**
 * Generates a staged (pre-rotation) update key and derives its
 * `nextKeyHashes` commitment.
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}
 * @returns {Promise<WebvhStagedKey>}
 */
async function generateStagedKey({
  keystoreAgent
}: {
  keystoreAgent: KeystoreAgent
}): Promise<WebvhStagedKey> {
  const key = await generateUpdateKey({ keystoreAgent })
  const nextKeyHash = await deriveNextKeyHash(key.publicKeyMultibase)
  return { ...key, nextKeyHash }
}

/**
 * Assembles the three Phase 1 keys as `{SCID}`-templated Multikey verification
 * methods for the create entry. Each id carries the full `publicKeyMultibase`
 * fragment (recovered from the did:web `vmId`), so `createDID` mints
 * `did:webvh:<scid>:...#<multibase>` ids -- no KMS read.
 *
 * @param options {object}
 * @param options.controllerTemplate {string}   the `{SCID}` controller id
 * @param options.didWebKeys {DidWebKeyMap}
 * @returns {object}   `verificationMethods` + relationship arrays for createDID
 */
function assembleWebvhVerificationMethods({
  controllerTemplate,
  didWebKeys
}: {
  controllerTemplate: string
  didWebKeys: DidWebKeyMap
}): {
  verificationMethods: VerificationMethod[]
  authentication: string[]
  assertionMethod: string[]
  keyAgreement: string[]
} {
  const vmId = (key: DidWebKey) =>
    `${controllerTemplate}#${multibaseOf(key.vmId)}`
  const method = (key: DidWebKey): VerificationMethod => ({
    id: vmId(key),
    type: MULTIKEY_VM_TYPE,
    controller: controllerTemplate,
    publicKeyMultibase: multibaseOf(key.vmId)
  })
  return {
    verificationMethods: [
      method(didWebKeys.authentication),
      method(didWebKeys.assertionMethod),
      method(didWebKeys.keyAgreement)
    ],
    authentication: [vmId(didWebKeys.authentication)],
    assertionMethod: [vmId(didWebKeys.assertionMethod)],
    keyAgreement: [vmId(didWebKeys.keyAgreement)]
  }
}

/**
 * Wraps a KMS `AsymmetricKey` fetched by kmsKeyId as a raw-bytes signer for the
 * webvh log. The update key lives in the root-controlled keystore, so signing
 * goes through the keystore agent.
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}
 * @param options.updateKey {WebvhUpdateKey}
 * @returns {Promise<Signer>}
 */
async function updateKeySigner({
  keystoreAgent,
  updateKey
}: {
  keystoreAgent: KeystoreAgent
  updateKey: WebvhUpdateKey
}): Promise<Signer> {
  const sign = await getKmsSignFunction({
    keystoreAgent,
    id: `did:key:${updateKey.publicKeyMultibase}#${updateKey.publicKeyMultibase}`,
    kmsKeyId: updateKey.kmsKeyId
  })
  return kmsUpdateKeySigner({
    key: { sign },
    publicKeyMultibase: updateKey.publicKeyMultibase
  })
}

/**
 * Creates the one-entry did:webvh log and its parallel `webDoc`. Extracted so
 * both the fresh-generate path and the torn-resume path (keys, no did) share
 * identical create wiring. `portable: true` is set at entry 1 (it can only be
 * enabled there); the three VMs come from Phase 1 (decision 3), signed by the
 * active update key with prerotation committed to the staged key.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @param options.didWebKeys {DidWebKeyMap}
 * @param options.webvh {DidWebvhBlock}
 * @param options.signer {Signer}
 * @returns {Promise<{ log: DIDLog; webDoc: object; did: string }>}
 */
async function createWebvhLog({
  wasServerUrl,
  spaceId,
  didWebKeys,
  webvh,
  signer
}: {
  wasServerUrl: string
  spaceId: string
  didWebKeys: DidWebKeyMap
  webvh: DidWebvhBlock
  signer: Signer
}): Promise<{ log: DIDLog; webDoc: object; did: string }> {
  const { host } = new URL(wasServerUrl)
  const controllerTemplate = didWebvhControllerTemplate({
    wasServerUrl,
    spaceId
  })
  const { verificationMethods, authentication, assertionMethod, keyAgreement } =
    assembleWebvhVerificationMethods({ controllerTemplate, didWebKeys })

  const result = await createDID({
    address: host,
    paths: ['space', spaceId, ID_COLLECTION.id],
    signer,
    updateKeys: [webvh.updateKey.publicKeyMultibase],
    nextKeyHashes: [webvh.stagedKey.nextKeyHash],
    verificationMethods,
    authentication,
    assertionMethod,
    keyAgreement,
    alsoKnownAsWeb: true,
    portable: true
  })
  if (!result.webDoc) {
    throw new Error('createDID did not return a webDoc despite alsoKnownAsWeb.')
  }
  return { log: result.log, webDoc: result.webDoc, did: result.did }
}

/**
 * Publishes an already-created log: PUT `did.jsonl` (`text/jsonl`) -> public on
 * it -> PUT `did.json` from `webDoc` (`application/did+json`, adopting the
 * webvh projection per decision 5) -> public on it (idempotent for a Space
 * whose `did.json` is already public from Phase 1). The shared publish tail of
 * the fresh and resume paths.
 *
 * @param options {object}
 * @param options.remoteStore {WASRemoteStore}
 * @param options.log {DIDLog}
 * @param options.webDoc {object}
 * @returns {Promise<void>}
 */
async function publishWebvhLog({
  remoteStore,
  log,
  webDoc
}: {
  remoteStore: WASRemoteStore
  log: DIDLog
  webDoc: object
}): Promise<void> {
  await remoteStore.putIdResource({
    resourceId: DID_LOG_RESOURCE,
    content: logToJsonlString(log),
    contentType: 'text/jsonl'
  })
  await remoteStore.setIdResourcePublic({ resourceId: DID_LOG_RESOURCE })
  await remoteStore.putIdResource({
    resourceId: DID_DOCUMENT_RESOURCE,
    content: webDoc,
    contentType: 'application/did+json'
  })
  await remoteStore.setIdResourcePublic({ resourceId: DID_DOCUMENT_RESOURCE })
}

/**
 * Writes `keys.json` v2: the Phase 1 relationship map plus the `webvh` block,
 * preserving the three did:web relationships. Called twice -- to anchor the
 * update keys before publish (no `did`), then to finalize with `did` set.
 */
async function writeKeysJson({
  remoteStore,
  didWebKeys,
  webvh
}: {
  remoteStore: WASRemoteStore
  didWebKeys: DidWebKeyMap
  webvh: DidWebvhBlock
}): Promise<void> {
  const content: DidWebKeyMapV2 = { ...didWebKeys, webvh }
  await remoteStore.putIdResource({
    resourceId: DID_KEYS_RESOURCE,
    content
  })
}

/**
 * Idempotently provisions and publishes the user's did:webvh DID log, run
 * directly after {@link ensureDidWeb} from `StorageManager.ensureUserCollections`
 * (non-fatal). Implements decision 6's steps and the torn-state
 * matrix:
 *
 * | keys.json.webvh | did.jsonl | action                                      |
 * | --------------- | --------- | ------------------------------------------- |
 * | absent          | absent    | fresh run: generate keys, anchor, create,   |
 * |                 |           |   publish, finalize                          |
 * | keys, no did    | absent    | resume: reuse keys, create, publish, finalize|
 * | keys, no did    | present   | crashed in finalize: fetch log,             |
 * |                 |           |   resolveDIDFromLog, reconcile did           |
 * | did present     | present   | steady state, done                          |
 * | absent/lost     | present   | frozen log (decision 4 prevents): repair    |
 * |                 |           |   via {@link repairKeyBindings}              |
 *
 * The already-parsed `keys.json` from `ensureDidWeb` is threaded in so steady
 * state stays one read total (plus one HEAD on the log).
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}
 * @param options.remoteStore {WASRemoteStore}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @param options.didWebKeys {DidWebKeyMapV2}   the parsed keys.json (with any
 *   webvh block) returned by ensureDidWeb.
 * @returns {Promise<DidWebvhBlock>}   the finalized webvh block (with `did`).
 */
export async function ensureDidWebvh({
  keystoreAgent,
  remoteStore,
  wasServerUrl,
  spaceId,
  didWebKeys
}: {
  keystoreAgent: KeystoreAgent
  remoteStore: WASRemoteStore
  wasServerUrl: string
  spaceId: string
  didWebKeys: DidWebKeyMapV2
}): Promise<DidWebvhBlock> {
  // A single raw read of the log doubles as the existence probe (WAS returns
  // 404 -- and this returns undefined -- for a missing resource) and the body
  // the torn-resume row needs.
  const logText = await remoteStore.getIdResourceRaw({
    resourceId: DID_LOG_RESOURCE
  })
  const logExists = logText !== undefined

  // Steady state: keys anchored with a did, and the log is published.
  if (didWebKeys.webvh?.did && logExists) {
    return didWebKeys.webvh
  }

  // Frozen-log row (decision 4), downgraded from a dead end to a repair: a
  // published log with no recorded update key can resolve but never update.
  // The write ordering below prevents this state on freewallet-provisioned
  // Spaces; when it is seen anyway (a lost or rolled-back keys.json), rebuild
  // the bindings from the published artifacts plus a WebKMS key listing.
  // Listing stays repair-only; keys.json remains the steady-state read.
  if (!didWebKeys.webvh && logExists) {
    console.warn(
      'did:webvh: did.jsonl exists but keys.json has no webvh block -- the ' +
        'update key id is lost; attempting key-binding repair via WebKMS ' +
        'List Keys.'
    )
    const repaired = await repairKeyBindings({ keystoreAgent, remoteStore })
    if (!repaired.webvh) {
      // Unreachable while the log exists (repair either rebuilds the block or
      // throws); a type-narrowing backstop.
      throw new Error('did:webvh: repair did not recover the update key.')
    }
    return repaired.webvh
  }

  // Steps 2-3: reuse anchored keys (torn resume) or generate a fresh pair, then
  // anchor keys.json with the webvh block (no `did` yet). Generating both keys
  // only when neither is recorded keeps the resume path from minting orphans.
  let webvh: DidWebvhBlock
  if (didWebKeys.webvh) {
    webvh = didWebKeys.webvh
  } else {
    const updateKey = await generateUpdateKey({ keystoreAgent })
    const stagedKey = await generateStagedKey({ keystoreAgent })
    webvh = { updateKey, stagedKey }
    await writeKeysJson({ remoteStore, didWebKeys, webvh })
  }

  const signer = await updateKeySigner({
    keystoreAgent,
    updateKey: webvh.updateKey
  })

  // Torn row (keys, no did, log present): the create crashed after publishing
  // the log but before finalize. Re-creating would mint a fresh SCID and
  // diverge from the public log, so instead adopt the published log's id.
  let did: string
  if (logText !== undefined) {
    const resolved = await resolveDIDFromLog(readLogFromString(logText))
    if (resolved.meta.error || !resolved.did) {
      throw new Error(
        `did:webvh: existing did.jsonl failed to resolve (${resolved.meta.error}).`
      )
    }
    did = resolved.did
  } else {
    // Steps 4-5: create the log with the active update key, then publish.
    const created = await createWebvhLog({
      wasServerUrl,
      spaceId,
      didWebKeys,
      webvh,
      signer
    })
    await publishWebvhLog({
      remoteStore,
      log: created.log,
      webDoc: created.webDoc
    })
    did = created.did
  }

  // Step 6: finalize keys.json with the resolved/created did.
  const finalized: DidWebvhBlock = { ...webvh, did }
  await writeKeysJson({ remoteStore, didWebKeys, webvh: finalized })
  return finalized
}

/**
 * Rebuilds `keys.json` from the published artifacts plus a WebKMS key listing
 * -- the recovery path for a lost or rolled-back `keys.json` (the torn-state
 * matrix's frozen-log row). Full tier only: List Keys is authorized as `read`
 * against the keystore controller, which only the root-controlled keystore
 * agent can invoke.
 *
 * KMS key local ids are server-generated random and appear in no published
 * artifact, so the bindings are rediscovered by public key material instead.
 * List the keystore once -- each listed description carries `keyUrl`, the
 * key's canonical invocation URL (the signable handle its alias-overridden
 * `id` erases) -- then:
 *
 * (a) match `did.json`'s three relationship verification methods by
 *     `publicKeyMultibase`;
 * (b) when `did.jsonl` is published, match the log's authorized `updateKeys`
 *     the same way, and recover the staged prerotation key by hashing every
 *     listed key against the log's committed `nextKeyHashes` -- the match no
 *     point lookup could make, since the log stores only the hash;
 * (c) rewrite `keys.json` from what matched.
 *
 * An unmatchable binding is unrepairable and throws: a published artifact
 * depends on a key the keystore no longer lists. The `retiredKeys` audit
 * trail is not recoverable (retired keys appear in no current artifact) and
 * restarts empty.
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}
 * @param options.remoteStore {WASRemoteStore}
 * @returns {Promise<DidWebKeyMapV2>}   the rebuilt, persisted keys.json
 */
export async function repairKeyBindings({
  keystoreAgent,
  remoteStore
}: {
  keystoreAgent: KeystoreAgent
  remoteStore: WASRemoteStore
}): Promise<DidWebKeyMapV2> {
  const didDoc = (await remoteStore.getIdResource({
    resourceId: DID_DOCUMENT_RESOURCE
  })) as
    | {
        verificationMethod?: Array<{ id?: string; publicKeyMultibase?: string }>
        authentication?: Array<string | { id?: string }>
        assertionMethod?: Array<string | { id?: string }>
        keyAgreement?: Array<string | { id?: string }>
      }
    | undefined
  if (!didDoc) {
    throw new Error(
      'keys.json repair: did.json is not published; there is nothing to ' +
        'match key bindings against.'
    )
  }
  const logText = await remoteStore.getIdResourceRaw({
    resourceId: DID_LOG_RESOURCE
  })

  // One listing, matched by public key material below. `keyUrl` is the
  // list-only projection field (webkms-client >= 14.7.1 types it; a pre-K5
  // server omits it, so entries without one are skipped and simply fail to
  // match).
  const listed = (await keystoreAgent.listKeys()) as Array<{
    publicKeyMultibase?: string
    keyUrl?: string
  }>
  const keyUrlByMultibase = new Map<string, string>()
  for (const description of listed) {
    if (description.publicKeyMultibase && description.keyUrl) {
      keyUrlByMultibase.set(description.publicKeyMultibase, description.keyUrl)
    }
  }

  // (a) The three did:web relationships, matched from the published document.
  const bind = (
    relationship: 'authentication' | 'assertionMethod' | 'keyAgreement'
  ): DidWebKey => {
    const [reference] = didDoc[relationship] ?? []
    const vmId = typeof reference === 'string' ? reference : reference?.id
    if (!vmId) {
      throw new Error(
        `keys.json repair: did.json declares no ${relationship} verification method.`
      )
    }
    const method = didDoc.verificationMethod?.find(entry => entry.id === vmId)
    const publicKeyMultibase = method?.publicKeyMultibase ?? multibaseOf(vmId)
    const kmsKeyId = keyUrlByMultibase.get(publicKeyMultibase)
    if (!kmsKeyId) {
      throw new Error(
        `keys.json repair: no keystore key matches the ${relationship} ` +
          `verification method (${publicKeyMultibase}).`
      )
    }
    return { vmId, kmsKeyId }
  }
  const repaired: DidWebKeyMapV2 = {
    authentication: bind('authentication'),
    assertionMethod: bind('assertionMethod'),
    keyAgreement: bind('keyAgreement')
  }

  // (b) The webvh block, matched from the log's own authorization parameters.
  if (logText !== undefined) {
    const resolved = await resolveDIDFromLog(readLogFromString(logText))
    if (resolved.meta.error || !resolved.did) {
      throw new Error(
        `keys.json repair: the published did.jsonl failed to resolve (${resolved.meta.error}).`
      )
    }
    const logUpdateKeys = resolved.meta.updateKeys ?? []
    const logNextKeyHashes = resolved.meta.nextKeyHashes ?? []

    const activeMultibase = logUpdateKeys.find(publicKeyMultibase =>
      keyUrlByMultibase.has(publicKeyMultibase)
    )
    const activeKeyUrl =
      activeMultibase === undefined
        ? undefined
        : keyUrlByMultibase.get(activeMultibase)
    if (activeMultibase === undefined || activeKeyUrl === undefined) {
      throw new Error(
        "keys.json repair: no keystore key matches the log's authorized " +
          'updateKeys -- the did:webvh log cannot be updated.'
      )
    }

    // The staged prerotation key: the log commits only its hash, so hash
    // every listed key until one lands in nextKeyHashes.
    let stagedKey: WebvhStagedKey | undefined
    for (const [publicKeyMultibase, keyUrl] of keyUrlByMultibase) {
      const nextKeyHash = await deriveNextKeyHash(publicKeyMultibase)
      if (logNextKeyHashes.includes(nextKeyHash)) {
        stagedKey = { kmsKeyId: keyUrl, publicKeyMultibase, nextKeyHash }
        break
      }
    }
    if (!stagedKey) {
      throw new Error(
        "keys.json repair: no keystore key hashes into the log's committed " +
          'nextKeyHashes -- the staged prerotation key is lost and the next ' +
          'rotation is impossible.'
      )
    }

    repaired.webvh = {
      did: resolved.did,
      updateKey: {
        kmsKeyId: activeKeyUrl,
        publicKeyMultibase: activeMultibase
      },
      stagedKey
    }
  }

  // (c) Persist the rebuilt anchor in one write.
  await remoteStore.putIdResource({
    resourceId: DID_KEYS_RESOURCE,
    content: repaired
  })
  return repaired
}

/**
 * Finalizes a rotation ceremony's keys.json roles (the shared tail of a fresh
 * rotation and a torn-finalize recovery): `updateKey <- stagedKey`,
 * `stagedKey <- newStaged`, the old `updateKey` appended to `retiredKeys`, and
 * `pendingStagedKey` dropped (it has become the active staged key). Then the
 * in-memory profile cache and the persisted session record are refreshed.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.remoteStore {WASRemoteStore}
 * @param options.didWebKeys {DidWebKeyMapV2}   the authoritative keys.json
 * @param options.block {DidWebvhBlock}   the pre-rotation webvh block
 * @param options.newStaged {WebvhStagedKey}   the freshly committed staged key
 * @param options.did {string}   the log's did (unchanged by a key rotation)
 * @returns {Promise<DidWebvhBlock>}   the finalized block
 */
async function finalizeRotatedRoles({
  session,
  remoteStore,
  didWebKeys,
  block,
  newStaged,
  did
}: {
  session: Session
  remoteStore: WASRemoteStore
  didWebKeys: DidWebKeyMapV2
  block: DidWebvhBlock
  newStaged: WebvhStagedKey
  did: string
}): Promise<DidWebvhBlock> {
  const finalized: DidWebvhBlock = {
    did,
    updateKey: {
      kmsKeyId: block.stagedKey.kmsKeyId,
      publicKeyMultibase: block.stagedKey.publicKeyMultibase
    },
    stagedKey: newStaged,
    retiredKeys: [...(block.retiredKeys ?? []), block.updateKey]
  }
  await writeKeysJson({ remoteStore, didWebKeys, webvh: finalized })

  session.profile.didWebvh = {
    did,
    updateKey: finalized.updateKey,
    stagedKey: finalized.stagedKey
  }
  return finalized
}

/**
 * Rotates the did:webvh log's update key (decision 7's user-triggered ceremony,
 * Settings page). The current staged key is revealed to sign its own activation
 * and become the sole active update key, a freshly generated staged key is
 * committed as the new `nextKeyHashes`, and keys.json roles roll forward. The
 * update key lives in the root-controlled keystore (decision 2 -- no
 * session-key path), and extending the append-only log needs the root zcap on
 * the `id` collection.
 *
 * Crash-recovery matrix (both kmsKeyIds are recorded at every intermediate
 * state, so a re-run re-derives which key the published log currently accepts):
 *
 * | keys.json                     | did.jsonl              | re-run action              |
 * | ----------------------------- | ---------------------- | -------------------------- |
 * | pending absent                | at active/staged commit| fresh rotation (steps 3-6) |
 * | pending set, log NOT advanced | still active/staged    | reuse pending, publish, fin|
 * | pending set, log advanced     | staged/newStaged commit| torn finalize: roles only  |
 *
 * @param options {object}
 * @param options.session {Session}   a session with the root keystore agent
 * @returns {Promise<DidWebvhBlock>}   the finalized webvh block
 */
export async function rotateWebvhUpdateKey({
  session
}: {
  session: Session
}): Promise<DidWebvhBlock> {
  const { keystoreAgent } = session.profile
  const remoteStore = session.storage.remoteStore
  if (!keystoreAgent) {
    throw new Error(
      'Rotating the did:webvh update key requires the root-controlled ' +
        'keystore agent.'
    )
  }
  if (!remoteStore) {
    throw new Error(
      'Rotating the did:webvh update key requires remote WAS storage.'
    )
  }

  // Load the authoritative keys.json + log (never the in-memory profile cache
  // for a write ceremony) and verify the local view before extending it.
  const didWebKeys = (await remoteStore.getIdResource({
    resourceId: DID_KEYS_RESOURCE
  })) as DidWebKeyMapV2 | undefined
  const block = didWebKeys?.webvh
  if (!didWebKeys || !block) {
    throw new Error(
      'did:webvh: keys.json has no webvh block -- publish the log (ensureDidWebvh) before rotating.'
    )
  }
  const logText = await remoteStore.getIdResourceRaw({
    resourceId: DID_LOG_RESOURCE
  })
  if (logText === undefined) {
    throw new Error('did:webvh: did.jsonl is missing; nothing to rotate.')
  }
  const log = readLogFromString(logText)
  const resolved = await resolveDIDFromLog(log)
  if (resolved.meta.error || !resolved.did) {
    throw new Error(
      `did:webvh: the published log failed to resolve (${resolved.meta.error}); refusing to rotate.`
    )
  }
  const logUpdateKeys = resolved.meta.updateKeys ?? []
  const logNextKeyHashes = resolved.meta.nextKeyHashes ?? []

  // Torn-finalize recovery: a prior ceremony crashed after publishing the
  // extended log but before rewriting keys.json roles. The log has already
  // advanced to the staged key with the pending key committed as next, so
  // finalize the roles without touching the log (re-signing would fork it).
  if (
    block.pendingStagedKey &&
    logUpdateKeys.includes(block.stagedKey.publicKeyMultibase) &&
    logNextKeyHashes.includes(block.pendingStagedKey.nextKeyHash)
  ) {
    return finalizeRotatedRoles({
      session,
      remoteStore,
      didWebKeys,
      block,
      newStaged: block.pendingStagedKey,
      did: resolved.did
    })
  }

  // Diverged-state guard: the log must still be at the current active key with
  // the current staged key committed as its next, or the local keys.json is out
  // of step with what was published.
  if (
    !logUpdateKeys.includes(block.updateKey.publicKeyMultibase) ||
    !logNextKeyHashes.includes(block.stagedKey.nextKeyHash)
  ) {
    throw new Error(
      'did:webvh: keys.json has diverged from the published log (the staged ' +
        'key is not the log-committed next key); refusing to rotate.'
    )
  }

  // Step 3: generate the NEW staged key -- or reuse an already-anchored one (a
  // prior ceremony that crashed between anchor and publish, so the log has not
  // advanced) -- and anchor it into keys.json as `pendingStagedKey` BEFORE
  // publishing anything, keeping the current roles intact (decision 4).
  const newStaged =
    block.pendingStagedKey ?? (await generateStagedKey({ keystoreAgent }))
  if (!block.pendingStagedKey) {
    await writeKeysJson({
      remoteStore,
      didWebKeys,
      webvh: { ...block, pendingStagedKey: newStaged }
    })
  }

  // Step 4: extend the log. The revealed staged key signs its own activation,
  // becomes the sole active update key, and commits the new staged key's hash.
  // updateDID is sparse (no document directives) so the verification methods are
  // preserved -- a key-only rotation.
  const signer = await updateKeySigner({
    keystoreAgent,
    updateKey: block.stagedKey
  })
  const updated = await updateDID({
    log,
    signer,
    updateKeys: [block.stagedKey.publicKeyMultibase],
    nextKeyHashes: [newStaged.nextKeyHash]
  })
  if (!updated.webDoc) {
    throw new Error(
      'did:webvh: updateDID returned no webDoc despite the did:web alsoKnownAs.'
    )
  }

  // Step 5: publish the extended log and republish did.json (its did:web
  // projection, decision 5), then finalize keys.json roles + caches.
  await publishWebvhLog({
    remoteStore,
    log: updated.log,
    webDoc: updated.webDoc
  })
  return finalizeRotatedRoles({
    session,
    remoteStore,
    didWebKeys,
    block,
    newStaged,
    did: updated.did
  })
}
