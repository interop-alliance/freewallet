/**
 * did:web hosting: provisions and publishes a multi-key did:web DID in the
 * user's WAS Space, with verification methods backed by KMS-held keys, and
 * exposes a KMS-backed authentication signer for DIDAuth.
 *
 * The DID document is an ordinary WAS Resource served by the unauthenticated
 * public-read path, so hosting needs zero server changes: the DID's path
 * segments name the `id` collection that holds it --
 * `did:web:<host>:space:<spaceId>:id` resolves to
 * `https://<host>/space/<spaceId>/id/did.json`. The `id` collection carries a
 * collection-level `PublicCanRead` policy (set at provisioning), so every
 * resource in it is world-readable without a per-resource grant.
 */
import type { KeystoreAgent } from '@interop/webkms-client'
import type { ISigner } from '@interop/data-integrity-core'
import type { Session } from '@/types/auth'
import { multibaseOf } from '@interop/wallet-core/webvh'
import type { DidWebKey, DidWebKeyMap } from '@interop/wallet-core/webvh'
import { DID_DOCUMENT_RESOURCE } from '@/app.config'
import { getKmsSignFunction } from '@/lib/kms'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

/**
 * The suite type of the two Ed25519 verification keys (authentication,
 * assertionMethod) -- what the WebKMS local module generates for the
 * `asymmetric` category.
 */
const ED25519_VM_TYPE = 'Ed25519VerificationKey2020'
/**
 * The suite type of the X25519 key-agreement key, generated for the
 * `keyAgreement` category.
 */
const X25519_KAK_TYPE = 'X25519KeyAgreementKey2020'

const DID_V1_CONTEXT = 'https://www.w3.org/ns/did/v1'
const ED25519_2020_CONTEXT = 'https://w3id.org/security/suites/ed25519-2020/v1'
const X25519_2020_CONTEXT = 'https://w3id.org/security/suites/x25519-2020/v1'

/**
 * The publicAliasTemplate placeholder the WebKMS server expands to the
 * generated key's multibase fingerprint. The fragment (`#z6Mk...` /
 * `#z6LS...`) is thus self-describing, did:key-style -- so the verification
 * method id already carries the key's `publicKeyMultibase`.
 */
const PUBLIC_KEY_MULTIBASE_PLACEHOLDER = '{publicKeyMultibase}'

/**
 * Builds the did:web DID for a Space from the WAS server URL and space id. The
 * host segment is percent-encoded per the did:web method spec, so a dev host
 * with a port becomes `localhost%3A8080`.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @returns {string}   e.g. `did:web:localhost%3A8080:space:<spaceId>:id`
 */
export function didWebFromSpace({
  wasServerUrl,
  spaceId
}: {
  wasServerUrl: string
  spaceId: string
}): string {
  const { host } = new URL(wasServerUrl)
  return `did:web:${encodeURIComponent(host)}:space:${spaceId}:id`
}

/**
 * Whether a parsed `keys.json` body is a well-formed key map (all three
 * relationships present with a `vmId` and `kmsKeyId`).
 */
function isKeyMap(value: unknown): value is DidWebKeyMap {
  if (!value || typeof value !== 'object') {
    return false
  }
  const map = value as Record<string, unknown>
  return (['authentication', 'assertionMethod', 'keyAgreement'] as const).every(
    relationship => {
      const entry = map[relationship] as Record<string, unknown> | undefined
      return (
        !!entry &&
        typeof entry.vmId === 'string' &&
        typeof entry.kmsKeyId === 'string'
      )
    }
  )
}

/**
 * Assembles the minimal multi-key did:web document from the DID and its key
 * map. Each verification method's `publicKeyMultibase` is recovered from its
 * id fragment (the KMS-expanded alias), so this is pure and unit-testable in
 * isolation -- no KMS round-trip.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.keys {DidWebKeyMap}
 * @returns {object}   the DID document
 */
export function assembleDidDocument({
  did,
  keys
}: {
  did: string
  keys: DidWebKeyMap
}): object {
  const method = (key: DidWebKey, type: string) => ({
    id: key.vmId,
    type,
    controller: did,
    publicKeyMultibase: multibaseOf(key.vmId)
  })
  return {
    '@context': [DID_V1_CONTEXT, ED25519_2020_CONTEXT, X25519_2020_CONTEXT],
    id: did,
    verificationMethod: [
      method(keys.authentication, ED25519_VM_TYPE),
      method(keys.assertionMethod, ED25519_VM_TYPE),
      method(keys.keyAgreement, X25519_KAK_TYPE)
    ],
    authentication: [keys.authentication.vmId],
    assertionMethod: [keys.assertionMethod.vmId],
    keyAgreement: [keys.keyAgreement.vmId]
  }
}

/**
 * Publishes `did.json` (as `application/did+json`) from a key map. It is
 * world-readable via the `id` collection's collection-level `PublicCanRead`
 * policy (set at provisioning), so no per-resource publication is needed. The
 * shared tail of both the fresh-generate path and the torn-resume path
 * (keys.json present, did.json missing).
 */
async function publishDidDocument({
  remoteStore,
  did,
  keys
}: {
  remoteStore: WASRemoteStore
  did: string
  keys: DidWebKeyMap
}): Promise<void> {
  await remoteStore.webvhIdStore().putIdResource({
    resourceId: DID_DOCUMENT_RESOURCE,
    content: assembleDidDocument({ did, keys }),
    contentType: 'application/did+json'
  })
}

/**
 * Generates one KMS key for a DID relationship and returns its durable
 * binding. The publicAliasTemplate makes the key's id the did:web
 * verification-method URL (fragment = multibase fingerprint).
 */
async function generateDidKey({
  keystoreAgent,
  did,
  category
}: {
  keystoreAgent: KeystoreAgent
  did: string
  category: 'asymmetric' | 'keyAgreement'
}): Promise<DidWebKey> {
  const key = await keystoreAgent.generateKey({
    category,
    publicAliasTemplate: `${did}#${PUBLIC_KEY_MULTIBASE_PLACEHOLDER}`
  })
  if (!key.id || !key.kmsId) {
    throw new Error(`KMS generateKey returned no id for a ${category} key.`)
  }
  return { vmId: key.id, kmsKeyId: key.kmsId }
}

/**
 * Idempotently provisions and publishes the user's did:web DID. The
 * steady-state path is a single read; a fresh Space generates three KMS keys,
 * writes `keys.json` (the recovery anchor) first, then publishes `did.json`.
 * A crash between steps resumes from `keys.json` on the next full login.
 *
 * The key map lives in the private `key-map` collection, while the published
 * artifacts (`did.json`, `did.jsonl`) live in the world-readable `id`
 * collection.
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}
 * @param options.remoteStore {WASRemoteStore}
 * @param options.did {string}   from {@link didWebFromSpace}
 * @returns {Promise<DidWebKeyMap>}
 */
export async function ensureDidWeb({
  keystoreAgent,
  remoteStore,
  did
}: {
  keystoreAgent: KeystoreAgent
  remoteStore: WASRemoteStore
  did: string
}): Promise<DidWebKeyMap> {
  const existing = await remoteStore.getKeyMap()
  if (isKeyMap(existing)) {
    // keys.json is the recovery anchor: the keys already exist. Confirm the
    // published document; republish it (from the same keys) if a torn earlier
    // run wrote keys.json but not did.json. Never regenerate here.
    const didDoc = await remoteStore.webvhIdStore().getIdResource({
      resourceId: DID_DOCUMENT_RESOURCE
    })
    if (!didDoc) {
      await publishDidDocument({ remoteStore, did, keys: existing })
    }
    return existing
  }

  // Fresh provisioning: mint the three keys with their aliases, then write
  // keys.json before did.json so the flow is crash-resumable.
  const keys: DidWebKeyMap = {
    authentication: await generateDidKey({
      keystoreAgent,
      did,
      category: 'asymmetric'
    }),
    assertionMethod: await generateDidKey({
      keystoreAgent,
      did,
      category: 'asymmetric'
    }),
    keyAgreement: await generateDidKey({
      keystoreAgent,
      did,
      category: 'keyAgreement'
    })
  }
  await remoteStore.webvhIdStore().putKeyMap({ content: keys })
  await publishDidDocument({ remoteStore, did, keys })
  return keys
}

/**
 * Wraps a KMS-backed `sign` closure as a plain `{ id, algorithm, sign }`
 * signer. `id` is overridden to the verification-method id so the proof names
 * the right `verificationMethod`; `algorithm` satisfies the suite's `Ed25519`
 * check. The `sign` closure comes from `kmsSignFunction`, which re-expresses the
 * KMS key's prototype `sign` method as an own property so the data-integrity
 * suites' shallow spread (`{ ...signer }`) preserves it.
 */
function signerFromKey({
  sign,
  vmId
}: {
  sign: (input: { data: Uint8Array }) => Promise<Uint8Array>
  vmId: string
}): ISigner {
  return {
    id: vmId,
    algorithm: 'Ed25519',
    sign
  } as unknown as ISigner
}

/**
 * A KMS-backed `authentication`-key signer for DIDAuth, or `undefined` when
 * the did:web is not provisioned or the session cannot reach the key. Its
 * `id` is the verification-method id (`keys.authentication.vmId`), so a proof
 * signed with it names the right `verificationMethod` with no special-casing.
 * The root key invokes the keystore's root capability.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {ISigner | undefined}
 */
export async function kmsAuthenticationSigner({
  session
}: {
  session: Session
}): Promise<ISigner | undefined> {
  const { didWeb, keystoreAgent } = session.profile
  if (!didWeb) {
    return undefined
  }
  const { vmId, kmsKeyId } = didWeb.keys.authentication

  if (keystoreAgent) {
    const sign = await getKmsSignFunction({
      keystoreAgent,
      id: vmId,
      kmsKeyId
    })
    return signerFromKey({ sign, vmId })
  }

  return undefined
}
