/**
 * did:web hosting: provisions and publishes a multi-key did:web DID in the
 * user's WAS Space, with verification methods backed by KMS-held keys, and
 * exposes a KMS-backed authentication signer for DIDAuth.
 *
 * The DID document is an ordinary WAS Resource served by the unauthenticated
 * public-read path, so hosting needs zero server changes: the DID's path
 * segments name the `id` collection that holds it --
 * `did:web:<host>:space:<spaceId>:id` resolves to
 * `https://<host>/space/<spaceId>/id/did.json`.
 */
import { AsymmetricKey, KmsClient } from '@interop/webkms-client'
import type { KeystoreAgent } from '@interop/webkms-client'
import type { ISigner } from '@interop/data-integrity-core'
import type { Session } from '@/types/auth'
import { DID_DOCUMENT_RESOURCE, DID_KEYS_RESOURCE } from '@/app.config'
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
 * One verification method's durable binding: the verification-method id (the
 * did:web `#fragment` URL, which is also the KMS key's publicAlias) and the
 * KMS key id used to invoke signing.
 */
export interface DidWebKey {
  vmId: string
  kmsKeyId: string
}

/**
 * The key-id map persisted as `keys.json` (and cached in the delegated session
 * record): the durable mapping from DID relationship to KMS key, since the KMS
 * protocol has no list-keys endpoint and key ids are server-generated.
 */
export interface DidWebKeyMap {
  authentication: DidWebKey
  assertionMethod: DidWebKey
  keyAgreement: DidWebKey
}

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
 * The `publicKeyMultibase` a verification-method id carries in its fragment.
 * The KMS expanded `#{publicKeyMultibase}` at generate time, so the fragment
 * IS the multibase key (no separate key-description fetch needed).
 */
function multibaseOf(vmId: string): string {
  return vmId.slice(vmId.lastIndexOf('#') + 1)
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
 * Publishes `did.json` (as `application/did+json`) from a key map and makes it
 * world-readable. The shared tail of both the fresh-generate path and the
 * torn-resume path (keys.json present, did.json missing).
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
  await remoteStore.putIdResource({
    resourceId: DID_DOCUMENT_RESOURCE,
    content: assembleDidDocument({ did, keys }),
    contentType: 'application/did+json'
  })
  await remoteStore.setIdResourcePublic({ resourceId: DID_DOCUMENT_RESOURCE })
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
  const existing = await remoteStore.getIdResource({
    resourceId: DID_KEYS_RESOURCE
  })
  if (isKeyMap(existing)) {
    // keys.json is the recovery anchor: the keys already exist. Confirm the
    // published document; republish it (from the same keys) if a torn earlier
    // run wrote keys.json but not did.json. Never regenerate here.
    const didDoc = await remoteStore.getIdResource({
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
  await remoteStore.putIdResource({
    resourceId: DID_KEYS_RESOURCE,
    content: keys
  })
  await publishDidDocument({ remoteStore, did, keys })
  return keys
}

/**
 * Wraps a KMS `AsymmetricKey` as a plain `{ id, algorithm, sign }` signer. The
 * wrapper is essential, not cosmetic: the data-integrity suites shallow-spread
 * the signer (`{ ...signer }`), which would drop `AsymmetricKey.sign` (a
 * prototype method). `id` is overridden to the verification-method id so the
 * proof names the right `verificationMethod`; `algorithm` satisfies the suite's
 * `Ed25519` check.
 */
function signerFromKey({
  key,
  vmId
}: {
  key: AsymmetricKey
  vmId: string
}): ISigner {
  return {
    id: vmId,
    algorithm: 'Ed25519',
    sign: ({ data }: { data: Uint8Array }) => key.sign({ data })
  } as unknown as ISigner
}

/**
 * A KMS-backed `authentication`-key signer for DIDAuth, or `undefined` when
 * the did:web is not provisioned or the session cannot reach the key. Its
 * `id` is the verification-method id (`keys.authentication.vmId`), so a proof
 * signed with it names the right `verificationMethod` with no special-casing.
 *
 * - `full` tier: the root key invokes the keystore's root capability.
 * - `delegated` tier: the browser session key invokes the persisted keystore
 *   `sign` capability (the Track E pieces) -- no passphrase needed.
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
  const { didWeb, keystoreAgent, keystoreId, keystoreCapability, zcapClient } =
    session.profile
  if (!didWeb) {
    return undefined
  }
  const { vmId, kmsKeyId } = didWeb.keys.authentication

  // Full tier: root key controls the keystore.
  if (keystoreAgent) {
    const key = await keystoreAgent.getAsymmetricKey({
      id: vmId,
      kmsId: kmsKeyId,
      type: ED25519_VM_TYPE
    })
    return signerFromKey({ key, vmId })
  }

  // Delegated tier: sign with the session key over the persisted keystore
  // `sign` capability. The capability targets the whole keystore, so it is
  // assigned after construction (the constructor rejects a `capability` and
  // `.fromCapability` would overwrite `kmsId` with the keystore URL); `sign`
  // then invokes it against the specific key's `kmsId` via target attenuation.
  if (keystoreId && keystoreCapability && zcapClient.invocationSigner) {
    const key = new AsymmetricKey({
      id: vmId,
      kmsId: kmsKeyId,
      type: ED25519_VM_TYPE,
      invocationSigner: zcapClient.invocationSigner,
      kmsClient: new KmsClient({ keystoreId })
    })
    key.capability = keystoreCapability
    return signerFromKey({ key, vmId })
  }

  return undefined
}
