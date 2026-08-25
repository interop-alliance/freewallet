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
import type {
  DidWebKey,
  DidWebKeyMap,
  WebvhIdStore
} from '@interop/wallet-core/webvh'
import { DID_DOCUMENT_RESOURCE } from '@/app.config'
import { getKmsSignFunction } from '@/lib/kms'

/**
 * The suite type of the Ed25519 verification keys -- what the WebKMS local
 * module generates for the `asymmetric` category.
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
 * Whether a parsed `keys.json` body is a well-formed key map: `authentication`
 * and `keyAgreement` present with a `vmId` and `kmsKeyId`. No KMS-held
 * assertion key exists (the account document's `assertionMethod` relation
 * lists client keys only), so any `assertionMethod` member a served map
 * carries is ignored and never republished.
 */
function isKeyMap(value: unknown): value is DidWebKeyMap {
  if (!value || typeof value !== 'object') {
    return false
  }
  const map = value as Record<string, unknown>
  const wellFormed = (entry: unknown): boolean => {
    const key = entry as Record<string, unknown> | undefined
    return (
      !!key && typeof key.vmId === 'string' && typeof key.kmsKeyId === 'string'
    )
  }
  return wellFormed(map.authentication) && wellFormed(map.keyAgreement)
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
      method(keys.keyAgreement, X25519_KAK_TYPE)
    ],
    authentication: [keys.authentication.vmId],
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
  idStore,
  did,
  keys
}: {
  idStore: WebvhIdStore
  did: string
  keys: DidWebKeyMap
}): Promise<void> {
  await idStore.putIdResource({
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
 * steady-state path is a single read; a fresh Space generates two KMS keys,
 * writes `keys.json` (the recovery anchor) first, then publishes `did.json`.
 * A crash between steps resumes from `keys.json` on the next full login.
 *
 * The key map lives in the private `key-map` collection, while the published
 * artifacts (`did.json`, `did.jsonl`) live in the world-readable `id`
 * collection.
 *
 * The keystore is acquired lazily, only on the fresh-mint path: a run that
 * short-circuits on an existing `keys.json` never touches the KMS, so a
 * caller whose keystore acquisition is itself a provisioning step (the
 * credential-anchored establishment) never creates a keystore it will not
 * use.
 *
 * @param options {object}
 * @param options.provideKeystoreAgent {Function}   `() =>
 *   Promise<KeystoreAgent>` -- called once, before the first key generation
 * @param options.remoteStore {object}   the key-map read and the `id`
 *   collection store (`WASRemoteStore` satisfies it structurally)
 * @param options.did {string}   from {@link didWebFromSpace}
 * @returns {Promise<DidWebKeyMap>}
 */
export async function ensureDidWeb({
  provideKeystoreAgent,
  remoteStore,
  did
}: {
  provideKeystoreAgent: () => Promise<KeystoreAgent>
  remoteStore: {
    getKeyMap(): Promise<unknown>
    webvhIdStore(): WebvhIdStore
  }
  did: string
}): Promise<DidWebKeyMap> {
  const idStore = remoteStore.webvhIdStore()
  const existing = await remoteStore.getKeyMap()
  if (isKeyMap(existing)) {
    // keys.json is the recovery anchor: the keys already exist. Confirm the
    // published document; republish it (from the same keys) if a torn earlier
    // run wrote keys.json but not did.json. Never regenerate here.
    const didDoc = await idStore.getIdResource({
      resourceId: DID_DOCUMENT_RESOURCE
    })
    if (!didDoc) {
      await publishDidDocument({ idStore, did, keys: existing })
    }
    return existing
  }

  // Fresh provisioning: mint the two keys with their aliases (no KMS-held
  // assertion key -- the account document's `assertionMethod` relation lists
  // client keys only), then write keys.json before did.json so the flow is
  // crash-resumable.
  const keystoreAgent = await provideKeystoreAgent()
  const [authentication, keyAgreement] = await Promise.all([
    generateDidKey({ keystoreAgent, did, category: 'asymmetric' }),
    generateDidKey({ keystoreAgent, did, category: 'keyAgreement' })
  ])
  const keys: DidWebKeyMap = {
    authentication,
    keyAgreement
  }
  await idStore.putKeyMap({ content: keys })
  await publishDidDocument({ idStore, did, keys })
  return keys
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
  if (!keystoreAgent) {
    return undefined
  }
  const { vmId, kmsKeyId } = didWeb.keys.authentication

  // `id` is the verification-method id so the proof names the right
  // `verificationMethod`; `algorithm` satisfies the suite's `Ed25519` check.
  // `getKmsSignFunction` returns the sign closure as an own property, so the
  // data-integrity suites' shallow spread (`{ ...signer }`) preserves it.
  return {
    id: vmId,
    algorithm: 'Ed25519',
    sign: await getKmsSignFunction({ keystoreAgent, id: vmId, kmsKeyId })
  } as unknown as ISigner
}
