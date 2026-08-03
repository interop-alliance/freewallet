/**
 * Application configuration — environment variable exports and app-wide
 * constants.
 */
import type { EntityIdentityRegistry } from '@interop/verifier-core'
import {
  CONTACTS_COLLECTION,
  CONTACTS_COLLECTION_SPEC,
  CONTACTS_HISTORY_COLLECTION,
  CONTACTS_HISTORY_COLLECTION_SPEC
} from '@interop/social-core'
import {
  PRIVATE_CREDENTIALS_COLLECTION_SPEC,
  PUBLIC_CREDENTIALS_COLLECTION_SPEC,
  WALLET_ACTIVITY_COLLECTION_SPEC
} from '@interop/wallet-core/space'

const env = import.meta.env

// This app's own origin, used for CHAPI wallet registration.
export const SERVER_URL = env.VITE_SERVER_URL || 'http://localhost:5173'
// Public deploy URL registered with the CHAPI mediator (authn.io).
export const DEPLOY_URL = env.VITE_DEPLOY_URL
// Remote WAS server URL. When set, a remote WAS Space is available as a sync
// target: the sync controller replicates the local RxDB collections to it in
// the background. (Guest sessions never sync.)
export const WAS_SERVER_URL = env.VITE_WAS_SERVER_URL
// WebKMS server URL. Defaults to the WAS server's in-process `/kms` facet;
// set VITE_KMS_SERVER_URL only when the KMS is hosted separately. When
// neither is set, the session has no KMS (keys stay on this device).
export const KMS_SERVER_URL =
  env.VITE_KMS_SERVER_URL ||
  (WAS_SERVER_URL ? `${WAS_SERVER_URL}/kms` : undefined)
// Lifetime of the capabilities delegated to a relying party when a user
// approves a "Login with Wallet" zcap request (`src/lib/walletRequest/
// processZcaps.ts`). Default 30 days: expiry bounds every RP grant. The WAS
// server now also has a Space-scoped revocation endpoint, so a grant can be
// retired before its expiry -- the recorded zcap ids are the hook for that.
export const RP_ZCAP_TTL_MS =
  (Number(env.VITE_RP_ZCAP_TTL_HOURS) || 720) * 60 * 60 * 1000

// Lifetime of a *write* capability delegated to a relying party (a grant on an
// RP-provisioned collection whose actions go beyond GET/HEAD). Default 7 days:
// deliberately shorter than the read-only TTL, since a stolen write grant can
// mutate RP data (a leaked grant can also be revoked before expiry via the
// Space-scoped revocation endpoint).
export const RP_ZCAP_WRITE_TTL_MS =
  (Number(env.VITE_RP_ZCAP_WRITE_TTL_HOURS) || 168) * 60 * 60 * 1000

// Lifetime of the read-only capability delegated by a *share* grant (a
// `https://w3id.org/byoe#shared-collection` request, which also escrows the grantee into the
// collection's key-epoch roster). Default 365 days: deliberately long, because
// expiry is the wrong removal mechanism here. The two axes of a share come
// apart at expiry -- the pull zcap dies but the epoch escrow does not, leaving
// a reader in the roster (and in the settings list) who can no longer fetch.
// The Settings "Shared collections" panel is the removal mechanism: it rotates
// the epoch and revokes the zcap indivisibly.
export const SHARE_ZCAP_TTL_MS =
  (Number(env.VITE_SHARE_ZCAP_TTL_HOURS) || 8760) * 60 * 60 * 1000

// Background-replication tuning (both optional).
// `VITE_WAS_SYNC_RETRY_MS` -- RxDB `retryTime` backoff between failed cycles.
export const WAS_SYNC_RETRY_MS = env.VITE_WAS_SYNC_RETRY_MS
  ? Number(env.VITE_WAS_SYNC_RETRY_MS)
  : undefined
// `VITE_WAS_SYNC_BATCH_SIZE` -- pull `limit` / push batch size.
export const WAS_SYNC_BATCH_SIZE = env.VITE_WAS_SYNC_BATCH_SIZE
  ? Number(env.VITE_WAS_SYNC_BATCH_SIZE)
  : undefined

export const WALLET_STANDARD_COLLECTIONS: Array<{
  key: string
  id: string
  name: string
  isPublic?: boolean
  // Declares the collection's client-side encryption descriptor on the server,
  // making it self-describing (a future client/delegate can discover that it is
  // encrypted and supply its own keys). Set-once / immutable on the server.
  encryption?: { scheme: 'edv' }
  // How the collection's cipher mints a document id, from the collection spec:
  // 'content' (content-addressed, immutable) or 'random' (the mutable
  // stable-id head model -- `contacts`). Only meaningful on an encrypted
  // collection; the ciphers are built with it so the minted ids follow the
  // spec (a `'random'` mint becomes the row id, see `browserStore.addContact`).
  idDerivation?: 'content' | 'random'
}> = [
  // Collection ids and their public/encryption config come from
  // `@interop/wallet-core/space` so this list matches Freewallet mobile's Space
  // layout byte-for-byte. The RxDB `key` and the friendly display `name` are
  // local (the library spec does not carry them); the local `encryption`
  // descriptor's `{ scheme: 'edv' }` object is derived from the spec's `'edv'` /
  // `'plaintext'` encryption string.
  {
    key: 'privateCredentials',
    id: PRIVATE_CREDENTIALS_COLLECTION_SPEC.collectionId,
    name: 'Verifiable Credentials',
    encryption:
      PRIVATE_CREDENTIALS_COLLECTION_SPEC.encryption === 'edv'
        ? { scheme: 'edv' }
        : undefined,
    idDerivation: PRIVATE_CREDENTIALS_COLLECTION_SPEC.idDerivation
  },
  {
    key: 'publicCredentials',
    id: PUBLIC_CREDENTIALS_COLLECTION_SPEC.collectionId,
    name: 'Verifiable Credentials (Publicly Shared)',
    isPublic: PUBLIC_CREDENTIALS_COLLECTION_SPEC.isPublic
  },
  {
    key: 'walletActivity',
    id: WALLET_ACTIVITY_COLLECTION_SPEC.collectionId,
    name: 'Wallet Activity Log',
    encryption:
      WALLET_ACTIVITY_COLLECTION_SPEC.encryption === 'edv'
        ? { scheme: 'edv' }
        : undefined,
    idDerivation: WALLET_ACTIVITY_COLLECTION_SPEC.idDerivation
  },
  // Ids come from `@interop/social-core` (not hardcoded) so this collection
  // matches Freewallet mobile's byte-for-byte -- a disagreement here would
  // split writes into separate collections that never converge.
  {
    key: 'contacts',
    id: CONTACTS_COLLECTION,
    name: 'Contacts',
    encryption: { scheme: 'edv' },
    idDerivation: CONTACTS_COLLECTION_SPEC.idDerivation
  },
  {
    key: 'contactsHistory',
    id: CONTACTS_HISTORY_COLLECTION,
    name: 'Contacts History',
    encryption: { scheme: 'edv' },
    idDerivation: CONTACTS_HISTORY_COLLECTION_SPEC.idDerivation
  }
]

// The WAS collections replicated by the sync controller: every standard
// collection, projected down to the (key, id) pair the collection-agnostic
// adapter needs. Every WALLET_STANDARD_COLLECTIONS entry syncs -- the `id`
// collection (below) is deliberately kept out of that list and so out of this
// one. Most synced collections are immutable per item and content-addressed --
// `public-credentials` plaintext (keyed by credential cid), the encrypted ones
// as EDV envelopes (keyed by a hash of the JWE ciphertext) -- and the adapter
// ships the stored bodies verbatim either way. `contacts` is the one mutable
// exception: a stable, randomly-derived row id whose body is genuinely
// overwritten in place (see `CONTACTS_COLLECTION_SPEC` in
// `@interop/social-core`), matching Freewallet mobile's SQLite head-document
// row. The push handler already supports an in-place content update
// generically (see `pushWrites.ts`); `contacts-history` stays content-addressed
// and immutable, same as `wallet-activity`.
export const SYNCED_COLLECTIONS: Array<{ key: string; id: string }> =
  WALLET_STANDARD_COLLECTIONS.map(({ key, id }) => ({ key, id }))
// The system collections and resource names that carry the account's identity
// and key material -- the world-readable `id` collection (`did.json`,
// `did.jsonl`), the private `key-map` collection (`keys.json`, `puk.json`,
// `client-labels.json`),
// and the unlock Space's `keyring` collection (`keyring.json`). They are
// shared wallet Space layout, declared once in `@interop/wallet-core/space`
// and re-exported here so app-side call sites keep one config import.
export {
  CLIENT_LABELS_RESOURCE,
  DID_DOCUMENT_RESOURCE,
  DID_KEYS_RESOURCE,
  DID_LOG_RESOURCE,
  ID_COLLECTION,
  KEY_MAP_COLLECTION,
  KEYRING_COLLECTION,
  KEYRING_RESOURCE,
  PUK_ROSTER_RESOURCE
} from '@interop/wallet-core/space'

// Whether to provision and publish the user's did:webvh DID log alongside the
// did:web document. An opt-out flag: default `true` (freewallet acts
// as a did:webvh demo platform, publishing the log out of the box), disabled
// only when `VITE_ENABLE_DID_WEBVH` is exactly the string `'false'`.
export const ENABLE_DID_WEBVH = env.VITE_ENABLE_DID_WEBVH !== 'false'

/**
 * HKDF parameters for the passkey unlock derivation
 * (`unlockSeed = HKDF(prfOutput)`). The WebAuthn PRF output is uniform
 * 32-byte key material, so no PBKDF2-style stretching is needed. The salt
 * differs from every other unlock method's salt (two methods must never
 * derive the same unlock Space); as with `KEYRING_KDF`, `version` pins the
 * parameter set.
 */
export const PASSKEY_KDF = {
  version: 1,
  algorithm: 'HKDF',
  hash: 'SHA-256',
  salt: 'freewallet/keyring/passkey/v1',
  info: 'freewallet/unlock-seed'
} as const

// The fixed app-wide WebAuthn PRF evaluation input. Safe as a shared public
// constant: the PRF output is an HMAC keyed per-credential inside the
// authenticator, so a common input still yields per-credential secrets. The
// string is versioned so a future `v2` can force new derivations.
export const PASSKEY_PRF_INPUT = new TextEncoder().encode(
  'freewallet/passkey/prf/v1'
)

// WebAuthn Relying Party ID for passkey ceremonies. Default unset: the page
// origin's registrable domain applies. Changing the origin or the RP ID
// orphans every registered passkey.
export const PASSKEY_RP_ID = env.VITE_PASSKEY_RP_ID || undefined

// The unlock-methods registry: a single collection in the user's DATA Space
// (not the unlock Space) holding one `methods.json` resource -- the list of an
// account's unlock methods (passphrase, passkeys). Deliberately kept out of
// WALLET_STANDARD_COLLECTIONS / SYNCED_COLLECTIONS: it gets no RxDB replica and
// no background replication, and is read/written directly like the keyring
// record (remote as source of truth, last-write-wins).
export const UNLOCK_METHODS_COLLECTION = {
  id: 'unlock-methods',
  name: 'Unlock Methods'
}
export const UNLOCK_METHODS_RESOURCE = 'methods.json'

// Lifetime of the management zcap an unlock identity delegates to the data
// identity at bind time (`src/session/keyring.ts`). Deliberately long-lived
// (10 years): the capability grants only GET/DELETE on that one unlock Space,
// so its worst-case leak is denial of a single unlock method (someone deletes
// that Space -- the method stops working, the wallet stays reachable via the
// others), never decryption. The WAS server enforces no maximum TTL on Space
// routes and the zcap is revocable at Space scope, so an unbounded lifetime is
// acceptable -- and long enough that a lost method stays revocable years later
// without re-deriving its unlock identity from the (possibly lost) secret.
export const UNLOCK_MANAGE_ZCAP_TTL_MS = 10 * 365 * 24 * 60 * 60 * 1000

// Lifetime of the PUT-on-`did.jsonl` delegation a recovery code's unlock
// record carries (`src/session/recovery.ts`). Deliberately long-lived like the
// management zcap above: a recovery code must work years after issuance, and
// the delegation's scope is one resource (the world-readable DID log), whose
// worst-case abuse is a log write that still has to verify against the
// published hash chain and prerotation commitments to resolve. The login-time
// recovery health check watches for delegation rot (the signing client's
// verification method leaving the document) rather than expiry.
export const RECOVERY_ZCAP_TTL_MS = 10 * 365 * 24 * 60 * 60 * 1000

// Offline-fallback lifetime of a locally cached keyring record when a WAS
// server is configured (the remote copy is the source of truth and is
// consulted first on every login). Bounds how long a passphrase retired on
// another device can keep unlocking this one while it is offline. Has no
// effect in no-WAS deployments, where the cache is the keyring's only copy.
export const KEYRING_CACHE_TTL_MS =
  (Number(env.VITE_KEYRING_CACHE_TTL_HOURS) || 7 * 24) * 60 * 60 * 1000

export const MAX_CREDENTIAL_JSON_FILE_BYTES = 10 * 1024 * 1024
// CORS proxy base URL for fetching remote credential URLs from
// AddCredentialPage. The target URL is appended as a `?url=` query parameter
// (see `src/lib/fetchFromURL.ts`). When a WAS server is configured, its
// built-in proxy facet at `/api/cors` is the default -- matching how
// `src/lib/corsProxy.ts` reaches the same endpoint.
export const CORS_PROXY_URL =
  env.VITE_CORS_PROXY_URL ||
  (WAS_SERVER_URL ? `${WAS_SERVER_URL}/api/cors` : 'https://corsproxy.io')

export const PASSWORD_RULES = {
  minlength: 16,
  minscore: 3
}

export const DATE_FMT: Intl.DateTimeFormatOptions = {
  year: 'numeric',
  month: 'short',
  day: 'numeric'
}

export const MEDIATOR_BASE = 'https://authn.io/mediator?origin='

export const KNOWN_REGISTRIES_URL =
  'https://digitalcredentials.github.io/dcc-known-registries/known-did-registries.json'

/**
 * Legacy DID registry URLs, used as a fallback when the remote
 * KNOWN_REGISTRIES_URL cannot be fetched. Each entry is tagged
 * `type: 'dcc-legacy'` so it satisfies the EntityIdentityRegistry contract
 * consumed by @interop/verifier-core and @digitalcredentials/issuer-registry-client.
 */
export const KnownDidRegistries: EntityIdentityRegistry[] = [
  {
    type: 'dcc-legacy',
    name: 'DCC Pilot Registry',
    url: 'https://digitalcredentials.github.io/issuer-registry/registry.json'
  },
  {
    type: 'dcc-legacy',
    name: 'DCC Sandbox Registry',
    url: 'https://digitalcredentials.github.io/sandbox-registry/registry.json'
  },
  {
    type: 'dcc-legacy',
    name: 'DCC Community Registry',
    url: 'https://digitalcredentials.github.io/community-registry/registry.json'
  },
  {
    type: 'dcc-legacy',
    name: 'DCC Registry',
    url: 'https://digitalcredentials.github.io/dcc-registry/registry.json'
  }
]

export const KNOWN_EXTENSIONS =
  /\.(json|jsonld|ldjson|txt|md|pdf|png|jpg|jpeg|webp|svg|csv|xml|yaml|yml)$/i

export const COMMON_CONTENT_TYPES: Record<string, string> = {
  'application/json': 'JSON',
  'application/ld+json': 'JSON-LD',
  'application/jsonld+json': 'JSON-LD',
  'application/pdf': 'PDF',
  'application/x-tar': 'TAR',
  'application/zip': 'ZIP',
  'application/xml': 'XML',
  'application/yaml': 'YAML',
  'application/x-yaml': 'YAML',
  'text/plain': 'TXT',
  'text/markdown': 'MD',
  'text/html': 'HTML',
  'text/css': 'CSS',
  'text/csv': 'CSV',
  'text/xml': 'XML',
  'image/png': 'PNG',
  'image/jpeg': 'JPEG',
  'image/gif': 'GIF',
  'image/svg+xml': 'SVG',
  'image/webp': 'WEBP'
}
