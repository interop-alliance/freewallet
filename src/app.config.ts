/**
 * Application configuration — environment variable exports and app-wide
 * constants.
 */
import type { EntityIdentityRegistry } from '@interop/verifier-core'
import {
  CONTACTS_COLLECTION,
  CONTACTS_HISTORY_COLLECTION
} from '@interop/social-core'

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
  // Declares the collection's client-side encryption marker on the server,
  // making it self-describing (a future client/delegate can discover that it is
  // encrypted and supply its own keys). Set-once / immutable on the server.
  encryption?: { scheme: 'edv' }
}> = [
  {
    key: 'privateCredentials',
    id: 'private-credentials',
    name: 'Verifiable Credentials',
    encryption: { scheme: 'edv' }
  },
  {
    key: 'publicCredentials',
    id: 'public-credentials',
    name: 'Verifiable Credentials (Publicly Shared)',
    isPublic: true
  },
  {
    key: 'walletActivity',
    id: 'wallet-activity',
    name: 'Wallet Activity Log',
    encryption: { scheme: 'edv' }
  },
  // Ids come from `@interop/social-core` (not hardcoded) so this collection
  // matches Freewallet mobile's byte-for-byte -- a disagreement here would
  // split writes into separate collections that never converge.
  {
    key: 'contacts',
    id: CONTACTS_COLLECTION,
    name: 'Contacts',
    encryption: { scheme: 'edv' }
  },
  {
    key: 'contactsHistory',
    id: CONTACTS_HISTORY_COLLECTION,
    name: 'Contacts History',
    encryption: { scheme: 'edv' }
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
/**
 * The `id` collection: a standard-on-the-server collection that holds the
 * user's published DID document (`did.json`) and its key-id map
 * (`keys.json`). Deliberately kept out of WALLET_STANDARD_COLLECTIONS -- it
 * gets no local RxDB replica and no background replication. Provisioned
 * alongside the standard collections; the DID document is made world-readable
 * at the resource level (a `PublicCanRead` policy on `did.json`), while the
 * key-id map stays capability-only.
 *
 * The path segments name the collection that holds the DID document, so the
 * did:web id is `did:web:<host>:space:<spaceId>:id` and resolves to
 * `https://<host>/space/<spaceId>/id/did.json`.
 */
export const ID_COLLECTION = { id: 'id', name: 'Identity' }
// The world-readable DID document resource, served as `application/did+json`.
export const DID_DOCUMENT_RESOURCE = 'did.json'
// The (non-public) key-id map: verification method to KMS key id. The recovery
// anchor -- written before `did.json` so a torn provisioning resumes from it.
export const DID_KEYS_RESOURCE = 'keys.json'
// The world-readable did:webvh history log, a raw JSON-Lines string
// served as `text/jsonl`: one log entry per line, each a full DID-document
// snapshot in a hash chain. Sibling of `did.json` in the same `id` collection;
// `did:webvh:<scid>:<host>:space:<spaceId>:id` resolves to
// `https://<host>/space/<spaceId>/id/did.jsonl`.
export const DID_LOG_RESOURCE = 'did.jsonl'

// Whether to provision and publish the user's did:webvh DID log alongside the
// did:web document. An opt-out flag: default `true` (freewallet acts
// as a did:webvh demo platform, publishing the log out of the box), disabled
// only when `VITE_ENABLE_DID_WEBVH` is exactly the string `'false'`.
export const ENABLE_DID_WEBVH = env.VITE_ENABLE_DID_WEBVH !== 'false'

/**
 * PBKDF2 parameters for the passphrase unlock derivation
 * (`unlockSeed = PBKDF2(passphrase)`). Version 1 pins exactly these
 * parameters; the keyring record's `version` field records which set produced
 * it, so changing any of them (iterations, hash, salt) requires minting a new
 * record version rather than silently breaking existing unlock derivations.
 * The salt is a fixed app-wide constant -- login stays passphrase-only, with
 * no email (or other) input mixed into the derivation. Every unlock method's
 * KDF carries a distinct salt, so two methods can never derive the same
 * unlock Space.
 */
export const KEYRING_KDF = {
  version: 1,
  algorithm: 'PBKDF2',
  iterations: 600_000,
  hash: 'SHA-256',
  salt: 'freewallet/keyring/unlock/v1'
} as const

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

// The unlock Space's single collection (holds the one keyring record), and the
// record's resource id within it. The unlock Space is a minimal second Space,
// controlled by the passphrase-derived unlock identity and separate from the
// wallet data Space.
export const KEYRING_COLLECTION = { id: 'keyring', name: 'Keyring' }
export const KEYRING_RESOURCE = 'keyring.json'

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
