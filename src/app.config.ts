/**
 * Application configuration — environment variable exports and app-wide
 * constants.
 */
import type { EntityIdentityRegistry } from '@interop/verifier-core'

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
// Lifetime of the delegated session zcaps minted at login (refresh-surviving
// sessions, `src/session/delegatedSession.ts`). After this the restored
// session's capabilities stop verifying and a fresh login is required.
export const SESSION_ZCAP_TTL_MS =
  (env.VITE_SESSION_ZCAP_TTL_HOURS
    ? Number(env.VITE_SESSION_ZCAP_TTL_HOURS)
    : 24) *
  60 *
  60 *
  1000

// Lifetime of the session vault envelope persisted at full login -- the vault
// KAK wrapped under a non-extractable AES-GCM key (`src/session/vault.ts`),
// which lets a restored (`delegated` tier) session unlock the vault without
// the passphrase. Deliberately independent of the zcap TTL: the vault can
// re-lock while the restored session (sync, plaintext reads) keeps working.
export const SESSION_VAULT_TTL_MS =
  (env.VITE_SESSION_VAULT_TTL_HOURS
    ? Number(env.VITE_SESSION_VAULT_TTL_HOURS)
    : 24) *
  60 *
  60 *
  1000

// Opt-out switch for the session vault envelope: when exactly 'true', the
// vault KAK is never persisted in any form and restored sessions always
// require a passphrase re-login to unlock the vault.
export const REQUIRE_PASSPHRASE_FOR_VAULT =
  env.VITE_REQUIRE_PASSPHRASE_FOR_VAULT === 'true'

// Lifetime of the capabilities delegated to a relying party when a user
// approves a "Login with Wallet" zcap request (`src/lib/walletRequest/
// processZcaps.ts`). Default 30 days: the WAS server has no Space-side
// revocation endpoint, so expiry is the sole limiter on RP grants.
export const RP_ZCAP_TTL_MS =
  (Number(env.VITE_RP_ZCAP_TTL_HOURS) || 720) * 60 * 60 * 1000

// Lifetime of a *write* capability delegated to a relying party (a grant on an
// RP-provisioned collection whose actions go beyond GET/HEAD). Default 7 days:
// deliberately shorter than the read-only TTL, since a stolen write grant can
// mutate RP data and there is no Space-side revocation endpoint.
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

// The WAS collections replicated by the sync controller: all three standard
// collections, through the same collection-agnostic adapter. All are immutable
// per item and content-addressed -- `public-credentials` plaintext (keyed by
// credential cid), the other two as EDV envelopes (keyed by a hash of the JWE
// ciphertext); the adapter ships the stored bodies verbatim either way.
export const SYNCED_COLLECTIONS: Array<{ key: string; id: string }> = [
  { key: 'privateCredentials', id: 'private-credentials' },
  { key: 'publicCredentials', id: 'public-credentials' },
  { key: 'walletActivity', id: 'wallet-activity' }
]

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
    name: 'Publicly Shared Verifiable Credentials',
    isPublic: true
  },
  {
    key: 'walletActivity',
    id: 'wallet-activity',
    name: 'Wallet Activity Log',
    encryption: { scheme: 'edv' }
  }
]
/**
 * The `id` collection: a standard-on-the-server collection that holds the
 * user's published DID document (`did.json`) and its key-id map
 * (`keys.json`). Deliberately kept out of WALLET_STANDARD_COLLECTIONS -- it
 * gets no local RxDB replica, no background replication, and no
 * per-collection session zcap. Provisioned (full tier only) alongside the
 * standard collections; the DID document is made world-readable at the
 * resource level (a `PublicCanRead` policy on `did.json`), while the key-id
 * map stays capability-only.
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
// The world-readable did:webvh history log (Phase 2), a raw JSON-Lines string
// served as `text/jsonl`: one log entry per line, each a full DID-document
// snapshot in a hash chain. Sibling of `did.json` in the same `id` collection;
// `did:webvh:<scid>:<host>:space:<spaceId>:id` resolves to
// `https://<host>/space/<spaceId>/id/did.jsonl`.
export const DID_LOG_RESOURCE = 'did.jsonl'

// Whether to provision and publish the user's did:webvh DID log alongside the
// did:web document (Phase 2). An opt-out flag: default `true` (freewallet acts
// as a did:webvh demo platform, publishing the log out of the box), disabled
// only when `VITE_ENABLE_DID_WEBVH` is exactly the string `'false'`.
export const ENABLE_DID_WEBVH = env.VITE_ENABLE_DID_WEBVH !== 'false'

/**
 * PBKDF2 parameters for the keyring unlock derivation
 * (`unlockSeed = PBKDF2(passphrase)`). Version 1 pins exactly these
 * parameters; the keyring record's `version` field records which set produced
 * it, so changing any of them (iterations, hash, salt) requires minting a new
 * record version rather than silently breaking existing unlock derivations.
 * The salt is a fixed app-wide constant -- login stays passphrase-only, with
 * no email (or other) input mixed into the derivation.
 */
export const KEYRING_KDF = {
  version: 1,
  iterations: 600_000,
  hash: 'SHA-256',
  salt: 'freewallet/keyring/unlock/v1'
} as const

// The unlock Space's single collection (holds the one keyring record), and the
// record's resource id within it. The unlock Space is a minimal second Space,
// controlled by the passphrase-derived unlock identity and separate from the
// wallet data Space.
export const KEYRING_COLLECTION = { id: 'keyring', name: 'Keyring' }
export const KEYRING_RESOURCE = 'keyring.json'

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
