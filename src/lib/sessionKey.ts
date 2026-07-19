/**
 * The browser session key: a non-extractable WebCrypto Ed25519
 * key pair persisted in its own IndexedDB database (deliberately separate
 * from the RxDB wallet database, so it survives wallet-storage decisions
 * independently and is shared across tabs). The private key can be *used*
 * by an open page but never exported -- the delegated zcaps persisted
 * alongside it are inert anywhere this key is absent.
 *
 * The key pair signs capability invocations only; it never delegates
 * (delegation proofs are signed by the root key at login, see
 * `src/session/delegatedSession.ts`).
 */
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import type { ISigner } from '@interop/data-integrity-core'

const SESSION_DB_NAME = 'freewallet-session'
const SESSION_STORE = 'session'
const KEY_PAIR_RECORD = 'key-pair'
const SESSION_RECORD = 'record'
const VAULT_KEY_RECORD = 'vault-key'
const VAULT_ENVELOPE_RECORD = 'vault-envelope'

/**
 * Every function below takes an optional `idb` (an `IDBFactory`), defaulting
 * to the global `indexedDB`. In a top-level document those are the same
 * thing; in a third-party iframe (the CHAPI popup) the global factory is the
 * PARTITIONED bucket, and callers pass the first-party factory obtained from
 * the Storage Access API instead (`requestFirstPartyStorage()` in
 * `src/lib/storageAccess.ts`) to reach the session persisted by the
 * top-level wallet.
 */

/**
 * Opens (creating on first use) the dedicated session IndexedDB database.
 *
 * @param options {object}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<IDBDatabase>}
 */
async function openSessionDb({
  idb = indexedDB
}: {
  idb?: IDBFactory
}): Promise<IDBDatabase> {
  return await new Promise((resolve, reject) => {
    const request = idb.open(SESSION_DB_NAME, 1)
    request.onupgradeneeded = () => {
      request.result.createObjectStore(SESSION_STORE)
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

/**
 * Runs one get/put/delete against the session object store, closing the
 * database connection afterwards (connections are cheap to reopen and a
 * held-open one blocks version upgrades in other tabs).
 *
 * @param mode {IDBTransactionMode}
 * @param operation {(store: IDBObjectStore) => IDBRequest}
 * @param [idb] {IDBFactory}
 * @returns {Promise<unknown>}
 */
async function withSessionStore(
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore) => IDBRequest,
  idb?: IDBFactory
): Promise<unknown> {
  const [result] = await withSessionStoreBatch(mode, [operation], idb)
  return result
}

/**
 * Runs several independent get/put/delete operations against the session
 * object store within a single transaction on one open connection, resolving
 * to their results in order. Batching this way avoids repeating the
 * openSessionDb() handshake (and the version check it carries) once per
 * operation -- the page-load restore, the login-time envelope save, and
 * logout each touch several records that would otherwise be serial
 * open/close cycles.
 *
 * @param mode {IDBTransactionMode}
 * @param operations {Array<(store: IDBObjectStore) => IDBRequest>}
 * @param [idb] {IDBFactory}
 * @returns {Promise<unknown[]>}
 */
async function withSessionStoreBatch(
  mode: IDBTransactionMode,
  operations: Array<(store: IDBObjectStore) => IDBRequest>,
  idb?: IDBFactory
): Promise<unknown[]> {
  const db = await openSessionDb({ idb })
  try {
    const transaction = db.transaction(SESSION_STORE, mode)
    const store = transaction.objectStore(SESSION_STORE)
    return await Promise.all(
      operations.map(
        operation =>
          new Promise((resolve, reject) => {
            const request = operation(store)
            request.onsuccess = () => resolve(request.result)
            request.onerror = () => reject(request.error)
          })
      )
    )
  } finally {
    db.close()
  }
}

/**
 * Loads the persisted session key pair, or generates and persists a new
 * non-extractable one on first use. WebCrypto `CryptoKey` objects survive
 * IndexedDB round-trips via the structured clone algorithm without the key
 * material ever being visible to script.
 *
 * @param [options] {object}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<CryptoKeyPair>}
 */
export async function getOrCreateSessionKeyPair({
  idb
}: {
  idb?: IDBFactory
} = {}): Promise<CryptoKeyPair> {
  const existing = await loadSessionKeyPair({ idb })
  if (existing) {
    return existing
  }
  // `extractable: false` -- the private key is usable but not exportable.
  // Ed25519 in WebCrypto is available in all evergreen browsers.
  const keyPair = (await crypto.subtle.generateKey('Ed25519', false, [
    'sign',
    'verify'
  ])) as CryptoKeyPair
  await withSessionStore(
    'readwrite',
    store => store.put(keyPair, KEY_PAIR_RECORD),
    idb
  )
  return keyPair
}

/**
 * Loads the persisted session key pair, or `null` if none exists.
 *
 * @param [options] {object}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<CryptoKeyPair | null>}
 */
export async function loadSessionKeyPair({
  idb
}: {
  idb?: IDBFactory
} = {}): Promise<CryptoKeyPair | null> {
  const stored = await withSessionStore(
    'readonly',
    store => store.get(KEY_PAIR_RECORD),
    idb
  )
  return (stored as CryptoKeyPair | undefined) ?? null
}

/**
 * Saves the persisted-session record (delegated zcaps and their context;
 * see `PersistedSessionRecord` in `src/session/delegatedSession.ts`).
 *
 * @param options {object}
 * @param options.record {unknown}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function saveSessionRecord({
  record,
  idb
}: {
  record: unknown
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store => store.put(record, SESSION_RECORD),
    idb
  )
}

/**
 * Loads the persisted-session record, or `null` if none exists.
 *
 * @param [options] {object}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<unknown | null>}
 */
export async function loadSessionRecord({
  idb
}: {
  idb?: IDBFactory
} = {}): Promise<unknown | null> {
  const stored = await withSessionStore(
    'readonly',
    store => store.get(SESSION_RECORD),
    idb
  )
  return stored ?? null
}

/**
 * Saves the session vault envelope pair: the non-extractable AES-GCM
 * wrapping key (a WebCrypto `CryptoKey`, structured-cloned like the session
 * key pair) and the wrapped vault-KAK envelope it decrypts (see
 * `src/session/vault.ts`). Overwrites any previous pair -- every full login
 * mints a fresh wrapping key.
 *
 * @param options {object}
 * @param options.wrappingKey {CryptoKey}
 * @param options.envelope {unknown}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function saveVaultEnvelope({
  wrappingKey,
  envelope,
  idb
}: {
  wrappingKey: CryptoKey
  envelope: unknown
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStoreBatch(
    'readwrite',
    [
      store => store.put(wrappingKey, VAULT_KEY_RECORD),
      store => store.put(envelope, VAULT_ENVELOPE_RECORD)
    ],
    idb
  )
}

/**
 * Loads the session vault envelope pair, or `null` when either half is
 * missing (an envelope without its wrapping key -- or vice versa -- is
 * useless).
 *
 * @param [options] {object}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ wrappingKey: CryptoKey, envelope: unknown } | null>}
 */
export async function loadVaultEnvelope({
  idb
}: {
  idb?: IDBFactory
} = {}): Promise<{ wrappingKey: CryptoKey; envelope: unknown } | null> {
  const [wrappingKey, envelope] = (await withSessionStoreBatch(
    'readonly',
    [
      store => store.get(VAULT_KEY_RECORD),
      store => store.get(VAULT_ENVELOPE_RECORD)
    ],
    idb
  )) as [CryptoKey | undefined, unknown]
  if (!wrappingKey || envelope === undefined || envelope === null) {
    return null
  }
  return { wrappingKey, envelope }
}

/**
 * Deletes the session vault envelope pair (both the wrapping key and the
 * envelope). Called when the envelope turns out to be unusable (fail closed)
 * and as part of clearing the persisted session.
 *
 * @param [options] {object}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function deleteVaultEnvelope({
  idb
}: {
  idb?: IDBFactory
} = {}): Promise<void> {
  await withSessionStoreBatch(
    'readwrite',
    [
      store => store.delete(VAULT_ENVELOPE_RECORD),
      store => store.delete(VAULT_KEY_RECORD)
    ],
    idb
  )
}

/**
 * Deletes the persisted session: the record, the key pair, and the vault
 * envelope. Called on logout -- the next login mints a fresh session key.
 * The keyring cache entries (see `saveKeyringCache`) are deliberately left
 * intact so that offline / no-WAS logins keep working across a logout;
 * when a WAS server is configured their offline use is bounded by the
 * keyring cache TTL.
 *
 * @param [options] {object}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function clearPersistedSession({
  idb
}: {
  idb?: IDBFactory
} = {}): Promise<void> {
  // The record, the key pair, and the vault envelope pair (its wrapping key
  // and envelope) all clear in a single transaction rather than four serial
  // open/close cycles.
  await withSessionStoreBatch(
    'readwrite',
    [
      store => store.delete(SESSION_RECORD),
      store => store.delete(KEY_PAIR_RECORD),
      store => store.delete(VAULT_ENVELOPE_RECORD),
      store => store.delete(VAULT_KEY_RECORD)
    ],
    idb
  )
}

/**
 * The object-store key under which a Space's keyring record is cached. Keyed by
 * the unlock Space id, so several accounts (several unlock identities) can hold
 * caches side by side in the shared session database.
 *
 * @param spaceId {string}
 * @returns {string}
 */
function keyringCacheKey(spaceId: string): string {
  return `keyring/${spaceId}`
}

/**
 * Caches a keyring record locally (keyed by its unlock Space id) so that
 * offline and no-WAS logins can unwrap the data seed without a remote read.
 * The record is the ciphertext-bearing keyring document; it is inert without
 * the passphrase that derives the unlock key-agreement key. The entry is
 * stamped with the write time so callers can bound how long it may answer
 * as an offline fallback (see `fetchKeyringSeed` in `src/session/keyring.ts`).
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param options.record {unknown}   the keyring record to cache
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function saveKeyringCache({
  spaceId,
  record,
  idb
}: {
  spaceId: string
  record: unknown
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store =>
      store.put({ record, cachedAt: Date.now() }, keyringCacheKey(spaceId)),
    idb
  )
}

/**
 * Loads a cached keyring record by its unlock Space id, or `null` if none is
 * cached. A legacy entry (a bare record cached before write-time stamps
 * existed) comes back with `cachedAt: null` -- usable, but of unknown age.
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ record: unknown, cachedAt: number | null } | null>}
 */
export async function loadKeyringCache({
  spaceId,
  idb
}: {
  spaceId: string
  idb?: IDBFactory
}): Promise<{ record: unknown; cachedAt: number | null } | null> {
  const stored = await withSessionStore(
    'readonly',
    store => store.get(keyringCacheKey(spaceId)),
    idb
  )
  if (stored === undefined || stored === null) {
    return null
  }
  const entry = stored as { record?: unknown; cachedAt?: unknown }
  if (entry.record !== undefined && typeof entry.cachedAt === 'number') {
    return { record: entry.record, cachedAt: entry.cachedAt }
  }
  return { record: stored, cachedAt: null }
}

/**
 * Deletes a cached keyring record by its unlock Space id. Used when the
 * account's unlock identity changes (a passphrase change retires the old
 * unlock Space and its cache).
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function deleteKeyringCache({
  spaceId,
  idb
}: {
  spaceId: string
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store => store.delete(keyringCacheKey(spaceId)),
    idb
  )
}

/**
 * The object-store key under which an account's unlock-methods registry record
 * is cached. Keyed by the data controller did:key, so several accounts can hold
 * caches side by side in the shared session database. (The controller DID, not
 * the data Space id, is the stable identity available wherever the registry is
 * read -- including no-WAS deployments that have no Space.)
 *
 * @param controller {string}   the data did:key
 * @returns {string}
 */
function unlockMethodsCacheKey(controller: string): string {
  return `unlock-methods/${controller}`
}

/**
 * Caches an unlock-methods registry record locally (keyed by the data
 * controller did:key) so a no-WAS deployment has a copy to read and a
 * WAS-configured one can refresh on a remote hit. The record is the
 * JWE-wrapped registry document; it is inert without the vault KAK that
 * decrypts it.
 *
 * @param options {object}
 * @param options.controller {string}   the data did:key
 * @param options.record {unknown}   the wrapped registry record to cache
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function saveUnlockMethodsCache({
  controller,
  record,
  idb
}: {
  controller: string
  record: unknown
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store => store.put(record, unlockMethodsCacheKey(controller)),
    idb
  )
}

/**
 * Loads a cached unlock-methods registry record by the data controller did:key,
 * or `null` if none is cached.
 *
 * @param options {object}
 * @param options.controller {string}   the data did:key
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<unknown | null>}
 */
export async function loadUnlockMethodsCache({
  controller,
  idb
}: {
  controller: string
  idb?: IDBFactory
}): Promise<unknown | null> {
  const stored = await withSessionStore(
    'readonly',
    store => store.get(unlockMethodsCacheKey(controller)),
    idb
  )
  return stored === undefined ? null : stored
}

/**
 * Deletes a cached unlock-methods registry record by the data controller
 * did:key. Used when the remote registry is gone (a 404-shaped miss).
 *
 * @param options {object}
 * @param options.controller {string}   the data did:key
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function deleteUnlockMethodsCache({
  controller,
  idb
}: {
  controller: string
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store => store.delete(unlockMethodsCacheKey(controller)),
    idb
  )
}

/**
 * The object-store key under which an account's passkey-safety notice is
 * stored. Keyed by the data controller did:key -- matching the unlock-methods
 * cache -- so several accounts can hold notices side by side in the shared
 * session database.
 *
 * @param controller {string}   the data did:key
 * @returns {string}
 */
function passkeySafetyKey(controller: string): string {
  return `passkey-safety/${controller}`
}

/**
 * Saves the passkey-safety notice: the local-only, per-controller marker that a
 * passkey-only signup left the account with a single unlock method. Its presence
 * drives the dashboard's recurring "add a second login method" safety prompt
 * (the stored backup flags scale that prompt's urgency); it is deleted once a
 * second unlock method exists. Local-only and never replicated -- a UI
 * reminder, not account state. The write time is stamped here.
 *
 * @param options {object}
 * @param options.controller {string}   the data did:key
 * @param options.backupEligibility {boolean}   the passkey's BE flag at signup
 * @param options.backupState {boolean}   the passkey's BS flag at signup
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function savePasskeySafetyNotice({
  controller,
  backupEligibility,
  backupState,
  idb
}: {
  controller: string
  backupEligibility: boolean
  backupState: boolean
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store =>
      store.put(
        {
          backupEligibility,
          backupState,
          createdAt: new Date().toISOString()
        },
        passkeySafetyKey(controller)
      ),
    idb
  )
}

/**
 * Loads an account's passkey-safety notice by the data controller did:key, or
 * `null` if none is stored.
 *
 * @param options {object}
 * @param options.controller {string}   the data did:key
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ backupEligibility: boolean, backupState: boolean, createdAt: string } | null>}
 */
export async function loadPasskeySafetyNotice({
  controller,
  idb
}: {
  controller: string
  idb?: IDBFactory
}): Promise<{
  backupEligibility: boolean
  backupState: boolean
  createdAt: string
} | null> {
  const stored = await withSessionStore(
    'readonly',
    store => store.get(passkeySafetyKey(controller)),
    idb
  )
  return (
    (stored as
      | { backupEligibility: boolean; backupState: boolean; createdAt: string }
      | undefined) ?? null
  )
}

/**
 * Deletes an account's passkey-safety notice by the data controller did:key.
 * Called once a second unlock method exists (the account is no longer
 * passkey-only) and for hygiene during account deletion.
 *
 * @param options {object}
 * @param options.controller {string}   the data did:key
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function deletePasskeySafetyNotice({
  controller,
  idb
}: {
  controller: string
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store => store.delete(passkeySafetyKey(controller)),
    idb
  )
}

/**
 * Computes the session key's did:key DID from its (always-exportable) public
 * key: export as JWK, re-encode as the multicodec/multibase fingerprint.
 *
 * @param options {object}
 * @param options.publicKey {CryptoKey}
 * @returns {Promise<{ did: string, verificationMethodId: string }>}
 */
export async function sessionKeyDid({
  publicKey
}: {
  publicKey: CryptoKey
}): Promise<{ did: string; verificationMethodId: string }> {
  const publicKeyJwk = (await crypto.subtle.exportKey('jwk', publicKey)) as {
    kty: 'OKP'
    crv: 'Ed25519'
    x: string
  }
  const verificationKey = await Ed25519VerificationKey.fromJsonWebKey({
    type: 'JsonWebKey',
    publicKeyJwk
  })
  const fingerprint = verificationKey.fingerprint()
  const did = `did:key:${fingerprint}`
  return { did, verificationMethodId: `${did}#${fingerprint}` }
}

/**
 * Wraps the session key pair as the pluggable signer the zcap stack expects
 * (`{ id, sign({ data }) }`). Signing happens inside WebCrypto; the private
 * key never surfaces.
 *
 * @param options {object}
 * @param options.keyPair {CryptoKeyPair}
 * @returns {Promise<{ signer: ISigner, did: string }>}
 */
export async function sessionKeySigner({
  keyPair
}: {
  keyPair: CryptoKeyPair
}): Promise<{ signer: ISigner; did: string }> {
  const { did, verificationMethodId } = await sessionKeyDid({
    publicKey: keyPair.publicKey
  })
  const signer: ISigner = {
    id: verificationMethodId,
    algorithm: 'Ed25519',
    async sign({ data }: { data: Uint8Array }) {
      const signature = await crypto.subtle.sign(
        'Ed25519',
        keyPair.privateKey,
        data as BufferSource
      )
      return new Uint8Array(signature)
    }
  }
  return { signer, did }
}
