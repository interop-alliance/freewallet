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
  const db = await openSessionDb({ idb })
  try {
    return await new Promise((resolve, reject) => {
      const transaction = db.transaction(SESSION_STORE, mode)
      const request = operation(transaction.objectStore(SESSION_STORE))
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })
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
 * Deletes the persisted session: the record *and* the key pair. Called on
 * logout -- the next login mints a fresh session key. The keyring cache
 * entries (see `saveKeyringCache`) are deliberately left intact so that
 * offline / no-WAS logins keep working across a logout.
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
  await withSessionStore(
    'readwrite',
    store => store.delete(SESSION_RECORD),
    idb
  )
  await withSessionStore(
    'readwrite',
    store => store.delete(KEY_PAIR_RECORD),
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
 * the passphrase that derives the unlock key-agreement key.
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
    store => store.put(record, keyringCacheKey(spaceId)),
    idb
  )
}

/**
 * Loads a cached keyring record by its unlock Space id, or `null` if none is
 * cached.
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<unknown | null>}
 */
export async function loadKeyringCache({
  spaceId,
  idb
}: {
  spaceId: string
  idb?: IDBFactory
}): Promise<unknown | null> {
  const stored = await withSessionStore(
    'readonly',
    store => store.get(keyringCacheKey(spaceId)),
    idb
  )
  return stored ?? null
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
