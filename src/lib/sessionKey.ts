/**
 * The `freewallet-session` IndexedDB database: a local, per-browser store
 * (deliberately separate from the RxDB wallet database, so it survives
 * wallet-storage decisions independently and is shared across tabs) holding
 * what ordinary login relies on -- the keyring cache (the offline / no-WAS
 * copy of the account-pointer record), this client's wrapped client-key
 * records, the keyring-freshness pins, the user key roster-epoch pins, the
 * roster-log and account-log chain-head pins, the unlock-methods registry
 * cache, and the
 * passkey-safety notices. None of it is secret on its own: the keyring,
 * client-key, and unlock-methods records are ciphertext, inert without the
 * passphrase-derived key; the freshness, roster-epoch, and chain-head pins and
 * the passkey-safety notice are local integrity/UI state, not secrets.
 *
 * Two kinds of entries live here and must not be conflated: the keyring and
 * unlock-methods entries are CACHES of remote records (refreshed on a hit,
 * droppable on a miss), while a client-key record is PRIMARY state -- the only
 * copy of this client's key set, never reconstructible from a server or a
 * passphrase, deleted only by the explicit unlock-method lifecycle flows.
 *
 * The three continuity pins over the account's own state -- the account-log
 * and roster-log chain-head pins and the roster-epoch pin -- are keyed by the
 * ACCOUNT DID rather than by the data Space id, so a host that mirrors an
 * account into a fresh Space id inherits the standing pins instead of a blank
 * trust-on-first-use slot, and so the pins travel with the account across a
 * legitimate host or Space migration. The unlock-layer entries (keyring
 * cache, client-key record, keyring-freshness pin) stay keyed by the unlock
 * Space id, and the unlock-methods cache and passkey-safety notice by the
 * data controller.
 */
import type {
  ResourceLogHeadPin,
  ResourceLogPinStore
} from '@interop/wallet-core/resourceLog'

const SESSION_DB_NAME = 'freewallet-session'
const SESSION_STORE = 'session'

/**
 * Every function below takes an optional `idb` (an `IDBFactory`), defaulting
 * to the global `indexedDB`. In a top-level document those are the same
 * thing; in a third-party iframe (the CHAPI popup) the global factory is a
 * PARTITIONED bucket that never sees the caches written by the top-level
 * wallet.
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
    const transaction = db.transaction(SESSION_STORE, mode)
    const store = transaction.objectStore(SESSION_STORE)
    return await new Promise((resolve, reject) => {
      const request = operation(store)
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })
  } finally {
    db.close()
  }
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
 * as an offline fallback (see `fetchKeyring` in `src/session/keyring.ts`).
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
 * The object-store key under which an unlock method's wrapped client-key
 * record lives. Keyed by the unlock Space id -- like the keyring cache -- so
 * each unlock method (passphrase, each passkey) holds its own wrap of this
 * client's key set, and several accounts can coexist in the shared session
 * database.
 *
 * @param spaceId {string}   the unlock Space id
 * @returns {string}
 */
function clientKeyRecordKey(spaceId: string): string {
  return `client-keys/${spaceId}`
}

/**
 * Saves a wrapped client-key record (this client's key set + cached user key,
 * JWE-wrapped to an unlock method's KAK), keyed by that method's unlock Space
 * id. Unlike the keyring cache this is primary state, not a cache of anything
 * remote: the client's private keys exist nowhere else.
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param options.record {unknown}   the wrapped client-key record
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function saveClientKeyRecord({
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
    store => store.put(record, clientKeyRecordKey(spaceId)),
    idb
  )
}

/**
 * Loads a wrapped client-key record by its unlock Space id, or `null` when
 * this client holds no key set under that unlock method (a browser that has
 * never provisioned or enrolled for the account).
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<unknown | null>}
 */
export async function loadClientKeyRecord({
  spaceId,
  idb
}: {
  spaceId: string
  idb?: IDBFactory
}): Promise<unknown | null> {
  const stored = await withSessionStore(
    'readonly',
    store => store.get(clientKeyRecordKey(spaceId)),
    idb
  )
  return stored === undefined ? null : stored
}

/**
 * Deletes a wrapped client-key record by its unlock Space id. Called only by
 * the explicit unlock-method lifecycle flows (a passphrase change rebinding to
 * a new unlock Space, method revocation, account deletion) -- never in
 * response to a server answer, since the record is the only copy of this
 * client's keys.
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function deleteClientKeyRecord({
  spaceId,
  idb
}: {
  spaceId: string
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store => store.delete(clientKeyRecordKey(spaceId)),
    idb
  )
}

/**
 * The object-store key under which an unlock method's keyring-freshness pin
 * lives -- keyed by the unlock Space id, like the keyring cache the pin
 * guards.
 *
 * @param spaceId {string}   the unlock Space id
 * @returns {string}
 */
function keyringFreshnessPinKey(spaceId: string): string {
  return `keyring-freshness/${spaceId}`
}

/**
 * Pins the newest signed `createdAt` this client has accepted for an unlock
 * method's keyring record. The record's own proof is what stops a storage host
 * forging one; the pin is what stops it replaying an older record it once
 * served legitimately -- a rollback that would send this client at a pointer
 * the account has since moved off. A record older than the pin is refused
 * (see `fetchKeyring` in `src/session/keyring.ts`); an equal or newer one
 * advances it, so the pin only ever moves forward. Plaintext local state: a
 * bind time is not a secret, only a continuity prior.
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param options.createdAt {string}   the record's signed bind timestamp
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function saveKeyringFreshnessPin({
  spaceId,
  createdAt,
  idb
}: {
  spaceId: string
  createdAt: string
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store =>
      store.put(
        { createdAt, pinnedAt: Date.now() },
        keyringFreshnessPinKey(spaceId)
      ),
    idb
  )
}

/**
 * Loads the pinned keyring-record bind timestamp for an unlock method, or
 * `null` when this client has never accepted a record under that method.
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<string | null>}
 */
export async function loadKeyringFreshnessPin({
  spaceId,
  idb
}: {
  spaceId: string
  idb?: IDBFactory
}): Promise<string | null> {
  const stored = await withSessionStore(
    'readonly',
    store => store.get(keyringFreshnessPinKey(spaceId)),
    idb
  )
  if (stored === null || stored === undefined) {
    return null
  }
  const { createdAt } = stored as { createdAt?: unknown }
  return typeof createdAt === 'string' ? createdAt : null
}

/**
 * Deletes the keyring-freshness pin for an unlock method -- on a remote
 * 404-shaped miss (the method was retired, so the continuity prior is stale)
 * and in the unlock-method lifecycle flows.
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function deleteKeyringFreshnessPin({
  spaceId,
  idb
}: {
  spaceId: string
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store => store.delete(keyringFreshnessPinKey(spaceId)),
    idb
  )
}

/**
 * The object-store key under which an account's user key roster-epoch pin
 * lives -- keyed by the ACCOUNT DID, not by the data Space id. A malicious
 * host that mints a fresh Space id, mirrors the world-readable log and the
 * ciphertext there, and redirects the account pointer at the copy would
 * otherwise inherit a blank continuity slot and reset every pin to
 * trust-on-first-use; keyed by the DID the mirror inherits the standing pins
 * instead. The pins therefore also travel with the account across a
 * legitimate host or Space migration under one DID.
 *
 * @param accountDid {string}   the account's did:webvh
 * @returns {string}
 */
function userKeyEpochPinKey(accountDid: string): string {
  return `user-key-epoch-pin/${accountDid}`
}

/**
 * The pinned epoch id in a stored pin record, or `null` when the record is
 * absent or malformed.
 *
 * @param stored {unknown}   the raw object-store value
 * @returns {string | null}
 */
function epochPinFrom(stored: unknown): string | null {
  if (stored === null || stored === undefined) {
    return null
  }
  const { epochId } = stored as { epochId?: unknown }
  return typeof epochId === 'string' && epochId ? epochId : null
}

/**
 * Pins the latest-seen user key roster epoch for an account -- the continuity
 * prior beside the keyring-freshness pin. The roster lives as an opaque
 * resource the server enforces no descriptor invariants on, so a served roster
 * whose epochs no longer contain (or precede) the pinned epoch is refused as
 * a rollback rather than followed (see `@interop/wallet-core/keys`). Plaintext
 * local state: an epoch id is public key material, not a secret.
 *
 * The pin is monotonic, never a blind overwrite: when a pin is already stored
 * and differs from the write, it only advances along the served (append-only)
 * epoch order in `epochIds`, and a write that would move it backward -- or
 * that cannot be ordered against the stored pin at all -- is refused as a
 * warn-and-no-op. A caller without the epoch order in hand can therefore only
 * establish a first pin or restate the stored value; it can never launder a
 * rollback into the pin.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account's did:webvh
 * @param options.epochId {string}   the roster's current epoch id (a did:key)
 * @param [options.epochIds] {string[]}   the served roster's append-only
 *   epoch-id order (oldest first), ordering the stored pin against the write
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function saveUserKeyEpochPin({
  accountDid,
  epochId,
  epochIds,
  idb
}: {
  accountDid: string
  epochId: string
  epochIds?: string[]
  idb?: IDBFactory
}): Promise<void> {
  const db = await openSessionDb({ idb })
  try {
    // Read and conditional write in ONE readwrite transaction, so the
    // compare-and-set cannot interleave with another tab's pin advance. The
    // put is issued synchronously from the read's success handler, which is
    // what keeps the transaction alive across the decision.
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(SESSION_STORE, 'readwrite')
      const store = transaction.objectStore(SESSION_STORE)
      const key = userKeyEpochPinKey(accountDid)
      const read = store.get(key)
      read.onerror = () => reject(read.error)
      read.onsuccess = () => {
        const stored = epochPinFrom(read.result)
        if (stored === epochId) {
          resolve()
          return
        }
        if (stored) {
          const storedIndex = epochIds ? epochIds.indexOf(stored) : -1
          const nextIndex = epochIds ? epochIds.indexOf(epochId) : -1
          if (
            storedIndex === -1 ||
            nextIndex === -1 ||
            nextIndex < storedIndex
          ) {
            console.warn(
              'Refusing to move the user key epoch pin backward (or off the ' +
                'served epoch order); keeping the stored pin.',
              { storedEpochId: stored, epochId }
            )
            resolve()
            return
          }
        }
        const write = store.put({ epochId, pinnedAt: Date.now() }, key)
        write.onerror = () => reject(write.error)
        write.onsuccess = () => resolve()
      }
    })
  } finally {
    db.close()
  }
}

/**
 * Advances the user key roster-epoch pin from a roster read: the served
 * descriptor carries both the epoch just authenticated and the append-only
 * epoch order the pin is checked against, so every caller that has a
 * descriptor in hand pins through here rather than restating the mapping.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account's did:webvh
 * @param options.epochId {string}   the roster's current epoch id (a did:key)
 * @param options.descriptor {{ epochs?: Array<{ id: string }> }}   the served
 *   roster descriptor
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function savePinFromDescriptor({
  accountDid,
  epochId,
  descriptor,
  idb
}: {
  accountDid: string
  epochId: string
  descriptor: { epochs?: Array<{ id: string }> }
  idb?: IDBFactory
}): Promise<void> {
  await saveUserKeyEpochPin({
    accountDid,
    epochId,
    epochIds: (descriptor.epochs ?? []).map(epoch => epoch.id),
    idb
  })
}

/**
 * Loads the pinned user key roster epoch for an account, or `null` when this
 * client has never seen the roster.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account's did:webvh
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<string | null>}
 */
export async function loadUserKeyEpochPin({
  accountDid,
  idb
}: {
  accountDid: string
  idb?: IDBFactory
}): Promise<string | null> {
  return epochPinFrom(
    await withSessionStore(
      'readonly',
      store => store.get(userKeyEpochPinKey(accountDid)),
      idb
    )
  )
}

/**
 * Deletes the pinned user key roster epoch for an account -- account deletion
 * and Space wipes, where the continuity prior is deliberately reset.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account's did:webvh
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function deleteUserKeyEpochPin({
  accountDid,
  idb
}: {
  accountDid: string
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store => store.delete(userKeyEpochPinKey(accountDid)),
    idb
  )
}

/**
 * The object-store key under which an account's roster-log chain-head pin
 * lives -- keyed by the account DID, like the roster-epoch pin, since both
 * guard the same `key-map/user-key.jsonl` roster of that account (see
 * `userKeyEpochPinKey` for why the DID rather than the Space id).
 *
 * @param accountDid {string}   the account's did:webvh
 * @returns {string}
 */
function userKeyLogPinKey(accountDid: string): string {
  return `user-key-log-head/${accountDid}`
}

/**
 * Builds the durable chain-head pin store for an account's user key roster
 * log, backed by the session database. The pin records the log's verified
 * identity (method, SCID) and latest verified head, and is what turns one-shot
 * log verification into continuity: a served log that forks, rolls back, or
 * switches identity against the pin is refused rather than adopted (see
 * `@interop/wallet-core/resourceLog`). Plaintext local state, like the epoch
 * pin beside it. The wallet-core verifier owns the write discipline (advance
 * after full verification only), so this store is a plain read/write seam.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account's did:webvh
 * @param [options.idb] {IDBFactory}
 * @returns {ResourceLogPinStore}
 */
export function userKeyLogPinStore({
  accountDid,
  idb
}: {
  accountDid: string
  idb?: IDBFactory
}): ResourceLogPinStore {
  return logPinStoreAt({ key: userKeyLogPinKey(accountDid), idb })
}

/**
 * A durable chain-head pin store over one session-database key. Each pinned
 * log gets its OWN store key: `ResourceLogPinStore` holds exactly one pin, so
 * sharing a key across logs would have each verification clobber the other's
 * pin.
 *
 * @param options {object}
 * @param options.key {string}   the object-store key the pin lives under
 * @param [options.idb] {IDBFactory}
 * @returns {ResourceLogPinStore}
 */
function logPinStoreAt({
  key,
  idb
}: {
  key: string
  idb?: IDBFactory
}): ResourceLogPinStore {
  return {
    async read(): Promise<ResourceLogHeadPin | null> {
      const stored = await withSessionStore(
        'readonly',
        store => store.get(key),
        idb
      )
      if (stored === null || stored === undefined) {
        return null
      }
      const { method, scid, head } = stored as Partial<ResourceLogHeadPin>
      if (
        typeof method !== 'string' ||
        typeof scid !== 'string' ||
        typeof head !== 'string'
      ) {
        return null
      }
      return { method, scid, head }
    },
    async write(pin: ResourceLogHeadPin): Promise<void> {
      await withSessionStore(
        'readwrite',
        store => store.put({ ...pin, pinnedAt: Date.now() }, key),
        idb
      )
    }
  }
}

/**
 * Deletes the roster-log chain-head pin for an account -- account deletion and
 * Space wipes, beside `deleteUserKeyEpochPin`.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account's did:webvh
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function deleteUserKeyLogPin({
  accountDid,
  idb
}: {
  accountDid: string
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store => store.delete(userKeyLogPinKey(accountDid)),
    idb
  )
}

/**
 * The object-store key under which an account's did:webvh account-log
 * chain-head pin lives -- keyed by the account DID like the roster-log pin,
 * but under its OWN key, since a pin store holds exactly one pin and the two
 * logs must never clobber each other's.
 *
 * @param accountDid {string}   the account's did:webvh
 * @returns {string}
 */
function accountLogPinKey(accountDid: string): string {
  return `account-log-head/${accountDid}`
}

/**
 * Builds the durable chain-head pin store for the account's did:webvh log
 * (`id/did.jsonl`), backed by the session database. Same seam and refusal
 * class as the roster-log pin beside it: a served account log that forks,
 * rolls back, or switches SCID/method against the pinned head is refused
 * rather than adopted (see `verifyAccountLog` in
 * `@interop/wallet-core/webvh`). The wallet-core verifier owns the write
 * discipline (trust-on-first-use, advance after full verification only), so
 * this store is a plain read/write seam.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account's did:webvh
 * @param [options.idb] {IDBFactory}
 * @returns {ResourceLogPinStore}
 */
export function accountLogPinStore({
  accountDid,
  idb
}: {
  accountDid: string
  idb?: IDBFactory
}): ResourceLogPinStore {
  return logPinStoreAt({ key: accountLogPinKey(accountDid), idb })
}

/**
 * Deletes the account-log chain-head pin for an account -- account deletion
 * and Space wipes, beside `deleteUserKeyLogPin`.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account's did:webvh
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function deleteAccountLogPin({
  accountDid,
  idb
}: {
  accountDid: string
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store => store.delete(accountLogPinKey(accountDid)),
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
