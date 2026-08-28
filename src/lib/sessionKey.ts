/**
 * The `freewallet-session` IndexedDB database: a local, per-browser store
 * (deliberately separate from the RxDB wallet database, so it survives
 * wallet-storage decisions independently and is shared across tabs) holding
 * what ordinary login relies on -- the keyring cache (the offline / no-WAS
 * copy of the account-pointer record), this client's wrapped client-key
 * records, the Space-to-DID mapping, the unlock-methods registry cache, and
 * the passkey-safety notices. None of it is secret on its own: the keyring,
 * client-key, and unlock-methods records are ciphertext, inert without the
 * passphrase-derived key; the Space-to-DID mapping and the passkey-safety
 * notice are local integrity/UI state, not secrets.
 *
 * Two kinds of entries live here and must not be conflated: the keyring and
 * unlock-methods entries are CACHES of remote records (refreshed on a hit,
 * droppable on a miss), while a client-key record is PRIMARY state -- the only
 * copy of this client's key set, never reconstructible from a server or a
 * passphrase, deleted only by the explicit unlock-method lifecycle flows.
 *
 * No continuity pin lives here. Continuity is checked within a session and
 * not across sessions (`decisions/0012-no-durable-continuity-pins.md`), so
 * every pin store a session builds is in-memory and dies with the tab. The
 * unlock-layer entries (keyring cache, client-key record) stay keyed by the
 * unlock Space id, and the unlock-methods cache and passkey-safety notice by
 * the data controller.
 */

/**
 * The session database's name -- the one browser-local IndexedDB database
 * this module owns. Exported so the wipe grades delete it by the same name
 * the opens use, rather than restating the string.
 */
export const SESSION_DB_NAME = 'freewallet-session'
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
 * Whether this browser holds a client-key record for an unlock method,
 * WITHOUT creating the session database. Any read through `openSessionDb`
 * creates `freewallet-session` on a miss (the versioned open runs
 * `onupgradeneeded`), so the login routing -- which must decide
 * "remembered here?" while remaining free to leave no trace -- first runs the
 * create-nothing existence probe (`sessionDatabaseExists`: the enumeration
 * API, or a versionless open whose upgrade is aborted) and only opens a
 * database that already exists (an open of an EXISTING database creates
 * nothing).
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<boolean>}
 */
export async function hasClientKeyRecord({
  spaceId,
  idb = indexedDB
}: {
  spaceId: string
  idb?: IDBFactory
}): Promise<boolean> {
  if (!(await sessionDatabaseExists({ idb }))) {
    return false
  }
  return (await loadClientKeyRecord({ spaceId, idb })) !== null
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
 * Deletes the whole of what one unlock method leaves on a browser: its
 * keyring cache and its wrapped client-key record. The one list of what an
 * unlock method owns locally, so a further per-credential artifact is added
 * here rather than at every retiring site.
 *
 * @param options {object}
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function deleteUnlockLocalState({
  spaceId,
  idb
}: {
  spaceId: string
  idb?: IDBFactory
}): Promise<void> {
  await deleteKeyringCache({ spaceId, idb })
  await deleteClientKeyRecord({ spaceId, idb })
}

/**
 * The object-store key under which this client's local "which account DID did
 * this data Space's log publish" mapping lives.
 *
 * @param spaceId {string}   the data Space id
 * @returns {string}
 */
function accountDidForSpaceKey(spaceId: string): string {
  return `account-did/space/${spaceId}`
}

/**
 * Records, locally, the account DID the data Space's log published as. A
 * signup torn between the log publication and the account-pointer backfill
 * heals at a later login whose pointer still names no did:webvh; this mapping
 * is what lets that heal state an `expectedDid` anyway, since the log was
 * published in this browser. (The chain-head pin slot needs no such bridge:
 * it is keyed by the Space id, so the same slot serves the account log from
 * true first contact on.)
 *
 * @param options {object}
 * @param options.spaceId {string}   the data Space id
 * @param options.accountDid {string}   the published account did:webvh
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function saveAccountDidForSpace({
  spaceId,
  accountDid,
  idb
}: {
  spaceId: string
  accountDid: string
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store =>
      store.put(
        { accountDid, savedAt: Date.now() },
        accountDidForSpaceKey(spaceId)
      ),
    idb
  )
}

/**
 * Loads the account DID this client saw a data Space's log publish as, or
 * `null` when it has never seen one.
 *
 * @param options {object}
 * @param options.spaceId {string}   the data Space id
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<string | null>}
 */
export async function loadAccountDidForSpace({
  spaceId,
  idb
}: {
  spaceId: string
  idb?: IDBFactory
}): Promise<string | null> {
  const stored = await withSessionStore(
    'readonly',
    store => store.get(accountDidForSpaceKey(spaceId)),
    idb
  )
  if (stored === null || stored === undefined) {
    return null
  }
  const { accountDid } = stored as { accountDid?: unknown }
  return typeof accountDid === 'string' && accountDid ? accountDid : null
}

/**
 * Deletes the local Space-to-account-DID mapping -- account deletion and Space
 * wipes. No pin is deleted beside it: every pin store is in-memory and dies
 * with the tab.
 *
 * @param options {object}
 * @param options.spaceId {string}   the data Space id
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function deleteAccountDidForSpace({
  spaceId,
  idb
}: {
  spaceId: string
  idb?: IDBFactory
}): Promise<void> {
  await withSessionStore(
    'readwrite',
    store => store.delete(accountDidForSpaceKey(spaceId)),
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
 * Whether the session database exists at all, WITHOUT creating it.
 * The probe has two tiers, because any VERSIONED open creates the database
 * on a miss: `indexedDB.databases()` answers directly where the engine has
 * it, and where it does not, a VERSIONLESS `open(SESSION_DB_NAME)` answers
 * the same question -- a versionless open of an absent database still fires
 * `onupgradeneeded` (with `oldVersion === 0`), and aborting that
 * versionchange transaction leaves nothing behind. Used by the login
 * routing (`hasClientKeyRecord`) and by the shared wipe enumeration, so a
 * wipe on a browser that never held session state does not create the very
 * database it set out to remove.
 *
 * The abort surfaces as the request's `onerror` (an `AbortError`), which is
 * this probe's "no" rather than a failure.
 *
 * @param options {object}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<boolean>}
 */
export async function sessionDatabaseExists({
  idb = indexedDB
}: {
  idb?: IDBFactory
} = {}): Promise<boolean> {
  if (typeof idb?.databases === 'function') {
    const databases = await idb.databases()
    return databases.some(db => db.name === SESSION_DB_NAME)
  }
  return await new Promise<boolean>((resolve, reject) => {
    // No version argument: an existing database opens at its own version
    // (no upgrade), and an absent one is created at version 1 -- which the
    // abort below undoes before anything is written.
    const request = idb.open(SESSION_DB_NAME)
    let absent = false
    request.onupgradeneeded = event => {
      if ((event as IDBVersionChangeEvent).oldVersion === 0) {
        absent = true
        request.transaction?.abort()
      }
    }
    request.onsuccess = () => {
      request.result.close()
      resolve(true)
    }
    request.onerror = () => {
      if (absent) {
        resolve(false)
        return
      }
      reject(request.error)
    }
    // A versionless open never blocks; if some engine says otherwise, an
    // existing connection is itself the evidence the database exists.
    request.onblocked = () => resolve(true)
  })
}
