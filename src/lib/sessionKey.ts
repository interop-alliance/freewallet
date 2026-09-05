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
 * One session-database entry family: the object-store key derived from an
 * id under a fixed prefix, plus the save, load, and delete operations over
 * it. The id field is named per family (`spaceId` for the unlock-layer
 * entries, `controller` for the per-account ones), so an instance's
 * operations carry the same option names the exported functions always had.
 * `save` stores the given value verbatim and `load` returns it verbatim (or
 * `null` on a miss); a family whose stored value is shaped or stamped wraps
 * these in a thin function of its own.
 *
 * @param options {object}
 * @param options.prefix {string}   the object-store key prefix
 * @param options.idKey {string}   the name of the id field in every option
 *   object
 * @returns {object}
 */
function sessionEntry<IdKey extends string>({
  prefix,
  idKey
}: {
  prefix: string
  idKey: IdKey
}) {
  type EntryOptions = { [Key in IdKey]: string } & { idb?: IDBFactory }
  const key = (id: string): string => `${prefix}/${id}`
  const keyOf = (options: EntryOptions): string => key(options[idKey])
  return {
    key,
    async save(options: EntryOptions & { record: unknown }): Promise<void> {
      await withSessionStore(
        'readwrite',
        store => store.put(options.record, keyOf(options)),
        options.idb
      )
    },
    async load(options: EntryOptions): Promise<unknown | null> {
      const stored = await withSessionStore(
        'readonly',
        store => store.get(keyOf(options)),
        options.idb
      )
      return stored === undefined ? null : stored
    },
    async delete(options: EntryOptions): Promise<void> {
      await withSessionStore(
        'readwrite',
        store => store.delete(keyOf(options)),
        options.idb
      )
    }
  }
}

/**
 * A Space's cached keyring record. Keyed by the unlock Space id, so several
 * accounts (several unlock identities) can hold caches side by side in the
 * shared session database.
 */
const keyringCache = sessionEntry({ prefix: 'keyring', idKey: 'spaceId' })

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
  await keyringCache.save({
    spaceId,
    record: { record, cachedAt: Date.now() },
    idb
  })
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
  const stored = await keyringCache.load({ spaceId, idb })
  if (stored === null) {
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
export const deleteKeyringCache = keyringCache.delete

/**
 * An unlock method's wrapped client-key record. Keyed by the unlock Space id
 * -- like the keyring cache -- so each unlock method (passphrase, each
 * passkey) holds its own wrap of this client's key set, and several accounts
 * can coexist in the shared session database.
 */
const clientKeyRecords = sessionEntry({
  prefix: 'client-keys',
  idKey: 'spaceId'
})

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
export const saveClientKeyRecord = clientKeyRecords.save

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
export const loadClientKeyRecord = clientKeyRecords.load

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
export const deleteClientKeyRecord = clientKeyRecords.delete

/**
 * Deletes the whole of what one unlock method leaves on a browser: its
 * keyring cache and its wrapped client-key record. The one list of what an
 * unlock method owns locally, so a further per-credential artifact is added
 * here rather than at every retiring site.
 *
 * Create-nothing: a browser holding no session database has nothing of this
 * method to delete, and opening one to delete from it would leave a
 * residue-zero visit (the account-deletion walk's default session type) with
 * a `freewallet-session` database it never had. A failing probe proceeds
 * anyway -- deleting from an existing database must not be skippable by a
 * probe hiccup.
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
  const exists = await sessionDatabaseExists({ idb }).catch(() => true)
  if (!exists) {
    return
  }
  await deleteKeyringCache({ spaceId, idb })
  await deleteClientKeyRecord({ spaceId, idb })
}

/**
 * This client's local "which account DID did this data Space's log publish"
 * mapping, keyed by the data Space id.
 */
const accountDidForSpace = sessionEntry({
  prefix: 'account-did/space',
  idKey: 'spaceId'
})

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
  await accountDidForSpace.save({
    spaceId,
    record: { accountDid, savedAt: Date.now() },
    idb
  })
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
  const stored = await accountDidForSpace.load({ spaceId, idb })
  if (stored === null) {
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
export const deleteAccountDidForSpace = accountDidForSpace.delete

/**
 * An account's cached unlock-methods registry record. Keyed by the data
 * controller did:key, so several accounts can hold caches side by side in the
 * shared session database. (The controller DID, not the data Space id, is the
 * stable identity available wherever the registry is read -- including no-WAS
 * deployments that have no Space.)
 */
const unlockMethodsCache = sessionEntry({
  prefix: 'unlock-methods',
  idKey: 'controller'
})

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
export const saveUnlockMethodsCache = unlockMethodsCache.save

/**
 * Loads a cached unlock-methods registry record by the data controller did:key,
 * or `null` if none is cached.
 *
 * @param options {object}
 * @param options.controller {string}   the data did:key
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<unknown | null>}
 */
export const loadUnlockMethodsCache = unlockMethodsCache.load

/**
 * Deletes a cached unlock-methods registry record by the data controller
 * did:key. Used when the remote registry is gone (a 404-shaped miss).
 *
 * @param options {object}
 * @param options.controller {string}   the data did:key
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export const deleteUnlockMethodsCache = unlockMethodsCache.delete

/**
 * An account's passkey-safety notice. Keyed by the data controller did:key --
 * matching the unlock-methods cache -- so several accounts can hold notices
 * side by side in the shared session database.
 */
const passkeySafetyNotices = sessionEntry({
  prefix: 'passkey-safety',
  idKey: 'controller'
})

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
  await passkeySafetyNotices.save({
    controller,
    record: {
      backupEligibility,
      backupState,
      createdAt: new Date().toISOString()
    },
    idb
  })
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
  return (await passkeySafetyNotices.load({ controller, idb })) as {
    backupEligibility: boolean
    backupState: boolean
    createdAt: string
  } | null
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
export const deletePasskeySafetyNotice = passkeySafetyNotices.delete

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
      // The event is optional-chained: a factory that fires the handler with
      // no event (a test double) must not throw inside a callback the probe's
      // promise cannot catch, which would hang the caller.
      if ((event as IDBVersionChangeEvent | undefined)?.oldVersion === 0) {
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
