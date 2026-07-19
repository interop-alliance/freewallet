/**
 * The unlock-methods registry: the list of how an account can be unlocked
 * (passphrase, one or more passkeys). Unlike the keyring record -- which lives
 * in each unlock method's own unlock Space and holds the wrapped data seed --
 * the registry lives once in the user's DATA Space, so a logged-in wallet can
 * enumerate and manage its methods without re-deriving each unlock identity.
 *
 * The record carries a single WebAuthn `userHandle` (minted at the first
 * passkey registration and reused for every later passkey, so authenticator
 * pickers show one account rather than N) and one entry per method. Its stored
 * body is a JWE wrapped to the session's vault KAK (it names credential ids the
 * server must not read), stored as `{ version, wrapped }` -- the same envelope
 * shape the keyring record uses. The remote copy in the data Space is the
 * source of truth and is consulted first; a local cache in the
 * `freewallet-session` IndexedDB (keyed by the data controller did:key) serves
 * no-WAS deployments and refreshes on every remote hit.
 *
 * Each entry also carries, when one was minted, the management zcap the unlock
 * identity delegated to the data identity at bind time -- the authority that
 * makes tap-free revocation of a lost method possible. It grants GET/DELETE on
 * that one unlock Space only (deletion of the method, never decryption), and
 * sits JWE-wrapped to the vault KAK like the rest of the record, so the server
 * never reads it. `revokeUnlockMethod` invokes it with the session's root key
 * to retire a lost passkey; entries predating the capability fall back to
 * `revokeUnlockMethodByCeremony` (a tap on the passkey being removed).
 */
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IZcap
} from '@interop/data-integrity-core'
import { base64urlnopad } from '@scure/base'
import {
  PASSKEY_KDF,
  UNLOCK_METHODS_COLLECTION,
  WAS_SERVER_URL
} from '@/app.config'
import type { Session } from '@/types/auth'
import { assertPasskeyPrf } from '@/lib/passkey'
import { deleteUnlockMethod } from '@/session/keyring'
import { createEdvDocCipher } from '@/stores/edvDocCipher'
import {
  deleteKeyringCache,
  deleteUnlockMethodsCache,
  loadUnlockMethodsCache,
  saveUnlockMethodsCache
} from '@/lib/sessionKey'
import {
  deleteUnlockSpaceWithCapability,
  ensureUnlockMethodsCollection,
  getUnlockMethodsRecord,
  putUnlockMethodsRecord
} from '@/stores/wasRemoteStore'

/**
 * The passphrase unlock method. `manageCapability` -- the management zcap the
 * unlock identity delegated to the data identity -- is present once a full
 * passphrase login or a passphrase change has backfilled it (see
 * `backfillPassphraseUnlockMethod`).
 */
export interface PassphraseUnlockMethod {
  type: 'passphrase'
  createdAt: string
  unlockSpaceId: string
  manageCapability?: IZcap
}

/**
 * A passkey unlock method. `credentialId` is base64url-encoded; `unlockSpaceId`
 * locates the unlock Space whose keyring record this passkey's PRF output
 * unwraps. The backup flags are captured at registration so a future UI can
 * warn about device-bound (not synced) passkeys. `manageCapability` -- when
 * present -- is the management zcap that allows tap-free revocation of this
 * passkey (deletion of its unlock Space) with the session's root key.
 */
export interface PasskeyUnlockMethod {
  type: 'passkey'
  label: string
  createdAt: string
  credentialId: string
  transports: string[]
  backupEligibility: boolean
  backupState: boolean
  unlockSpaceId: string
  manageCapability?: IZcap
}

/**
 * A single unlock-method entry -- a discriminated union on `type`.
 */
export type UnlockMethod = PassphraseUnlockMethod | PasskeyUnlockMethod

/**
 * The version-1 unlock-methods registry record. `userHandle` is a base64url
 * (16-byte) WebAuthn user handle, one per wallet.
 */
export interface UnlockMethodsRecord {
  version: 1
  userHandle: string
  methods: UnlockMethod[]
}

/**
 * The version stamped on the stored `{ version, wrapped }` envelope -- the
 * outer wrapper around the JWE, distinct from the registry's own `version`.
 */
const STORED_RECORD_VERSION = 1

/**
 * Resolves the session's vault key material for wrap/unwrap, throwing when the
 * vault is locked (no KAK). The registry is a full-tier flow, so this is
 * expected to be present.
 *
 * @param session {Session}
 * @returns {{ keyAgreementKey: IKeyAgreementKey, keyResolver: IKeyResolver }}
 */
function requireVaultKeys(session: Session): {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
} {
  const { keyAgreementKey, keyResolver } = session.profile
  if (!keyAgreementKey || !keyResolver) {
    throw new Error(
      'The vault must be unlocked to read or write unlock methods.'
    )
  }
  return { keyAgreementKey, keyResolver }
}

/**
 * Wraps an unlock-methods record into its stored envelope: the record encrypted
 * (JWE, ECDH-ES to the vault KAK) via the same EDV cipher the wallet ships,
 * under the `{ version, wrapped }` shape.
 *
 * @param options {object}
 * @param options.record {UnlockMethodsRecord}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the vault KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<{ version: number, wrapped: unknown }>}
 */
async function wrapRecord({
  record,
  keyAgreementKey,
  keyResolver
}: {
  record: UnlockMethodsRecord
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<{ version: number; wrapped: unknown }> {
  const cipher = await createEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId: UNLOCK_METHODS_COLLECTION.id
  })
  const { envelope } = await cipher.encrypt({
    data: record as unknown as Parameters<typeof cipher.encrypt>[0]['data']
  })
  return { version: STORED_RECORD_VERSION, wrapped: envelope }
}

/**
 * Unwraps and validates a stored unlock-methods envelope: rejects an outer
 * `version` other than 1, decrypts the payload, then sanity-checks the
 * registry shape (its own `version`, a string `userHandle`, an array of
 * methods).
 *
 * @param options {object}
 * @param options.record {unknown}   the stored `{ version, wrapped }` envelope
 * @param options.keyAgreementKey {IKeyAgreementKey}   the vault KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<UnlockMethodsRecord>}
 */
async function unwrapRecord({
  record,
  keyAgreementKey,
  keyResolver
}: {
  record: unknown
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<UnlockMethodsRecord> {
  if (record === null || typeof record !== 'object') {
    throw new Error('Malformed unlock-methods record.')
  }
  const { version, wrapped } = record as {
    version?: unknown
    wrapped?: unknown
  }
  if (version !== STORED_RECORD_VERSION) {
    throw new Error(
      `Unsupported unlock-methods record version "${String(version)}".`
    )
  }
  const cipher = await createEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId: UNLOCK_METHODS_COLLECTION.id
  })
  const plaintext = (await cipher.decrypt({
    envelope: wrapped as never
  })) as {
    version?: unknown
    userHandle?: unknown
    methods?: unknown
  }

  if (plaintext.version !== 1) {
    throw new Error(
      `Unsupported unlock-methods registry version "${String(
        plaintext.version
      )}".`
    )
  }
  if (typeof plaintext.userHandle !== 'string' || !plaintext.userHandle) {
    throw new Error('Unlock-methods record is missing a userHandle.')
  }
  if (!Array.isArray(plaintext.methods)) {
    throw new Error('Unlock-methods record is missing its methods list.')
  }
  return {
    version: 1,
    userHandle: plaintext.userHandle,
    methods: plaintext.methods as UnlockMethod[]
  }
}

/**
 * Loads the account's unlock-methods registry, or `null` when none has been
 * written yet. When a WAS server is configured the remote copy in the data
 * Space is the source of truth: it is read first, refreshes the local cache on
 * a hit, and drops the cache on a 404-shaped miss. A remote read failure
 * rethrows (this minimal phase runs only full-tier and online). With no WAS
 * server the cache is the only copy.
 *
 * @param options {object}
 * @param options.session {Session}   a full-tier session (root zcapClient +
 *   unlocked vault)
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<UnlockMethodsRecord | null>}
 */
export async function getUnlockMethods({
  session,
  idb
}: {
  session: Session
  idb?: IDBFactory
}): Promise<UnlockMethodsRecord | null> {
  const controller = session.user.id
  const { keyAgreementKey, keyResolver } = requireVaultKeys(session)

  if (!WAS_SERVER_URL) {
    const cached = await loadUnlockMethodsCache({ controller, idb })
    if (!cached) {
      return null
    }
    try {
      return await unwrapRecord({
        record: cached,
        keyAgreementKey,
        keyResolver
      })
    } catch (err) {
      console.warn('Discarding an unusable cached unlock-methods record:', err)
      await deleteUnlockMethodsCache({ controller, idb })
      return null
    }
  }

  const record = await getUnlockMethodsRecord({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: session.profile.zcapClient,
    spaceId: requireSpaceId(session)
  })
  if (!record) {
    await deleteUnlockMethodsCache({ controller, idb })
    return null
  }
  const parsed = await unwrapRecord({ record, keyAgreementKey, keyResolver })
  await saveUnlockMethodsCache({ controller, record, idb })
  return parsed
}

/**
 * Writes the account's unlock-methods registry (last-write-wins). Wraps the
 * record under the vault KAK, and -- when a WAS server is configured -- ensures
 * the `unlock-methods` collection exists in the data Space before PUTting the
 * record there with the root zcapClient. Always refreshes the local cache.
 *
 * @param options {object}
 * @param options.session {Session}   a full-tier session (root zcapClient +
 *   unlocked vault)
 * @param options.record {UnlockMethodsRecord}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function putUnlockMethods({
  session,
  record,
  idb
}: {
  session: Session
  record: UnlockMethodsRecord
  idb?: IDBFactory
}): Promise<void> {
  const controller = session.user.id
  const { keyAgreementKey, keyResolver } = requireVaultKeys(session)
  const wrapped = await wrapRecord({ record, keyAgreementKey, keyResolver })

  if (WAS_SERVER_URL) {
    const spaceId = requireSpaceId(session)
    await ensureUnlockMethodsCollection({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: session.profile.zcapClient,
      spaceId
    })
    await putUnlockMethodsRecord({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: session.profile.zcapClient,
      spaceId,
      record: wrapped
    })
  }

  await saveUnlockMethodsCache({ controller, record: wrapped, idb })
}

/**
 * Resolves the data Space id from the session's storage, throwing when absent
 * (a WAS server is configured but the session has no remote store -- e.g. a
 * guest, which never reaches this registry).
 *
 * @param session {Session}
 * @returns {string}
 */
function requireSpaceId(session: Session): string {
  const spaceId = session.storage.spaceId
  if (!spaceId) {
    throw new Error('No remote data Space is available for unlock methods.')
  }
  return spaceId
}

/**
 * Whether a registry entry names a given unlock method: a passkey entry matches
 * on `credentialId`, a passphrase entry on its type (there is only ever one
 * passphrase entry). Used to drop the retired entry from the methods list.
 *
 * @param candidate {UnlockMethod}   an entry in the stored registry
 * @param target {UnlockMethod}   the entry being removed
 * @returns {boolean}
 */
function isSameMethod(candidate: UnlockMethod, target: UnlockMethod): boolean {
  if (target.type === 'passkey') {
    return (
      candidate.type === 'passkey' &&
      candidate.credentialId === target.credentialId
    )
  }
  return candidate.type === target.type
}

/**
 * Reloads the registry, drops the given entry, and writes the result. Shared
 * by both revocation paths -- the Space and keyring cache are already gone by
 * the time this runs, so a missing registry is simply a no-op.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {UnlockMethod}   the entry to remove
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
async function dropRegistryEntry({
  session,
  entry,
  idb
}: {
  session: Session
  entry: UnlockMethod
  idb?: IDBFactory
}): Promise<void> {
  const record = await getUnlockMethods({ session, idb })
  if (!record) {
    return
  }
  const methods = record.methods.filter(method => !isSameMethod(method, entry))
  await putUnlockMethods({ session, record: { ...record, methods }, idb })
}

/**
 * Whether an unlock method can be revoked without a WebAuthn ceremony: always
 * true with no WAS server (there is no Space to delete -- only the keyring cache
 * and the registry entry are cleared), otherwise only when the entry carries a
 * management zcap the session's root key can invoke to delete its unlock Space.
 *
 * @param entry {UnlockMethod}
 * @returns {boolean}
 */
export function canRevokeWithoutCeremony(entry: UnlockMethod): boolean {
  return !WAS_SERVER_URL || !!entry.manageCapability
}

/**
 * Revokes an unlock method tap-free: deletes its unlock Space with the entry's
 * management zcap (invoked by the session's ROOT zcapClient), drops the local
 * keyring cache for that Space, then removes the entry from the registry. This
 * is the path for a LOST passkey -- no ceremony on the authenticator being
 * removed. With a WAS server configured it requires `entry.manageCapability`
 * (callers gate on `canRevokeWithoutCeremony` first); a 404 from the Space
 * delete is tolerated (already gone). With no WAS server there is no Space to
 * delete, so only the cache and the registry entry are cleaned up.
 *
 * @param options {object}
 * @param options.session {Session}   a full-tier session (root zcapClient +
 *   unlocked vault)
 * @param options.entry {UnlockMethod}   the method to retire
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function revokeUnlockMethod({
  session,
  entry,
  idb
}: {
  session: Session
  entry: UnlockMethod
  idb?: IDBFactory
}): Promise<void> {
  if (WAS_SERVER_URL) {
    if (!entry.manageCapability) {
      throw new Error(
        'This unlock method has no management capability; it can only be ' +
          'revoked by tapping the passkey being removed.'
      )
    }
    await deleteUnlockSpaceWithCapability({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: session.profile.zcapClient,
      spaceId: entry.unlockSpaceId,
      capability: entry.manageCapability
    })
  }
  await deleteKeyringCache({ spaceId: entry.unlockSpaceId, idb })
  await dropRegistryEntry({ session, entry, idb })
}

/**
 * Revokes a passkey unlock method by ceremony -- the fallback for an entry that
 * carries no management zcap (bound before the capability existed). Asserts the
 * passkey being removed (its PRF output derives the unlock identity), deletes
 * that method's keyring (its unlock Space + cache), then drops the registry
 * entry. Requires the authenticator, so it is unusable for a genuinely lost
 * passkey -- `revokeUnlockMethod` covers that case.
 *
 * @param options {object}
 * @param options.session {Session}   a full-tier session (unlocked vault)
 * @param options.entry {PasskeyUnlockMethod}   the passkey to retire
 * @param [options.idb] {IDBFactory}
 * @param [options.signal] {AbortSignal}   aborts the WebAuthn ceremony
 * @returns {Promise<void>}
 */
export async function revokeUnlockMethodByCeremony({
  session,
  entry,
  idb,
  signal
}: {
  session: Session
  entry: PasskeyUnlockMethod
  idb?: IDBFactory
  signal?: AbortSignal
}): Promise<void> {
  const { prfOutput } = await assertPasskeyPrf({
    credentialIds: [base64urlnopad.decode(entry.credentialId)],
    signal
  })
  await deleteUnlockMethod({ secret: prfOutput, kdf: PASSKEY_KDF, idb })
  await dropRegistryEntry({ session, entry, idb })
}

/**
 * Backfills the registry's passphrase entry from the current full session,
 * without re-prompting for the passphrase. When this session was produced by a
 * passphrase login (`profile.unlockMethod.type === 'passphrase'`) with the
 * vault unlocked, it records (or corrects) the passphrase entry's unlock Space
 * and management zcap -- created at first passphrase login, updated after a
 * passphrase change made elsewhere, and completed once the profile carries a
 * management capability the stored entry lacks. Any other session (a passkey
 * login, a locked vault) writes nothing -- but still returns the existing
 * registry when it can be read, so callers (the Settings passkeys section)
 * can use this as their load-plus-backfill entry point for every session.
 *
 * The registry is created only when `createIfMissing` is set (a fresh 16-byte
 * userHandle is minted): the lazy-creation points are first passkey
 * registration and first Settings render, so a plain login never materializes
 * it. Writes only when something changed, and returns the resulting record (or
 * `null` when none exists and none was created). Errors are the caller's to
 * handle (call sites fire-and-forget with a `console.warn`).
 *
 * @param options {object}
 * @param options.session {Session}   a full-tier session
 * @param [options.idb] {IDBFactory}
 * @param [options.createIfMissing] {boolean}   mint the registry when absent;
 *   default false
 * @returns {Promise<UnlockMethodsRecord | null>}
 */
export async function backfillPassphraseUnlockMethod({
  session,
  idb,
  createIfMissing = false
}: {
  session: Session
  idb?: IDBFactory
  createIfMissing?: boolean
}): Promise<UnlockMethodsRecord | null> {
  const { unlockMethod, keyAgreementKey, keyResolver } = session.profile
  // The vault keys are needed to read (let alone write) the registry.
  if (!keyAgreementKey || !keyResolver) {
    return null
  }

  let record = await getUnlockMethods({ session, idb })
  // Only a passphrase full session can backfill; any other session (a passkey
  // login) just reports the registry as it stands -- never null when one
  // exists, so a Settings load through this function cannot mistake an
  // account with passkeys for one with no registry.
  if (unlockMethod?.type !== 'passphrase') {
    return record
  }
  if (!record) {
    if (!createIfMissing) {
      return null
    }
    record = {
      version: 1,
      userHandle: base64urlnopad.encode(
        crypto.getRandomValues(new Uint8Array(16))
      ),
      methods: []
    }
  }

  const existing = record.methods.find(
    (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
  )
  const { unlockSpaceId, manageCapability } = unlockMethod

  // Write only when the stored entry is missing, points at a stale unlock Space
  // (a passphrase change happened elsewhere), or lacks a management capability
  // the profile now carries.
  const changed =
    !existing ||
    existing.unlockSpaceId !== unlockSpaceId ||
    (!!manageCapability && !existing.manageCapability)
  if (!changed) {
    return record
  }

  const entry: PassphraseUnlockMethod = {
    type: 'passphrase',
    createdAt: existing?.createdAt ?? new Date().toISOString(),
    unlockSpaceId,
    ...(manageCapability ? { manageCapability } : {})
  }
  const methods = existing
    ? record.methods.map(method =>
        method.type === 'passphrase' ? entry : method
      )
    : [...record.methods, entry]
  const nextRecord: UnlockMethodsRecord = { ...record, methods }
  await putUnlockMethods({ session, record: nextRecord, idb })
  return nextRecord
}
