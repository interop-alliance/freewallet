/**
 * The unlock-methods registry: the list of how an account can be unlocked
 * (passphrase, one or more passkeys). Unlike the keyring record -- which lives
 * in each unlock method's own unlock Space and holds the encrypted account
 * pointer -- the registry lives once in the user's DATA Space, so a logged-in
 * wallet can enumerate and manage its methods without re-deriving each unlock
 * identity.
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
import type { ZcapClient } from '@interop/ezcap'
import { base64urlnopad } from '@scure/base'
import {
  DATE_FMT,
  PASSKEY_KDF,
  UNLOCK_METHODS_COLLECTION,
  WAS_SERVER_URL
} from '@/app.config'
import type { Session } from '@/types/auth'
import {
  assertPasskeyPrf,
  registerPasskey,
  type PasskeyRegistration
} from '@/lib/passkey'
import { bindUnlockSecret, deleteUnlockMethod } from '@/session/keyring'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type { PersistableClientKeys } from '@/session/keyring'
import {
  didKeyZcapClient,
  type ClientWebvhUpdateKeys
} from '@interop/wallet-core/webvh'
import type { Puk } from '@interop/wallet-core/keys'
import { createEdvDocCipher } from '@interop/was-client/edv'
import {
  deleteAccountPointerPin,
  deleteClientKeyRecord,
  deleteKeyringCache,
  deleteUnlockMethodsCache,
  loadUnlockMethodsCache,
  saveUnlockMethodsCache
} from '@/lib/sessionKey'
import { deleteUnlockSpaceWithCapability } from '@interop/wallet-core/keyring'
import {
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
 * A recovery-code unlock method (the code is a minimal
 * always-enrolled client). Beside the shared members, the entry records the
 * code's public posture so Settings can correlate it with the document and
 * roster without the code: `recoveryKid` (its PUK-roster kid),
 * `keyAgreementKeyMultibase` / `updateKeyMultibase` (the published
 * `keyAgreement` VM and the `nextKeyHashes` commitment), and
 * `delegationKeyId` (the verification method that signed the record's
 * `did.jsonl` delegation -- what the login-time health check tests against
 * the current document, since a delegation signed by a since-removed client
 * stops verifying under the current-key-set rule). Public halves only; the
 * code itself is never stored anywhere.
 */
export interface RecoveryCodeUnlockMethod {
  type: 'recovery-code'
  label: string
  createdAt: string
  unlockSpaceId: string
  manageCapability?: IZcap
  recoveryKid: string
  keyAgreementKeyMultibase: string
  updateKeyMultibase: string
  delegationKeyId?: string
}

/**
 * A single unlock-method entry -- a discriminated union on `type`, kept
 * additive (the quorum seam: a future method joins the union rather than
 * changing the record shape).
 */
export type UnlockMethod =
  PassphraseUnlockMethod | PasskeyUnlockMethod | RecoveryCodeUnlockMethod

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
 * Resolves the session's vault key material for wrap/unwrap. The vault KAK is
 * present for the life of every session, so these keys are expected to resolve;
 * the guard throws only defensively.
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
 * rethrows. With no WAS server the cache is the only copy.
 *
 * @param options {object}
 * @param options.session {Session}
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
 * @param options.session {Session}
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
 * Re-seals the remote unlock-methods record from one set of vault keys to
 * another -- the PUK-rotation bridge. The stored record is a single-recipient
 * envelope to the vault KAK, so whichever client rotates the PUK must re-wrap
 * the registry to the new one, or every later session (holding only the
 * rotated PUK) meets an envelope it cannot decrypt and the registry is lost
 * for good. Reads the remote copy (the source of truth), decrypts with the
 * pre-rotation keys, re-encrypts to the post-rotation keys, and PUTs it back;
 * a registry that does not exist yet is a no-op. The local cache is left
 * alone: with a WAS server the remote copy is read first and refreshes the
 * cache on the next hit.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   an enrolled client's root client
 * @param options.spaceId {string}   the data Space id
 * @param options.from {object}   the pre-rotation vault keys
 * @param options.from.keyAgreementKey {IKeyAgreementKey}
 * @param options.from.keyResolver {IKeyResolver}
 * @param options.to {object}   the post-rotation vault keys
 * @param options.to.keyAgreementKey {IKeyAgreementKey}
 * @param options.to.keyResolver {IKeyResolver}
 * @returns {Promise<void>}
 */
export async function rewrapUnlockMethodsRecord({
  storageServerUrl,
  zcapClient,
  spaceId,
  from,
  to
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  from: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  to: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
}): Promise<void> {
  const stored = await getUnlockMethodsRecord({
    storageServerUrl,
    zcapClient,
    spaceId
  })
  if (!stored) {
    return
  }
  const record = await unwrapRecord({
    record: stored,
    keyAgreementKey: from.keyAgreementKey,
    keyResolver: from.keyResolver
  })
  const wrapped = await wrapRecord({
    record,
    keyAgreementKey: to.keyAgreementKey,
    keyResolver: to.keyResolver
  })
  await putUnlockMethodsRecord({
    storageServerUrl,
    zcapClient,
    spaceId,
    record: wrapped
  })
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
 * on `credentialId`, a recovery-code entry on `recoveryKid`, a passphrase
 * entry on its type (there is only ever one passphrase entry). Used to drop
 * the retired entry from the methods list.
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
  if (target.type === 'recovery-code') {
    return (
      candidate.type === 'recovery-code' &&
      candidate.recoveryKid === target.recoveryKid
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
 * @param options.session {Session}
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
    // The management zcap names the account did:key as its controller (the
    // unlock layer stays did:key end to end), so the invocation must sign
    // under the did:key keyId even when the session's own client signs data
    // requests as the promoted did:webvh.
    const { keyAgent } = session.profile
    await deleteUnlockSpaceWithCapability({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: keyAgent
        ? didKeyZcapClient({ keyAgent })
        : session.profile.zcapClient,
      spaceId: entry.unlockSpaceId,
      capability: entry.manageCapability
    })
  }
  await deleteKeyringCache({ spaceId: entry.unlockSpaceId, idb })
  // Retiring the method also retires this client's local records under it:
  // the client-key wrap (other methods keep their own wraps of the same key
  // set) and the pointer pin.
  await deleteClientKeyRecord({ spaceId: entry.unlockSpaceId, idb })
  await deleteAccountPointerPin({ spaceId: entry.unlockSpaceId, idb })
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
 * @param options.session {Session}
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
 * login) writes nothing -- but still returns the existing
 * registry when it can be read, so callers (the Settings passkeys section)
 * can use this as their load-plus-backfill entry point for any session.
 *
 * The registry is created only when `createIfMissing` is set (a fresh 16-byte
 * userHandle is minted): the lazy-creation points are first passkey
 * registration and first Settings render, so a plain login never materializes
 * it. Writes only when something changed, and returns the resulting record (or
 * `null` when none exists and none was created). Errors are the caller's to
 * handle (call sites fire-and-forget with a `console.warn`).
 *
 * @param options {object}
 * @param options.session {Session}
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

/**
 * Enrolls a new passkey as an unlock method: runs the WebAuthn registration
 * ceremony, binds this client's key set under the passkey's PRF-derived
 * unlock identity, and assembles the registry entry describing the passkey.
 * The caller is responsible for persisting the returned entry in the registry
 * (and, at signup, for provisioning the data Space first). Shared by the
 * signup and Settings "add a passkey" flows.
 *
 * `delegateManagementTo` drives the entry's optional `manageCapability`: when
 * an account did:key is given (and a WAS server is configured) the bind
 * delegates GET/DELETE on the new unlock Space to it, and the entry carries
 * the resulting capability so the passkey can later be revoked tap-free;
 * otherwise the entry omits it.
 *
 * @param options {object}
 * @param options.clientSeed {Uint8Array}   this client's 32-byte seed to bind
 *   under the passkey
 * @param options.controller {string}   the account did:key
 * @param options.userHandle {Uint8Array}   the account's WebAuthn user handle
 * @param options.userName {string}   the WebAuthn user name shown in pickers
 * @param options.locale {string}   active i18n language for the entry's date label
 * @param options.promptForPrfRetry {() => boolean | Promise<boolean>}   PRF-retry
 *   consent callback (see `registerPasskey`)
 * @param [options.email] {string}   account email, carried in the wrapped record
 * @param [options.puk] {Puk}   the account's per-user key, cached in the local
 *   client-key record so a passkey login recovers it
 * @param [options.webvhUpdateKeys] {ClientWebvhUpdateKeys}   this client's
 *   did:webvh update-key seeds, cached in the local client-key record so a
 *   passkey login recovers update authority
 * @param [options.pointer] {AccountPointer}   the account pointer the new
 *   keyring record carries
 * @param [options.excludeCredentialIds] {Uint8Array[]}   authenticators already
 *   holding a passkey for this wallet, excluded from the ceremony
 * @param [options.delegateManagementTo] {string}   an account did:key to
 *   delegate the unlock Space management zcap to
 * @returns {Promise<{ registration: PasskeyRegistration, entry: PasskeyUnlockMethod }>}
 */
export async function enrollPasskey({
  clientSeed,
  controller,
  userHandle,
  userName,
  locale,
  promptForPrfRetry,
  email,
  puk,
  webvhUpdateKeys,
  pointer,
  excludeCredentialIds,
  delegateManagementTo
}: {
  clientSeed: Uint8Array
  controller: string
  userHandle: Uint8Array
  userName: string
  locale: string
  promptForPrfRetry: () => boolean | Promise<boolean>
  email?: string
  puk?: Puk
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  pointer?: AccountPointer
  excludeCredentialIds?: Uint8Array[]
  delegateManagementTo?: string
}): Promise<{
  registration: PasskeyRegistration
  entry: PasskeyUnlockMethod
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
}> {
  const registration = await registerPasskey({
    userHandle,
    userName,
    excludeCredentialIds,
    promptForPrfRetry
  })

  // Bind this client's key set under the passkey's PRF-derived unlock
  // identity -- this is what makes the passkey able to log in on this client.
  // Delegating management to the account did:key lets the passkey later be
  // revoked without a tap on the (possibly lost) authenticator.
  const { unlockSpaceId, manageCapability, persistClientKeys } =
    await bindUnlockSecret({
      clientSeed,
      controller,
      secret: registration.prfOutput,
      kdf: PASSKEY_KDF,
      email,
      puk,
      webvhUpdateKeys,
      pointer,
      delegateManagementTo
    })

  const now = new Date()
  const entry: PasskeyUnlockMethod = {
    type: 'passkey',
    label: `Passkey created ${now.toLocaleDateString(locale, DATE_FMT)}`,
    createdAt: now.toISOString(),
    credentialId: base64urlnopad.encode(registration.credentialId),
    transports: registration.transports,
    backupEligibility: registration.backupEligibility,
    backupState: registration.backupState,
    unlockSpaceId,
    ...(manageCapability ? { manageCapability } : {})
  }
  return { registration, entry, persistClientKeys }
}
