/**
 * The account-settings ceremonies, as plain async orchestrators: the ordered
 * sequences behind the Settings page (the login handle, the passphrase
 * keyring, the passkey unlock methods, the did:webvh update-key rotation, and
 * account deletion). Every ordering that matters for safety lives here rather
 * than in component state, so it is stated once and testable without a DOM;
 * the page keeps the form state, the confirmation dialogs, and the messages.
 */
import { base64urlnopad } from '@scure/base'
import type { IZcap } from '@interop/data-integrity-core'
import { isWebvhDid, rotateWebvhUpdateKey } from '@interop/wallet-core/webvh'
import { deriveUnlockIdentity, KEYRING_KDF } from '@interop/wallet-core/keyring'
import {
  bindPassphrase,
  changePassphrase,
  deleteKeyring,
  unlockManagementGrantee,
  verifyPassphrase,
  WrongPassphraseError
} from '@/session/keyring'
import {
  adoptPassphraseRebind,
  emptyUnlockMethodsRegistry,
  backfillPassphraseUnlockMethod,
  canRevokeWithoutCeremony,
  enrollPasskey,
  getUnlockMethods,
  putUnlockMethods,
  revokeUnlockMethod,
  revokeUnlockMethodByCeremony,
  upsertPassphraseUnlockMethod,
  type PassphraseUnlockMethod,
  type PasskeyUnlockMethod,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import {
  accountLogPinStore,
  deletePasskeySafetyNotice,
  deleteUserKeyEpochPin
} from '@/lib/sessionKey'
import { invalidateVerifiedLog } from '@/session/verifiedLog'
import { findLoginCredential, loginHandleOf } from '@/lib/loginCredential'
import type { Session } from '@/types/auth'

/**
 * Reads the account's current login handle (the self-issued Login Credential's
 * username), or an empty string when none has been chosen yet.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<string>}
 */
export async function readLoginHandle({
  session
}: {
  session: Session
}): Promise<string> {
  const credentials = await session.storage.listCredentials()
  const found = findLoginCredential({ credentials })
  return found ? (loginHandleOf(found.vc) ?? '') : ''
}

/**
 * Loads the unlock-methods registry for the Settings passkeys section, lazily
 * creating/repairing the passphrase entry (the registry's backfill point). A
 * backfill failure falls back to a plain read; a read failure propagates, so
 * the caller can show a non-blocking load error while the rest of the section
 * keeps working.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<UnlockMethodsRecord | null>}
 */
export async function loadUnlockRegistry({
  session
}: {
  session: Session
}): Promise<UnlockMethodsRecord | null> {
  try {
    return await backfillPassphraseUnlockMethod({
      session,
      createIfMissing: true
    })
  } catch (err) {
    console.warn('Could not backfill the unlock methods; reading:', err)
    return await getUnlockMethods({ session })
  }
}

/**
 * Changes the account passphrase and adopts the rebind into the live session.
 *
 * Ordering: the rebind retires the unlock identity this session logged in
 * under, so the live profile is swapped onto the new one immediately -- later
 * re-wraps (rolled update-key seeds, a rotated user key) must hit the new
 * client-key record, and the registry backfill must never repoint at the
 * deleted unlock Space. Repointing the registry's passphrase entry is a
 * separate, best-effort follow-up (`repointPassphraseUnlockMethod`), because
 * the change itself has already succeeded by then.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.oldPassphrase {string}
 * @param options.newPassphrase {string}
 * @returns {Promise<{ oldPassphraseRetired: boolean, unlockSpaceId: string,
 *   manageCapability?: IZcap }>}
 * @throws {WrongPassphraseError}   the current passphrase did not verify
 */
export async function changeAccountPassphrase({
  session,
  oldPassphrase,
  newPassphrase
}: {
  session: Session
  oldPassphrase: string
  newPassphrase: string
}): Promise<{
  oldPassphraseRetired: boolean
  unlockSpaceId: string
  manageCapability?: IZcap
}> {
  const profile = session.profile
  const clientSeed = profile.clientSeed
  if (!clientSeed) {
    throw new Error('Changing the passphrase needs this client key set.')
  }
  // The keyring record is bound under the ACCOUNT controller (the first
  // client's did:key) -- on an enrolled second client it differs from this
  // client's `user.id`, so verification must match against it.
  const {
    oldPassphraseRetired,
    unlockSpaceId,
    manageCapability,
    persistClientKeys
  } = await changePassphrase({
    clientSeed,
    controller: profile.accountController ?? session.user.id,
    oldPassphrase,
    newPassphrase,
    userKey: profile.userKey,
    webvhUpdateKeys: profile.clientWebvhKeys
  })
  // The rebind retired the unlock identity this session logged in under:
  // swap the live profile onto the new one, so later re-wraps (rolled
  // update-key seeds, a rotated user key) hit the new client-key record and the
  // registry backfill never repoints at the deleted unlock Space.
  adoptPassphraseRebind({
    session,
    unlockSpaceId,
    manageCapability,
    persistClientKeys
  })
  return { oldPassphraseRetired, unlockSpaceId, manageCapability }
}

/**
 * Repoints the registry's passphrase entry at the unlock Space a passphrase
 * change (or bind) produced, preserving the entry's original creation date.
 * Best-effort: the passphrase change itself has already succeeded, so a
 * failure resolves to `null` instead of throwing.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.unlockSpaceId {string}
 * @param [options.manageCapability] {IZcap}
 * @returns {Promise<UnlockMethodsRecord | null>}   the updated registry, or
 *   null when there was nothing to update (or the update failed)
 */
export async function repointPassphraseUnlockMethod({
  session,
  unlockSpaceId,
  manageCapability
}: {
  session: Session
  unlockSpaceId: string
  manageCapability?: IZcap
}): Promise<UnlockMethodsRecord | null> {
  try {
    const current = await getUnlockMethods({ session })
    if (!current) {
      return null
    }
    // The repoint sets `manageCapability` unconditionally: a change that
    // minted none must clear the one the retired unlock Space's entry carried.
    const updated = upsertPassphraseUnlockMethod({
      record: current,
      unlockSpaceId,
      manageCapability,
      keepAbsentManageCapability: true
    })
    await putUnlockMethods({ session, record: updated })
    return updated
  } catch (err) {
    console.warn('Could not update the passphrase unlock-method entry:', err)
    return null
  }
}

/**
 * Runs the add-a-passkey ceremony and records the new method in the registry.
 *
 * Ordering: the passkey is bound to this client's key set first, so a
 * registry write that fails still leaves a passkey that logs in -- reported
 * back as `recorded: false` rather than thrown, since the ceremony itself
 * succeeded. The passkey-safety notice is cleared only once the account
 * positively has a second unlock method.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.registry {UnlockMethodsRecord | null}   the registry already
 *   in hand (it may carry the backfilled passphrase entry); a fresh one is
 *   minted when none has been written yet
 * @param options.locale {string}   active i18n language code
 * @param options.userName {string}   WebAuthn user name for the ceremony
 * @param options.promptForPrfRetry {function}   resolves the user's choice
 *   when the authenticator needs a second (assertion) ceremony for the PRF
 * @returns {Promise<{ record: UnlockMethodsRecord, recorded: boolean }>}
 */
export async function addAccountPasskey({
  session,
  registry,
  locale,
  userName,
  promptForPrfRetry
}: {
  session: Session
  registry: UnlockMethodsRecord | null
  locale: string
  userName: string
  promptForPrfRetry: () => Promise<boolean>
}): Promise<{ record: UnlockMethodsRecord; recorded: boolean }> {
  const profile = session.profile
  const clientSeed = profile.clientSeed
  if (!clientSeed) {
    throw new Error('Adding a passkey needs this client key set.')
  }
  // Reuse the registry already loaded (it may already carry the backfilled
  // passphrase entry) so the new passkey shares the one wallet-wide user
  // handle and excludes any authenticator already holding a passkey for this
  // wallet. Fall back to a fresh registry when none has been written yet.
  const base = registry ?? emptyUnlockMethodsRegistry()
  const excludeCredentialIds = base.methods
    .filter(
      (method): method is PasskeyUnlockMethod => method.type === 'passkey'
    )
    .map(method => base64urlnopad.decode(method.credentialId))

  // Run the ceremony, bind this client's key set under the passkey's
  // unlock identity, and build the registry entry. Delegating management
  // to the account identity lets Settings later revoke this passkey
  // without a tap on the (possibly lost) authenticator -- from any
  // enrolled client, since a promoted account's grant names the
  // did:webvh. The record still binds under the account controller (the
  // FIRST client's did:key) -- on an enrolled second client it differs
  // from this client's `user.id`.
  const accountController = profile.accountController ?? session.user.id
  const { entry } = await enrollPasskey({
    clientSeed,
    userKey: profile.userKey,
    webvhUpdateKeys: profile.clientWebvhKeys,
    pointer: profile.accountPointer,
    controller: accountController,
    userHandle: base64urlnopad.decode(base.userHandle),
    userName,
    locale,
    email: session.user.email,
    excludeCredentialIds,
    delegateManagementTo: unlockManagementGrantee({
      pointer: profile.accountPointer,
      controller: accountController
    }),
    promptForPrfRetry
  })

  const record: UnlockMethodsRecord = {
    ...base,
    methods: [...base.methods, entry]
  }
  try {
    await putUnlockMethods({ session, record })
  } catch (err) {
    // The passkey is already bound and will log in; only the registry
    // listing entry failed to persist.
    console.error('Could not record the new passkey in the registry:', err)
    return { record, recorded: false }
  }
  // The account now has a second unlock method, so the dashboard's
  // passkey-only safety prompt is resolved. Non-fatal.
  if (record.methods.length > 1) {
    try {
      await deletePasskeySafetyNotice({ controller: session.user.id })
    } catch (err) {
      console.warn('Could not clear the passkey-safety notice:', err)
    }
  }
  return { record, recorded: true }
}

/**
 * Saves an edited passkey label back to the registry.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.registry {UnlockMethodsRecord}
 * @param options.entry {PasskeyUnlockMethod}   the passkey being renamed
 * @param options.label {string}   the new label (already trimmed)
 * @returns {Promise<UnlockMethodsRecord>}   the updated registry
 */
export async function renameAccountPasskey({
  session,
  registry,
  entry,
  label
}: {
  session: Session
  registry: UnlockMethodsRecord
  entry: PasskeyUnlockMethod
  label: string
}): Promise<UnlockMethodsRecord> {
  const record: UnlockMethodsRecord = {
    ...registry,
    methods: registry.methods.map(method =>
      method.type === 'passkey' && method.credentialId === entry.credentialId
        ? { ...method, label }
        : method
    )
  }
  await putUnlockMethods({ session, record })
  return record
}

/**
 * Removes a passkey: tap-free via its management zcap when present, else a
 * WebAuthn ceremony against that passkey (legacy entries). Both paths also
 * drop the registry entry itself.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {PasskeyUnlockMethod}
 * @returns {Promise<void>}
 */
export async function removeAccountPasskey({
  session,
  entry
}: {
  session: Session
  entry: PasskeyUnlockMethod
}): Promise<void> {
  if (canRevokeWithoutCeremony(entry)) {
    await revokeUnlockMethod({ session, entry })
  } else {
    await revokeUnlockMethodByCeremony({ session, entry })
  }
}

/**
 * Adds a passphrase unlock method to a passkey-only account: binds this
 * client's key set under a passphrase unlock identity and appends a passphrase
 * registry entry.
 *
 * Ordering: the bind comes first, so a registry write that fails still leaves
 * a passphrase that logs in. The passkey-safety notice is cleared last and is
 * best-effort -- the account now has a passphrase backup either way.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.registry {UnlockMethodsRecord | null}
 * @param options.passphrase {string}
 * @returns {Promise<UnlockMethodsRecord>}   the updated registry
 */
export async function addAccountPassphrase({
  session,
  registry,
  passphrase
}: {
  session: Session
  registry: UnlockMethodsRecord | null
  passphrase: string
}): Promise<UnlockMethodsRecord> {
  const clientSeed = session.profile.clientSeed
  if (!clientSeed) {
    throw new Error('Adding a passphrase needs this client key set.')
  }
  // Bind under the ACCOUNT controller -- the first client's did:key,
  // which differs from this client's `user.id` on an enrolled second
  // client. Management is delegated to the account identity (the
  // did:webvh on a promoted account), so any enrolled client can later
  // revoke this method.
  const accountController = session.profile.accountController ?? session.user.id
  const { unlockSpaceId, manageCapability } = await bindPassphrase({
    clientSeed,
    controller: accountController,
    passphrase,
    email: session.user.email,
    userKey: session.profile.userKey,
    webvhUpdateKeys: session.profile.clientWebvhKeys,
    pointer: session.profile.accountPointer,
    delegateManagementTo: unlockManagementGrantee({
      pointer: session.profile.accountPointer,
      controller: accountController
    })
  })
  const base = registry ?? emptyUnlockMethodsRegistry()
  const entry: PassphraseUnlockMethod = {
    type: 'passphrase',
    createdAt: new Date().toISOString(),
    unlockSpaceId,
    manageCapability
  }
  const record: UnlockMethodsRecord = {
    ...base,
    methods: [...base.methods, entry]
  }
  await putUnlockMethods({ session, record })
  // The account now has a passphrase backup, so the passkey-only safety
  // prompt is resolved. Best-effort.
  try {
    await deletePasskeySafetyNotice({ controller: session.user.id })
  } catch (err) {
    console.warn('Could not clear the passkey-safety notice:', err)
  }
  return record
}

/**
 * Rotates this client's did:webvh update key (per-client self-rotation).
 *
 * Ordering: every changed seed set is persisted into the wrapped client-key
 * record (and the in-memory profile) before and after the log extends, so a
 * crash mid-rotation resumes from durable state.
 *
 * The read the rotation builds on runs under this browser's account-log
 * chain-head pin and the account's own DID, so a truncated or substituted log
 * is refused (`ResourceLogContinuityError`) before any entry is published.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<void>}
 */
export async function rotateAccountUpdateKey({
  session
}: {
  session: Session
}): Promise<void> {
  const remoteStore = session.storage.remoteStore
  const updateKeys = session.profile.clientWebvhKeys
  const persistClientKeys = session.profile.persistClientKeys
  if (!remoteStore || !updateKeys || !persistClientKeys) {
    throw new Error('Rotating the update key needs an enrolled remote account.')
  }
  const pointerDid = session.profile.accountPointer?.did
  const expectedDid =
    session.profile.didWebvh?.did ??
    (isWebvhDid(pointerDid) ? pointerDid : undefined)
  try {
    await rotateWebvhUpdateKey({
      idStore: remoteStore.webvhIdStore(),
      updateKeys,
      persistUpdateKeys: async next => {
        await persistClientKeys({ webvhUpdateKeys: next })
        session.profile.clientWebvhKeys = next
      },
      expectedDid,
      pinStore: accountLogPinStore({ spaceId: remoteStore.spaceId })
    })
  } finally {
    // The rotation publishes a log entry (and a torn rotation may have
    // published one before failing), so the session's verified-log memo is
    // dropped either way.
    invalidateVerifiedLog({ profile: session.profile })
  }
}

/**
 * How an account-deletion attempt ended: the passphrase did not verify, the
 * ceremony failed before anything was wiped, or the account is gone and the
 * caller should now clear the session and leave the app.
 */
export type AccountDeletionResult = 'wrong-passphrase' | 'failed' | 'deleted'

/**
 * Deletes the account, in the order that keeps a failure recoverable:
 *
 * (a) confirm the passphrase before wiping anything -- a wrong passphrase must
 * not delete data (guests have no keyring, so this is skipped);
 * (b) wipe the data Space and the local replica -- on failure the caller keeps
 * the old semantics: surface the error, do NOT log out, the data is still
 * there;
 * (c) retire the passphrase keyring only after a successful wipe -- if the
 * keyring died first and the wipe then failed, the data Space would be
 * orphaned unrecoverably; non-fatal, since the data is already gone.
 *
 * (d) clearing the session and (e) leaving for the landing page stay with the
 * caller, which owns the app shell.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.passphrase {string}   ignored for a guest session
 * @returns {Promise<AccountDeletionResult>}
 */
export async function deleteAccount({
  session,
  passphrase
}: {
  session: Session
  passphrase: string
}): Promise<AccountDeletionResult> {
  const isGuest = !!session.isGuest
  // One derivation for both unlock-layer steps below (the confirmation and
  // the retirement), rather than running the 600k-iteration KDF twice.
  const unlock = isGuest
    ? undefined
    : await deriveUnlockIdentity({ secret: passphrase, kdf: KEYRING_KDF })
  // (a) Confirm the passphrase before wiping anything -- a wrong passphrase
  // must not delete data. Guests have no keyring, so this is skipped.
  if (!isGuest) {
    try {
      // Match against the ACCOUNT controller the keyring record was bound
      // under (differs from `user.id` on an enrolled second client).
      await verifyPassphrase({
        controller: session.profile.accountController ?? session.user.id,
        passphrase,
        unlock
      })
    } catch (err) {
      if (err instanceof WrongPassphraseError) {
        return 'wrong-passphrase'
      }
      // Any other failure (e.g. the remote is unreachable) is a generic
      // delete failure -- do not touch the user's data.
      console.error('Could not verify the passphrase for deletion:', err)
      return 'failed'
    }
  }
  // (b) Wipe the data Space and the local replica. On failure keep the old
  // semantics: surface the error, do not log out (the data is still there).
  try {
    console.log('Wiping user data...')
    await session.storage?.wipeStorage()
  } catch (err) {
    console.error('Error wiping user data:', err)
    return 'failed'
  }
  // (c) Retire the passphrase keyring only after a successful wipe -- if the
  // keyring died first and the wipe then failed, the data Space would be
  // orphaned unrecoverably. Non-fatal: the data is already gone, so a
  // leftover record is only a hygiene residue. Guests have no keyring.
  if (!isGuest) {
    try {
      const { unlockSpaceDeleted } = await deleteKeyring({
        passphrase,
        unlock
      })
      if (!unlockSpaceDeleted) {
        console.warn(
          'Could not delete the unlock Space during account deletion.'
        )
      }
    } catch (err) {
      console.warn('Could not retire the passphrase keyring:', err)
    }
    // Best-effort cleanup of the local passkey-safety notice for hygiene.
    try {
      await deletePasskeySafetyNotice({ controller: session.user.id })
    } catch (err) {
      console.warn('Could not delete the passkey-safety notice:', err)
    }
    // The pinned key-roster epoch is continuity state about the Space just
    // wiped: clear it beside the pointer pin `deleteKeyring` drops, so a
    // re-provisioned account is never refused against a pin from the deleted
    // one.
    const dataSpaceId = session.profile.accountPointer?.spaceId
    if (dataSpaceId) {
      try {
        await deleteUserKeyEpochPin({ spaceId: dataSpaceId })
      } catch (err) {
        console.warn('Could not delete the key-roster epoch pin:', err)
      }
    }
  }
  return 'deleted'
}
