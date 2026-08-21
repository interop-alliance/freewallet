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
import { WasClient } from '@interop/was-client'
import {
  accountLogPinId,
  isWebvhDid,
  rotateWebvhUpdateKey
} from '@interop/wallet-core/webvh'
import {
  clientAnnexDidParts,
  delegatedClientsPointer
} from '@interop/wallet-core/clientAnnex'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import { PASSKEY_KDF } from '@/app.config'
import {
  establishPassphrasePosture,
  establishStandingUnlock
} from '@/session/standingUnlock'
import type { StandingUnlockFields } from '@/session/unlockMethods'
import {
  bindPassphrase,
  changePassphrase,
  deleteKeyring,
  deriveUnlockCredential,
  unlockManagementGrantee,
  verifyPassphrase,
  WrongPassphraseError
} from '@/session/keyring'
import {
  adoptPassphraseRebind,
  emptyUnlockMethodsRegistry,
  backfillPassphraseUnlockMethod,
  canRevokeWithoutCeremony,
  deleteUnlockMethodArtifacts,
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
  assertAccountCeremonyAllowed,
  assertDurableSession,
  isDurableSession
} from '@/session/persistence'
import { executeLocalWipe, snapshotWipeTargets } from '@/session/wipe'
import { rotateOffUnlockCredential } from '@/session/credentialRotation'
import { adoptRotatedUserKey } from '@/session/userKeyAdoption'
import {
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
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
 * The old passphrase is then RETIRED for real (`rotateOffUnlockCredential`):
 * its document posture leaves, the user key rotates off its roster wrap, and
 * every encrypted collection re-epochs onto the fresh key -- which is what
 * makes changing the passphrase the remedy for a leaked one. The retirement
 * runs last and its failure is reported rather than thrown (`rotation:
 * 'failed'`): the change itself cannot be rolled back, and a torn retirement
 * converges at the next login's completion sweep.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.oldPassphrase {string}
 * @param options.newPassphrase {string}
 * @returns {Promise<{ oldPassphraseRetired: boolean, unlockSpaceId: string,
 *   manageCapability?: IZcap, rotation: 'rotated' | 'skipped' | 'failed' }>}
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
  rotation: 'rotated' | 'skipped' | 'failed'
}> {
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Changing the passphrase'
  })
  const profile = session.profile
  const clientSeed = profile.clientSeed
  if (!clientSeed) {
    throw new Error('Changing the passphrase needs this client key set.')
  }
  // The OLD credential's standing posture, captured before the rebind
  // replaces the registry entry with the new passphrase's. Best-effort: an
  // unreadable registry (or an entry that never held a posture) simply means
  // there is nothing to retire.
  const oldStanding = await standingPosture({ session })
  // The keyring record is bound under the ACCOUNT controller (the first
  // client's did:key) -- on an enrolled second client it differs from this
  // client's `user.id`, so verification must match against it.
  // One derivation for the new passphrase, shared by the rebind and the
  // standing-posture establishment below.
  const newCredential = await deriveUnlockCredential({
    secret: newPassphrase,
    kdf: KEYRING_KDF
  })
  const {
    oldPassphraseRetired,
    unlockSpaceId,
    manageCapability,
    persistClientKeys,
    oldLadderSeed
  } = await changePassphrase({
    clientSeed,
    controller: profile.accountController ?? session.user.id,
    oldPassphrase,
    newPassphrase,
    userKey: profile.userKey,
    webvhUpdateKeys: profile.clientWebvhKeys,
    newCredential
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
  // Give the NEW passphrase the standing posture (roster wrap, commitment
  // document entry, bridge delegation, standing-layout record). Best-effort:
  // a failure leaves the plain rebind above, which logs in normally.
  const { ladderSeed: newLadderSeed } = await establishPassphrasePosture({
    session,
    passphrase: newPassphrase,
    email: session.user.email,
    credential: newCredential
  })
  // The session's annex-writing seed follows the live credential: the
  // old passphrase's seed is being retired, so mid-session annex writes
  // (the revocation cascade's re-mint, a later rotation's strike) must sign
  // as the new one.
  if (newLadderSeed) {
    session.profile.ladderSeed = newLadderSeed
  }
  // Retire the OLD credential: document posture out, user key rotated off its
  // roster wrap, every encrypted collection re-epoch'd, then the live session
  // adopts the fresh key. Reported, never thrown -- the passphrase change has
  // already landed and cannot roll back, and a torn retirement is finished by
  // the login-time completion sweep.
  let rotation: 'rotated' | 'skipped' | 'failed' = 'skipped'
  try {
    const outcome = await rotateOffUnlockCredential({
      session,
      method: {
        type: 'passphrase',
        ...oldStanding,
        // The old record's ladder seed, captured by the rebind before the old
        // unlock Space was deleted: the retirement's ladder attribution then
        // holds every rung a priori rather than walking from the recorded one.
        ...(oldLadderSeed ? { ladderSeed: oldLadderSeed } : {})
      },
      // The new credential's seed survives the retirement; the annex
      // strike-or-swap stage signs (or re-mints the generation) with it,
      // never with the retired seed.
      ...(newLadderSeed ? { survivingLadderSeed: newLadderSeed } : {}),
      verb: 'changing the passphrase'
    })
    if (outcome?.rotated && outcome.userKey) {
      rotation = 'rotated'
      await adoptRotatedUserKey({
        session,
        spaceId: rotationSpaceId({ session }),
        userKey: outcome.userKey
      })
    }
  } catch (err) {
    console.error('Could not retire the old passphrase credential:', err)
    rotation = 'failed'
  }
  return { oldPassphraseRetired, unlockSpaceId, manageCapability, rotation }
}

/**
 * The standing-posture members the registry records for the account's current
 * passphrase entry, read before a change replaces it. Best-effort: an
 * unreadable registry, or no passphrase entry at all, resolves to an empty
 * posture, which makes the retirement a skip.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<{ keyAgreementKeyMultibase?: string,
 *   updateKeyMultibase?: string }>}
 */
async function standingPosture({ session }: { session: Session }): Promise<{
  keyAgreementKeyMultibase?: string
  updateKeyMultibase?: string
}> {
  try {
    const record = await getUnlockMethods({ session })
    const entry = record?.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    return {
      keyAgreementKeyMultibase: entry?.keyAgreementKeyMultibase,
      updateKeyMultibase: entry?.updateKeyMultibase
    }
  } catch (err) {
    console.warn(
      'Could not read the passphrase posture to retire; skipping the ' +
        'credential rotation:',
      err
    )
    return {}
  }
}

/**
 * The data Space id a rotated user key is adopted against -- the account
 * pointer's, falling back to the session storage's.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {string}
 */
function rotationSpaceId({ session }: { session: Session }): string {
  return session.profile.accountPointer?.spaceId ?? session.storage.spaceId!
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
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Adding a passkey'
  })
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
  const { registration, entry } = await enrollPasskey({
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

  // Make the passkey a STANDING credential with the PRF output still in hand
  // (roster wrap, verbatim document entry -- the PRF output is high-entropy
  // -- bridge delegation, standing-layout record). Best-effort: a failure
  // leaves the plain bind above, which logs in normally and falls back to
  // the connect ceremony on a fresh browser.
  try {
    const established = await establishStandingUnlock({
      session,
      secret: registration.prfOutput,
      kdf: PASSKEY_KDF,
      lowEntropy: false,
      email: session.user.email
    })
    if (established.manageCapability) {
      entry.manageCapability = established.manageCapability
    }
    Object.assign(entry, established.standingFields)
  } catch (err) {
    console.warn(
      'Could not establish the passkey as a standing credential; a fresh ' +
        'browser will need the connect-another-wallet ceremony:',
      err
    )
  }

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
      await session.profile.persistence.passkeyNotices.delete({
        controller: session.user.id
      })
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
 * retire the passkey as a standing credential (document posture out, user key
 * rotated off its roster wrap, every encrypted collection re-epoch'd) and drop
 * the registry entry itself.
 *
 * A failed rotation throws: it runs before the registry drop, so nothing
 * irreversible has happened and a retry converges from durable state.
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
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Removing a passkey'
  })
  const verb = 'removing a passkey'
  const outcome = canRevokeWithoutCeremony(entry)
    ? await revokeUnlockMethod({ session, entry, verb })
    : await revokeUnlockMethodByCeremony({ session, entry, verb })
  // The registry teardown above ran under the pre-rotation vault keys, so the
  // live session adopts the fresh key only now (the adoption re-seals the
  // registry to it). Internally best-effort.
  if (outcome?.rotated && outcome.userKey) {
    await adoptRotatedUserKey({
      session,
      spaceId: rotationSpaceId({ session }),
      userKey: outcome.userKey
    })
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
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Adding a passphrase'
  })
  const clientSeed = session.profile.clientSeed
  if (!clientSeed) {
    throw new Error('Adding a passphrase needs this client key set.')
  }
  // Bind under the ACCOUNT controller -- the first client's did:key,
  // which differs from this client's `user.id` on an enrolled second
  // client. Management is delegated to the account identity (the
  // did:webvh on a promoted account), so any enrolled client can later
  // revoke this method.
  //
  // On a promoted account the bind runs as the full standing-posture
  // ceremony (roster wrap, commitment document entry, bridge delegation,
  // standing-layout record), so a fresh browser can later self-enroll with
  // the passphrase alone. An unpromoted (or no-WAS) account falls back to
  // the plain pointer bind.
  const accountController = session.profile.accountController ?? session.user.id
  let unlockSpaceId: string
  let manageCapability: IZcap | undefined
  let standingFields: StandingUnlockFields | undefined
  try {
    const established = await establishStandingUnlock({
      session,
      secret: passphrase,
      kdf: KEYRING_KDF,
      lowEntropy: true,
      email: session.user.email
    })
    unlockSpaceId = established.unlockSpaceId
    manageCapability = established.manageCapability
    standingFields = established.standingFields
  } catch (err) {
    console.warn(
      'Could not establish the passphrase as a standing credential; binding ' +
        'it as a plain pointer record:',
      err
    )
    const bound = await bindPassphrase({
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
    unlockSpaceId = bound.unlockSpaceId
    manageCapability = bound.manageCapability
  }
  const base = registry ?? emptyUnlockMethodsRegistry()
  const entry: PassphraseUnlockMethod = {
    type: 'passphrase',
    createdAt: new Date().toISOString(),
    unlockSpaceId,
    manageCapability,
    ...(standingFields ?? {})
  }
  const record: UnlockMethodsRecord = {
    ...base,
    methods: [...base.methods, entry]
  }
  await putUnlockMethods({ session, record })
  // The account now has a passphrase backup, so the passkey-only safety
  // prompt is resolved. Best-effort.
  try {
    await session.profile.persistence.passkeyNotices.delete({
      controller: session.user.id
    })
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
  // The subject of this ceremony is durable by nature: it rotates THIS
  // browser's did:webvh update key, and its persist-before-publish ordering
  // needs a durable client-key record to persist the rolled seeds into. So it
  // asserts durability outright. The other account-management ceremonies here
  // are reachable from a transient session, but only inside a step-up, so
  // they carry the step-up gate instead.
  assertDurableSession({
    persistence: session.profile.persistence,
    ceremony: 'Update-key rotation'
  })
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
      // The pin slot is keyed by the data Space id, so the same slot serves
      // the account log from first contact on; the read the rotation builds
      // on runs under it.
      pinStore: session.profile.persistence.logPins,
      logId: accountLogPinId({ spaceId: remoteStore.spaceId })
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
 * (a2) snapshot what only the live account can still answer: the
 * unlock-methods registry (it lives in the data Space the wipe destroys) and
 * the auxiliary annex Space's id and `gen-` collection listing (found
 * through the account document's delegated-clients pointer);
 * (b0) walk the registry and delete EVERY unlock method's server-side
 * artifacts -- its unlock Space, and with it the sealed bridge and
 * `delegatedClients` delegations -- plus each method's local trio,
 * best-effort per entry: this is what removes the dangling existence-oracle
 * Spaces a probe could still find after the account is gone (an entry
 * recording no management capability keeps its Space, stated residue);
 * (b1) tear down the auxiliary annex Space beside the account Space --
 * one recursive Space delete, run BEFORE the data-Space wipe because the
 * server resolves the auxiliary Space's did:webvh controller by reading the
 * account log out of the account Space -- and drop the annex chain-head
 * pin slots for every generation the listing named; warn-only, and a failure
 * leaves an orphan the server can identify by its `DelegatedClientsSpace`
 * type;
 * (b) wipe the remote data Space -- on failure the caller keeps the old
 * semantics: surface the error, do NOT log out, the data is still there;
 * (c) retire the passphrase keyring only after a successful wipe -- if the
 * keyring died first and the wipe then failed, the data Space would be
 * orphaned unrecoverably; non-fatal, since the data is already gone;
 * (w) run the shared wipe enumeration (`src/session/wipe.ts`) over the
 * targets snapshotted at (a2): every unlock method's local trio, the pins
 * (annex slots by prefix), the Space-keyed bookkeeping, the
 * unlock-methods cache, the replica databases, and the per-account
 * localStorage families -- a surviving replica is the one fatal stage.
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
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Deleting the account'
  })
  const isGuest = !!session.isGuest
  // One derivation for both unlock-layer steps below (the confirmation and
  // the retirement), rather than running the 600k-iteration KDF twice.
  const credential = isGuest
    ? undefined
    : await deriveUnlockCredential({ secret: passphrase, kdf: KEYRING_KDF })
  // (a) Confirm the passphrase before wiping anything -- a wrong passphrase
  // must not delete data. Guests have no keyring, so this is skipped.
  if (!isGuest) {
    try {
      // Match against the ACCOUNT controller the keyring record was bound
      // under (differs from `user.id` on an enrolled second client).
      await verifyPassphrase({
        controller: session.profile.accountController ?? session.user.id,
        passphrase,
        credential
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
  // (a2) Snapshot what only the live account can still answer, before
  // anything is deleted: the registry rides in the data Space and unwraps
  // with the session's vault keys, and the auxiliary Space is found through
  // the account document's pointer. Both best-effort -- an unreadable
  // registry or log narrows the teardown, never blocks the deletion.
  let registry: UnlockMethodsRecord | null = null
  let clientAnnex: { was: WasClient; spaceId: string } | undefined
  // The Storage Access seam: a session begun from the CHAPI popup carries the
  // unpartitioned factory here, so every session-database delete below lands
  // in the first-party bucket the records actually live in.
  const idb = isDurableSession(session.profile.persistence)
    ? session.profile.persistence.idb
    : undefined
  if (!isGuest) {
    try {
      registry = await getUnlockMethods({ session })
    } catch (err) {
      console.warn(
        'Could not read the unlock-methods registry for deletion; other ' +
          "methods' unlock Spaces survive:",
        err
      )
    }
    try {
      const pointer = session.profile.accountPointer
      if (pointer && isWebvhDid(pointer.did)) {
        const { doc } = await verifiedAccountLog({
          profile: session.profile,
          pointer
        })
        const pointedDid = delegatedClientsPointer({ doc })
        if (pointedDid !== undefined) {
          const clientAnnexSpaceId = clientAnnexDidParts({
            did: pointedDid
          }).spaceId
          const was = new WasClient({
            serverUrl: pointer.host,
            zcapClient: session.profile.zcapClient
          })
          clientAnnex = { was, spaceId: clientAnnexSpaceId }
        }
      }
    } catch (err) {
      console.warn(
        'Could not locate the auxiliary annex Space for deletion:',
        err
      )
    }

    // (b0) The registry walk: every unlock method's unlock Space (holding
    // its record with the sealed bridge and sibling delegations) and local
    // trio, best-effort per entry. Run before the data-Space wipe only for
    // ordering hygiene -- each delete rides the entry's own management zcap,
    // whose unlock Space is its own root.
    for (const entry of registry?.methods ?? []) {
      try {
        await deleteUnlockMethodArtifacts({ session, entry, idb })
      } catch (err) {
        console.warn(
          `Could not delete the ${entry.type} unlock method's artifacts:`,
          err
        )
      }
    }

    // (b1) The auxiliary annex Space, before the account Space: its
    // controller is the account did:webvh, which the server resolves by
    // reading the account log out of the account Space -- once that is
    // wiped, no authority can reach the auxiliary Space again. One recursive
    // delete covers the generation collections and the embedded delegations;
    // the annex chain-head pin slots are cleared by the shared wipe
    // enumeration below (by prefix, so they go even when this delete fails).
    if (clientAnnex) {
      try {
        await clientAnnex.was.space(clientAnnex.spaceId).delete()
      } catch (err) {
        console.warn(
          'Could not tear down the auxiliary annex Space; it survives ' +
            'as a typed orphan:',
          err
        )
      }
    }
  }
  // The wipe targets, snapshotted from the session and the discovery above
  // before any local state is deleted.
  const targets = snapshotWipeTargets({
    session,
    registry,
    clientAnnexSpaceId: clientAnnex?.spaceId
  })
  // (b) Wipe the remote data Space. On failure keep the old semantics:
  // surface the error, do not log out (the data is still there).
  try {
    console.log('Wiping user data...')
    await session.storage?.wipeRemoteStorage()
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
        credential,
        idb
      })
      if (!unlockSpaceDeleted) {
        console.warn(
          'Could not delete the unlock Space during account deletion.'
        )
      }
    } catch (err) {
      console.warn('Could not retire the passphrase keyring:', err)
    }
  }
  // The local half: the shared wipe enumeration, for guests and full
  // accounts alike -- every unlock method's local trio, the pins, the
  // Space-keyed continuity bookkeeping, the caches, the replica databases,
  // and the per-account localStorage families. A surviving replica keeps the
  // old fatal semantics (the local data is still there, so do not log out);
  // every other stage failure is hygiene residue on an account already gone.
  const { failed } = await executeLocalWipe({
    targets,
    storage: session.storage ?? undefined,
    idb
  })
  if (failed.includes('replica')) {
    return 'failed'
  }
  return 'deleted'
}
