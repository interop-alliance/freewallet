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
import type { WasClient } from '@interop/was-client'
import {
  accountLogPinId,
  isWebvhDid,
  rotateWebvhUpdateKey
} from '@interop/wallet-core/webvh'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import { PASSKEY_KDF } from '@/app.config'
import {
  establishPassphraseStanding,
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
  upsertPasskeyUnlockMethod,
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
import { pointedClientAnnexReach } from '@/session/annexReach'
import { enrolledClientContext } from '@/session/enrolledContext'
import { executeLocalWipe, snapshotWipeTargets } from '@/session/wipe'
import { rotateOffUnlockCredential } from '@/session/credentialRotation'
import { adoptRotatedUserKey } from '@/session/userKeyAdoption'
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
 * A transient session makes no registry call at all: the registry is
 * durable-session state, so this returns `null` immediately rather than
 * calling the backfill or the plain read.
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
  if (!isDurableSession(session.profile.persistence)) {
    return null
  }
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
 * client-key record. The registry's passphrase entry is written LAST, after
 * the retirement, and it is the retirement's outcome that decides what
 * standing configuration the entry names (see below).
 *
 * The old passphrase is then RETIRED for real (`rotateOffUnlockCredential`):
 * its document inventory leaves, the user key rotates off its roster wrap, and
 * every encrypted collection re-epochs onto the fresh key -- which is what
 * makes changing the passphrase the remedy for a leaked one. The retirement
 * runs last and its failure is reported rather than thrown (`rotation:
 * 'failed'`): the change itself cannot be rolled back, and a torn retirement
 * converges at the next login's completion sweep.
 *
 * Four guards keep the retirement honest. The old credential's standing configuration (its
 * registry standing members) is read BEFORE anything is written, and a read
 * that fails refuses the whole change: the entry would end up naming the new
 * passphrase's multibases, leaving the leaked credential standing
 * (commitment and roster wrap intact) with nothing left to name it by. An
 * entry naming a credential the TYPED old passphrase does not derive is a
 * pending retirement from an earlier change, and is refused
 * (`PendingPassphraseRetirementError`): the entry's standing configuration and the record's
 * ladder seed would then belong to two different credentials, so the
 * retirement would remove one credential's document inventory while striking
 * the other's ladder, and the post-edit roster would re-wrap to the
 * credential just left unnamed. A login with the passphrase clears it (the
 * login-time repair), and the change can then run. A
 * "change" whose new passphrase derives the same credential as the old one
 * is refused (`SamePassphraseError`) before anything is written: the
 * retirement would strip the standing configuration the establishment just re-published,
 * while skipping it would orphan the old ladder's committed rung (the
 * establishment mints a fresh ladder seed every run), so neither outcome is
 * a change at all. And the registry write is deferred until the retirement
 * has reported, which splits its two failure directions. A retirement that
 * threw AFTER its document edit landed (`onInventoryRemoved` fired) records
 * the new standing configuration: the old credential's document inventory is already gone, so
 * any login's completion sweep finishes the roster rotation and the
 * collection cascade. A retirement that failed AT the edit records the OLD
 * credential's standing configuration under the new unlock Space, which is the one state
 * that still names the credential left standing -- the next passphrase
 * login's repair (`repairTornPassphraseRetirement`) retires it.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.oldPassphrase {string}
 * @param options.newPassphrase {string}
 * @returns {Promise<{ oldPassphraseRetired: boolean, unlockSpaceId: string,
 *   manageCapability?: IZcap, rotation: 'rotated' | 'skipped' | 'failed',
 *   registry: UnlockMethodsRecord | null }>}
 * @throws {WrongPassphraseError}   the current passphrase did not verify
 * @throws {SamePassphraseError}   the new passphrase is the current one
 * @throws {PendingPassphraseRetirementError}   the registry still names an
 *   earlier passphrase whose retirement did not finish
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
  registry: UnlockMethodsRecord | null
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
  // The OLD credential's standing configuration, captured before the rebind
  // replaces the registry entry with the new passphrase's -- the retirement
  // must hold the old multibases before the upsert destroys them. A session
  // that cannot run a retirement at all (no WAS, a guest, an unpromoted
  // account) has nothing to read; otherwise an unreadable registry refuses
  // the change up front, while nothing has been written yet.
  const oldStanding = enrolledClientContext({ session })
    ? await standingConfiguration({ session })
    : {}
  // The keyring record is bound under the ACCOUNT controller (the first
  // client's did:key) -- on an enrolled second client it differs from this
  // client's `user.id`, so verification must match against it.
  // One derivation each for the typed old and new passphrases, shared by the
  // rebind, the pending-retirement guard, and the standing-configuration
  // establishment below, so neither KDF runs twice.
  const [oldCredential, newCredential] = await Promise.all([
    deriveUnlockCredential({ secret: oldPassphrase, kdf: KEYRING_KDF }),
    deriveUnlockCredential({ secret: newPassphrase, kdf: KEYRING_KDF })
  ])
  // An entry recording a credential the typed old passphrase does not derive
  // is an earlier change's pending retirement. Refused before anything is
  // written: this run's retirement would be handed that credential's standing configuration
  // beside the record's own ladder seed, which belongs to the typed one.
  if (
    oldStanding.keyAgreementKeyMultibase !== undefined &&
    oldStanding.keyAgreementKeyMultibase !==
      oldCredential.standing.keyAgreementKeyMultibase
  ) {
    throw new PendingPassphraseRetirementError()
  }
  // The derivation is deterministic, so a same-string change derives the
  // credential the registry already records. Refused, not skipped: retiring
  // it would strip the standing configuration just re-published, and skipping the
  // retirement would leave the old ladder's rung committed with no registry
  // entry naming it.
  if (
    newPassphrase === oldPassphrase ||
    (oldStanding.keyAgreementKeyMultibase !== undefined &&
      oldStanding.keyAgreementKeyMultibase ===
        newCredential.standing.keyAgreementKeyMultibase)
  ) {
    throw new SamePassphraseError()
  }
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
    newCredential,
    oldCredential
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
  // Give the NEW passphrase the standing configuration (roster wrap, commitment
  // document entry, bridge delegation, standing-layout record). Best-effort:
  // a failure leaves the plain rebind above, which logs in normally.
  const { ladderSeed: newLadderSeed, established } =
    await establishPassphraseStanding({
      session,
      passphrase: newPassphrase,
      email: session.user.email,
      credential: newCredential,
      // The registry entry is written below, once the retirement has
      // reported: which credential's standing configuration it must name depends on how the
      // retirement ended.
      recordInRegistry: false
    })
  // The session's annex-writing seed follows the live credential: the
  // old passphrase's seed is being retired, so mid-session annex writes
  // (the revocation cascade's re-mint, a later rotation's strike) must sign
  // as the new one.
  if (newLadderSeed) {
    session.profile.ladderSeed = newLadderSeed
  }
  // Retire the OLD credential: document inventory out, user key rotated off its
  // roster wrap, every encrypted collection re-epoch'd, then the live session
  // adopts the fresh key. Reported, never thrown -- the passphrase change has
  // already landed and cannot roll back, and a torn retirement is finished by
  // the login-time completion sweep.
  let rotation: 'rotated' | 'skipped' | 'failed' = 'skipped'
  // Whether the retirement's document edit landed. It is proven by the
  // ceremony having reached the stage that fires this, never inferred from
  // the throw.
  let inventoryRemoved = false
  try {
    const outcome = await rotateOffUnlockCredential({
      onInventoryRemoved: () => {
        inventoryRemoved = true
      },
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
  // The registry write, last. A retirement that succeeded, that had nothing
  // to retire, or that died after its document edit landed, records the NEW
  // credential's standing configuration (undefined when the establishment did not run,
  // which leaves the upsert's carry rule in charge). A retirement that
  // failed AT the edit records the OLD credential's standing configuration instead: the
  // entry then names the new unlock Space but the old credential's
  // multibases, which is the state the login-time repair detects and
  // finishes. Restating it explicitly is what makes it survive -- the upsert
  // drops an entry's carried standing fields when the unlock Space changes.
  const retirementFailedAtTheEdit = rotation === 'failed' && !inventoryRemoved
  let standing: StandingUnlockFields | undefined = established?.standingFields
  if (retirementFailedAtTheEdit) {
    standing =
      Object.keys(oldStanding).length > 0 ? { ...oldStanding } : undefined
  }
  // The standing establishment re-minted the management zcap with PUT (the
  // bind's is the narrow GET/DELETE one); the entry records the wide one, so
  // the revocation cascade can re-PUT this credential's record.
  const registry = await recordPassphraseEntry({
    session,
    unlockSpaceId,
    manageCapability: established?.manageCapability ?? manageCapability,
    standing
  })
  return {
    oldPassphraseRetired,
    unlockSpaceId,
    manageCapability,
    rotation,
    registry
  }
}

/**
 * The new passphrase is the current one: a change that would retire the
 * credential it just re-established, refused before anything is written.
 */
export class SamePassphraseError extends Error {
  constructor(
    message = 'The new passphrase must differ from the current one.'
  ) {
    super(message)
    this.name = 'SamePassphraseError'
  }
}

/**
 * The registry's passphrase entry names a credential the typed old
 * passphrase does not derive: an earlier change whose retirement did not
 * finish. Refused before anything is written -- a login with the passphrase
 * runs the repair, after which the change can proceed.
 */
export class PendingPassphraseRetirementError extends Error {
  constructor(
    message = 'The registry still names a passphrase whose retirement did ' +
      'not finish; log in again with the passphrase first so it completes.'
  ) {
    super(message)
    this.name = 'PendingPassphraseRetirementError'
  }
}

/**
 * The standing-inventory members the registry records for the account's current
 * passphrase entry, read before a change replaces it -- the WHOLE set, not
 * just the two multibases the retirement names by: a change whose retirement
 * fails at its document edit restates this verbatim, and an entry that lost
 * `unlockClientDid` would silently drop out of every delegation re-mint pass
 * while it stands pending. No registry, or no passphrase entry (a bind that
 * never established a standing configuration), resolves to empty, which makes the
 * retirement a skip. A read that FAILS is not an empty configuration: it throws, so
 * the caller refuses the change instead of overwriting the entry it could not
 * read.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<StandingUnlockFields>}
 * @throws {Error}   the registry could not be read
 */
async function standingConfiguration({
  session
}: {
  session: Session
}): Promise<StandingUnlockFields> {
  let record: UnlockMethodsRecord | null
  try {
    record = await getUnlockMethods({ session })
  } catch (err) {
    throw new Error(
      'Could not read the passphrase standing configuration to retire; the passphrase was ' +
        'not changed.',
      { cause: err }
    )
  }
  const entry = record?.methods.find(
    (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
  )
  if (!entry) {
    return {}
  }
  // Everything the entry holds beside its non-standing members IS its
  // standing configuration, so the set carries across without restating the
  // interface here (the upsert's carry rule reads the same way).
  const {
    type: _type,
    createdAt: _createdAt,
    unlockSpaceId: _unlockSpaceId,
    manageCapability: _manageCapability,
    ...standingMembers
  } = entry
  return standingMembers
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
 * Writes the registry's passphrase entry for a change that has already
 * landed: it points at the new unlock Space and carries the standing configuration
 * the caller decided on (the new credential's, or the old one's when the
 * retirement failed at its document edit). The entry's original creation date
 * is preserved. Best-effort -- the passphrase change itself has already
 * succeeded, so a failure resolves to `null` instead of throwing.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.unlockSpaceId {string}
 * @param [options.manageCapability] {IZcap}
 * @param [options.standing] {StandingUnlockFields}   the standing configuration the entry
 *   must name; absent leaves the upsert's carry rule in charge
 * @returns {Promise<UnlockMethodsRecord | null>}   the updated registry, or
 *   null when there was nothing to update (or the update failed)
 */
async function recordPassphraseEntry({
  session,
  unlockSpaceId,
  manageCapability,
  standing
}: {
  session: Session
  unlockSpaceId: string
  manageCapability?: IZcap
  standing?: StandingUnlockFields
}): Promise<UnlockMethodsRecord | null> {
  try {
    const current = await getUnlockMethods({ session })
    if (!current) {
      return null
    }
    // `manageCapability` is written unconditionally: a change that minted
    // none must clear the one the retired unlock Space's entry carried.
    const updated = upsertPassphraseUnlockMethod({
      record: current,
      unlockSpaceId,
      manageCapability,
      keepAbsentManageCapability: true,
      ...(standing ? { standing } : {})
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
 * The registry is re-read immediately before the write and the new entry is
 * merged into that FRESH record, so a change another tab, another client, or
 * a login-time refresh landed since the page loaded is not reverted. The
 * page-held record seeds only the two inputs the WebAuthn ceremony needs
 * before the write exists: the wallet-wide user handle the passkey registers
 * under, and the exclude list of authenticators already holding one.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.registry {UnlockMethodsRecord | null}   the registry already
 *   in hand, used ONLY for the WebAuthn user handle and the exclude list; a
 *   fresh one is minted when none has been written yet
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

  // Merge into a FRESH read rather than into the page-held record: anything
  // written between the page's load and this write (another tab, another
  // client, a login-time refresh) must survive. A fresh read that comes back
  // empty falls back to `base` rather than to a new empty registry -- the
  // passkey was just registered under `base.userHandle`, so that handle is
  // the one that has to be persisted. A fresh read carrying a DIFFERENT
  // handle wins anyway: the stored record is the source of truth, and the
  // registration is already bound either way.
  let record: UnlockMethodsRecord = upsertPasskeyUnlockMethod({
    record: base,
    entry
  })
  try {
    const fresh = await getUnlockMethods({ session })
    record = upsertPasskeyUnlockMethod({ record: fresh ?? base, entry })
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
 * The label is mapped onto a FRESH read of the registry rather than onto the
 * page-held record, so a rename does not revert whatever else was written
 * since the page loaded. Two cases end without a write: a fresh read that no
 * longer lists the renamed `credentialId` (the passkey was removed
 * elsewhere) returns that record unchanged rather than re-adding a retired
 * entry, and a registry that does not exist at all throws -- the UI offers
 * rename only on a listed entry, so there is nothing honest to write.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.entry {PasskeyUnlockMethod}   the passkey being renamed
 * @param options.label {string}   the new label (already trimmed)
 * @returns {Promise<UnlockMethodsRecord>}   the updated registry
 * @throws {Error}   no registry has been written for this account
 */
export async function renameAccountPasskey({
  session,
  entry,
  label
}: {
  session: Session
  entry: PasskeyUnlockMethod
  label: string
}): Promise<UnlockMethodsRecord> {
  const current = await getUnlockMethods({ session })
  if (!current) {
    throw new Error(
      'There is no unlock-methods registry to rename a passkey in.'
    )
  }
  const listed = current.methods.some(
    method =>
      method.type === 'passkey' && method.credentialId === entry.credentialId
  )
  if (!listed) {
    return current
  }
  const record: UnlockMethodsRecord = {
    ...current,
    methods: current.methods.map(method =>
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
 * retire the passkey as a standing credential (document inventory out, user key
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
 * The registry is re-read immediately before the write and the entry is
 * UPSERTED into that fresh record (there is only ever one passphrase entry),
 * so neither a concurrent write nor a second run of this ceremony can be
 * reverted or duplicated. A fresh read that comes back empty starts from a
 * newly minted registry.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.passphrase {string}
 * @returns {Promise<UnlockMethodsRecord>}   the updated registry
 */
export async function addAccountPassphrase({
  session,
  passphrase
}: {
  session: Session
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
  // On a promoted account the bind runs as the full standing-configuration
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
  // The merge base is a fresh read, never the page-held record: a concurrent
  // write must not be reverted here. The upsert also makes a second run of
  // this ceremony replace the single passphrase entry instead of appending a
  // duplicate one naming a different credential.
  const current = await getUnlockMethods({ session })
  const record = upsertPassphraseUnlockMethod({
    record: current ?? emptyUnlockMethodsRegistry(),
    unlockSpaceId,
    // The plain-bind fallback mints no capability; `keepAbsentManageCapability`
    // stays false so no `manageCapability: undefined` key is stored.
    manageCapability,
    // The plain-bind fallback establishes no standing configuration either.
    // Its entry names a freshly bound unlock Space, so the upsert's carry
    // rule has nothing stale to carry forward.
    ...(standingFields ? { standing: standingFields } : {})
  })
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
 * ceremony failed before anything was wiped, the account is gone and the
 * caller should now clear the session and leave the app, or the account is
 * gone but this browser could not CONFIRM its local replica is deleted (it
 * cannot enumerate its databases). The last is not a failure -- the remote
 * account really is deleted -- and not a plain success either, so it stays
 * its own outcome for the caller's copy.
 */
export type AccountDeletionResult =
  'wrong-passphrase' | 'failed' | 'deleted' | 'deleted-unverified'

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
 * localStorage families -- a surviving replica is the one fatal stage, and
 * a replica delete that could not be confirmed ends as
 * `'deleted-unverified'` rather than as a clean deletion.
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
  let registryUnread = false
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
      registryUnread = true
      console.warn(
        'Could not read the unlock-methods registry for deletion; other ' +
          "methods' unlock Spaces survive:",
        err
      )
    }
    try {
      const pointer = session.profile.accountPointer
      if (pointer && isWebvhDid(pointer.did)) {
        const reach = await pointedClientAnnexReach({ session, pointer })
        if (reach !== null) {
          clientAnnex = { was: reach.was, spaceId: reach.spaceId }
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
    registryUnread,
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
  const { failed, unverified } = await executeLocalWipe({
    targets,
    storage: session.storage ?? undefined,
    idb
  })
  if (failed.includes('replica')) {
    return 'failed'
  }
  if (unverified.includes('replica')) {
    return 'deleted-unverified'
  }
  return 'deleted'
}
