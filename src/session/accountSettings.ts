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
import {
  generateLadderSeed,
  ladderRung
} from '@interop/wallet-core/clientAnnex'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import { DATE_FMT, PASSKEY_KDF } from '@/app.config'
import { registerPasskey } from '@/lib/passkey'
import {
  establishStandingUnlock,
  standingFieldsOfKeyringHit
} from '@/session/standingUnlock'
import type { StandingUnlockFields } from '@/session/unlockMethods'
import {
  changePassphrase,
  deleteKeyring,
  deleteUnlockMethod,
  deriveUnlockCredential,
  fetchKeyring,
  unlockKeyAgreementMembers,
  verifyPassphrase,
  WrongPassphraseError,
  type KeyringFetchResult,
  type UnlockCredential
} from '@/session/keyring'
import {
  adoptPassphraseRebind,
  emptyUnlockMethodsRegistry,
  backfillPassphraseUnlockMethod,
  canRevokeWithoutCeremony,
  deleteUnlockMethodArtifacts,
  getUnlockMethods,
  revokeUnlockMethod,
  updateUnlockMethods,
  revokeUnlockMethodByCeremony,
  upsertPasskeyUnlockMethod,
  upsertPassphraseUnlockMethod,
  type PassphraseUnlockMethod,
  type PasskeyUnlockMethod,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import { sessionRosterStore } from '@/session/rosterStore'
import {
  assertAccountCeremonyAllowed,
  assertBrowserLocalSession,
  isBrowserLocalSession
} from '@/session/persistence'
import { pointedClientAnnexReach } from '@/session/annexReach'
import {
  enrolledClientContext,
  type EnrolledClientContext
} from '@/session/enrolledContext'
import { documentListsCredential } from '@/session/pendingRetirement'
import { executeLocalWipe, snapshotWipeTargets } from '@/session/wipe'
import { rotateOffUnlockCredential } from '@/session/credentialRotation'
import { adoptRotatedUserKey } from '@/session/userKeyAdoption'
import {
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import { findLoginCredential, loginHandleOf } from '@/lib/loginCredential'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:settings')

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
 * A transient session makes no registry call at all: this surface is gated
 * on the browser-local persistence strategy, so it returns `null`
 * immediately rather than calling the backfill or the plain read.
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
  if (!isBrowserLocalSession(session.profile.persistence)) {
    return null
  }
  try {
    return await backfillPassphraseUnlockMethod({
      session,
      createIfMissing: true
    })
  } catch (err) {
    log.warn('Could not backfill the unlock methods; reading', { err })
    return await getUnlockMethods({ session })
  }
}

/**
 * Changes the account passphrase and adopts the new unlock identity into the
 * live session.
 *
 * Ordering, establish-first: on a WAS account the NEW passphrase is made a
 * standing credential BEFORE anything about the old one is touched. The old
 * passphrase is verified read-only (capturing its record's ladder seed for
 * the retirement's attribution), then `establishStandingUnlock` runs as the
 * ceremony's first write: roster wrap, commitment document entry, bridge
 * delegation, standing-layout record at the new unlock Space. Its failure
 * FAILS the change with the old credential fully intact -- record, Space,
 * standing configuration, all unchanged -- so "could not change your
 * passphrase" is true and a retry with the same new passphrase converges
 * (every establishment stage is idempotent). Only after the establishment
 * does the old unlock identity go (its Space and local state), and the live
 * profile is swapped onto the new one -- later re-wraps (rolled update-key
 * seeds, a rotated user key) must hit the new client-key record. The
 * registry's passphrase entry is written LAST, after the retirement, and it
 * is the retirement's outcome that decides what standing configuration the
 * entry names (see below). A change torn between the establishment and the
 * old credential's teardown leaves BOTH passphrases live and standing; the
 * next new-passphrase login's torn-retirement repair (or a retry of the
 * same change) retires the old one. A no-WAS (or guest, or unpromoted)
 * session keeps the plain rebind-then-delete order instead: nothing can be
 * standing there, so there is nothing to establish first.
 *
 * The old passphrase is then RETIRED for real (`rotateOffUnlockCredential`):
 * its document inventory leaves, the user key rotates off its roster wrap, and
 * every encrypted collection re-epochs onto the fresh key -- which is what
 * makes changing the passphrase the remedy for a leaked one. The retirement
 * runs last and its failure is reported rather than thrown (`rotation:
 * 'failed'`): the change itself cannot be rolled back, and a torn retirement
 * converges at the next login's completion sweep.
 *
 * Five guards keep the retirement honest. The old credential's standing configuration (its
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
 * The fifth guard covers a BARE entry: one carrying no identity members at
 * all, which the retirement would read as "nothing standing to retire".
 * That reading is only true when the credential really has no document
 * inventory. When the typed old credential IS standing in the account
 * document, reporting the change clean would be a silent failure on the one
 * remedy for a leaked passphrase -- its commitment, its roster wrap, and its
 * latent self-enrollment authority would all survive with nothing naming
 * them. So the document is consulted for a bare entry, and a bare entry over
 * a standing credential ends as `rotation: 'unretired'`, with the entry
 * rebuilt from what the change itself holds in the shape the next
 * login's repair detects. A document read that fails is
 * treated as unknown: the change still lands, and the outcome is still not
 * reported clean.
 *
 * The NEW passphrase's standing establishment is the ceremony's body, not a
 * best-effort upgrade: its failure fails the whole change (the
 * no-plain-bind-fallback rule), before the old credential is touched. The
 * residue a torn establishment can leave (a roster wrap or document
 * commitment for the new credential, with no record yet) is converged by
 * retrying the same change; a user who abandons the new passphrase for a
 * different one leaves that residue orphaned until the retry-shaped mender
 * exists (roadmap FW-342).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.oldPassphrase {string}
 * @param options.newPassphrase {string}
 * @returns {Promise<{ oldPassphraseRetired: boolean, unlockSpaceId: string,
 *   manageCapability?: IZcap,
 *   rotation: 'rotated' | 'skipped' | 'failed' | 'unretired',
 *   registry: UnlockMethodsRecord | null }>}
 * @throws {WrongPassphraseError}   the current passphrase did not verify
 * @throws {SamePassphraseError}   the new passphrase is the current one
 * @throws {PendingPassphraseRetirementError}   the registry still names an
 *   earlier passphrase whose retirement did not finish
 * @throws {Error}   the new passphrase could not be established as a
 *   standing credential; the old passphrase is unchanged
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
  rotation: 'rotated' | 'skipped' | 'failed' | 'unretired'
  registry: UnlockMethodsRecord | null
}> {
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Changing the passphrase'
  })
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes; on a settled session the chain resolved long ago.
  await session.registryReady
  const profile = session.profile
  const clientSeed = profile.clientSeed
  if (!clientSeed) {
    throw new Error('Changing the passphrase needs this client key set.')
  }
  // The OLD credential's standing configuration, captured before the change
  // replaces the registry entry with the new passphrase's -- the retirement
  // must hold the old multibases before the upsert destroys them. A session
  // that cannot run a retirement at all (no WAS, a guest, an unpromoted
  // account) has nothing to read; otherwise an unreadable registry refuses
  // the change up front, while nothing has been written yet.
  const context = enrolledClientContext({ session })
  const { fields: oldStanding, registryAbsent } = context
    ? await standingConfiguration({ session })
    : { fields: {} as StandingUnlockFields, registryAbsent: false }
  // The keyring record is bound under the ACCOUNT controller (the first
  // client's did:key) -- on an enrolled second client it differs from this
  // client's `user.id`, so verification must match against it.
  // One derivation each for the typed old and new passphrases, shared by the
  // verification, the pending-retirement guard, and the standing-configuration
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
  // The bare-entry guard. An entry with no identity members names nothing,
  // so the retirement below would skip and the change would report clean --
  // true only when the credential has no document inventory either. The
  // document is the only thing that can tell the two apart.
  const bareCredential =
    context && oldStanding.keyAgreementKeyMultibase === undefined
      ? await documentStateOfCredential({
          session,
          context,
          credential: oldCredential
        })
      : 'absent'
  // The two arms. On a WAS account (an enrolled context) the NEW passphrase
  // is established standing FIRST, before the old unlock identity is
  // touched; the plain rebind-then-delete order survives only where nothing
  // can be standing (no WAS, a guest, an unpromoted account -- the same
  // states with no retirement to run).
  const controller = profile.accountController ?? session.user.id
  let oldPassphraseRetired: boolean
  let unlockSpaceId: string
  let manageCapability: IZcap | undefined
  let oldLadderSeed: Uint8Array | undefined
  let newLadderSeed: Uint8Array | undefined
  let established:
    | {
        unlockSpaceId: string
        manageCapability?: IZcap
        standingFields: StandingUnlockFields
      }
    | undefined
  if (context) {
    // Verify the old passphrase read-only -- nothing is written on a wrong
    // one -- capturing its record's ladder seed, so the retirement below
    // holds every rung a priori rather than walking from the recorded one.
    ;({ ladderSeed: oldLadderSeed } = await verifyPassphrase({
      controller,
      passphrase: oldPassphrase,
      credential: oldCredential
    }))
    // The establishment, first and fatal (roster wrap, commitment document
    // entry, bridge delegation, standing-layout record at the new unlock
    // Space): a failure leaves the old credential fully intact -- record,
    // Space, standing configuration -- so the thrown "not changed" is true,
    // and a retry with the same new passphrase converges on the
    // establishment's idempotent stages.
    let outcome: Awaited<ReturnType<typeof establishStandingUnlock>>
    try {
      outcome = await establishStandingUnlock({
        session,
        secret: newPassphrase,
        kdf: KEYRING_KDF,
        lowEntropy: true,
        email: session.user.email,
        credential: newCredential
      })
    } catch (err) {
      log.error(
        'Could not establish the new passphrase as a standing credential; the passphrase was not changed',
        { err }
      )
      throw new Error(
        'The new passphrase could not be established as a standing ' +
          'credential; the passphrase was not changed.',
        { cause: err }
      )
    }
    // Swap the live profile onto the new unlock identity: later re-wraps
    // (rolled update-key seeds, a rotated user key) must hit the new
    // standing-layout record, and the registry backfill must never repoint
    // the passphrase entry at the unlock Space deleted below.
    adoptPassphraseRebind({
      session,
      unlockSpaceId: outcome.unlockSpaceId,
      manageCapability: outcome.manageCapability,
      persistClientKeys: outcome.persistClientKeys
    })
    newLadderSeed = outcome.ladderSeed
    unlockSpaceId = outcome.unlockSpaceId
    manageCapability = outcome.manageCapability
    established = {
      unlockSpaceId: outcome.unlockSpaceId,
      ...(outcome.manageCapability
        ? { manageCapability: outcome.manageCapability }
        : {}),
      standingFields: outcome.standingFields
    }
    // The old unlock identity's teardown: its Space (best-effort -- a failed
    // delete leaves the old record able to locate the account only until
    // the retirement below strips its standing) and its local state. A
    // change torn between the establishment and here leaves BOTH
    // passphrases live; the next new-passphrase login's torn-retirement
    // repair, or a retry of this change, retires the old one.
    const deleted = await deleteKeyring({
      passphrase: oldPassphrase,
      credential: oldCredential
    })
    oldPassphraseRetired = deleted.unlockSpaceDeleted
  } else {
    const rebound = await changePassphrase({
      clientSeed,
      controller,
      oldPassphrase,
      newPassphrase,
      userKey: profile.userKey,
      webvhUpdateKeys: profile.clientWebvhKeys,
      newCredential,
      oldCredential
    })
    // The rebind retired the unlock identity this session logged in under:
    // swap the live profile onto the new one, so later re-wraps hit the new
    // client-key record.
    adoptPassphraseRebind({
      session,
      unlockSpaceId: rebound.unlockSpaceId,
      manageCapability: rebound.manageCapability,
      persistClientKeys: rebound.persistClientKeys
    })
    oldPassphraseRetired = rebound.oldPassphraseRetired
    unlockSpaceId = rebound.unlockSpaceId
    manageCapability = rebound.manageCapability
    oldLadderSeed = rebound.oldLadderSeed
  }
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
  let rotation: 'rotated' | 'skipped' | 'failed' | 'unretired' = 'skipped'
  // Whether the retirement's document edit landed. It is proven by the
  // ceremony having reached the stage that fires this, never inferred from
  // the throw.
  let inventoryRemoved = false
  if (bareCredential !== 'absent') {
    // Bare entry, standing (or unverifiable) credential: there is nothing to
    // retire BY, since the retirement names its subject through the entry's
    // members. Reported as `unretired` rather than skipped -- the old
    // passphrase may still unlock the wallet, which is the opposite of what
    // this ceremony promises.
    log.warn(
      'The registry named no inventory for the old passphrase; it was not retired',
      { bareCredential }
    )
    rotation = 'unretired'
  } else {
    try {
      const outcome = await rotateOffUnlockCredential({
        onInventoryRemoved: () => {
          inventoryRemoved = true
        },
        session,
        method: {
          type: 'passphrase',
          ...oldStanding,
          // The old record's ladder seed, captured by the read-only
          // verification before the old unlock Space was deleted: the
          // retirement's ladder attribution then holds every rung a priori
          // rather than walking from the recorded one.
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
        // The retirement re-sealed the registry to the fresh key in band and
        // swapped the session onto it, so this returns on its id guard; it
        // retries the re-seal only when that in-band step failed and left the
        // session on the pre-rotation keys.
        await adoptRotatedUserKey({
          session,
          spaceId: rotationSpaceId({ session }),
          userKey: outcome.userKey
        })
      }
    } catch (err) {
      log.error('Could not retire the old passphrase credential', { err })
      rotation = 'failed'
    }
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
  // Whether this run must mint a registry to write into. Only the rebuilt
  // bare shape below needs one: it is the state whose whole point is
  // leaving something durable that names the old credential.
  let mintRegistry = false
  if (retirementFailedAtTheEdit) {
    standing =
      Object.keys(oldStanding).length > 0 ? { ...oldStanding } : undefined
  } else if (rotation === 'unretired') {
    // The bare entry, filled in from the credential this change holds. The
    // shape is deliberately the failed-at-the-edit one -- the new unlock
    // Space naming the OLD credential's members -- because that is exactly
    // what the next passphrase login's torn-retirement repair detects and
    // retires. Rebuilding it here is what gives the credential left standing
    // a mender, instead of leaving it standing unnamed forever. That repair
    // runs from a login with the NEW passphrase, whose standing-layout
    // record the (fatal) establishment above just wrote.
    standing = await standingFieldsOfCredential({
      credential: oldCredential,
      ladderSeed: oldLadderSeed
    })
    mintRegistry = registryAbsent
  }
  // The standing establishment re-minted the management zcap with PUT (the
  // bind's is the narrow GET/DELETE one); the entry records the wide one, so
  // the revocation cascade can re-PUT this credential's record.
  const registry = await recordPassphraseEntry({
    session,
    unlockSpaceId,
    manageCapability: established?.manageCapability ?? manageCapability,
    standing,
    // A registry that was absent when this change started has no entry for
    // the deferred write to update, so the one state that needs a durable
    // name for the old credential -- the rebuilt bare shape above -- mints
    // the record instead of no-oping. Every other path keeps the absent
    // registry absent (the backfill's business).
    createIfMissing: mintRegistry
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
 * `registryAbsent` reports the third state the fields alone cannot: no
 * registry record at all, as against a record whose passphrase entry is
 * absent or bare. A caller that must leave something naming the old
 * credential has to mint the record in that case, since the deferred write
 * below reads the registry again and would find nothing to update.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<{ fields: StandingUnlockFields, registryAbsent: boolean }>}
 * @throws {Error}   the registry could not be read
 */
async function standingConfiguration({
  session
}: {
  session: Session
}): Promise<{ fields: StandingUnlockFields; registryAbsent: boolean }> {
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
  const registryAbsent = !record
  const entry = record?.methods.find(
    (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
  )
  if (!entry) {
    return { fields: {}, registryAbsent }
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
  return { fields: standingMembers, registryAbsent }
}

/**
 * Whether the typed old credential's `keyAgreement` inventory is still in the
 * account document. Asked only for a BARE registry entry, where the registry
 * itself cannot say whether there is anything to retire.
 *
 * A read that fails resolves to `'unknown'` rather than throwing: the change
 * must not be thrown away over a document fetch, but it must not be reported
 * clean either, so the caller treats unknown exactly like standing.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {EnrolledClientContext}
 * @param options.credential {UnlockCredential}   the typed old passphrase
 * @returns {Promise<'standing' | 'absent' | 'unknown'>}
 */
async function documentStateOfCredential({
  session,
  context,
  credential
}: {
  session: Session
  context: EnrolledClientContext
  credential: UnlockCredential
}): Promise<'standing' | 'absent' | 'unknown'> {
  const keyAgreementKeyMultibase = credential.standing.keyAgreementKeyMultibase
  if (!keyAgreementKeyMultibase) {
    return 'absent'
  }
  try {
    const { doc } = await verifiedAccountLog({
      profile: session.profile,
      pointer: context.pointer
    })
    const listed = await documentListsCredential({
      doc,
      did: context.pointer.did,
      keyAgreementKeyMultibase
    })
    return listed ? 'standing' : 'absent'
  } catch (err) {
    log.warn(
      'Could not check the account document for the old passphrase; treating it as still standing',
      { err }
    )
    return 'unknown'
  }
}

/**
 * The standing fields of a credential held in hand, for the registry entry a
 * bare-entry change leaves behind: the roster kid, the `keyAgreement`
 * multibase, and the client did all come from the credential's own
 * derivation, and `updateKeyMultibase` is ladder rung 0 of the seed the
 * rebind captured.
 *
 * Without that seed the entry cannot record an update key, and the
 * torn-retirement repair skips an entry missing one -- so the absence is
 * logged where it happens.
 *
 * @param options {object}
 * @param options.credential {UnlockCredential}
 * @param [options.ladderSeed] {Uint8Array}   the old record's ladder seed
 * @returns {Promise<StandingUnlockFields>}
 */
async function standingFieldsOfCredential({
  credential,
  ladderSeed
}: {
  credential: UnlockCredential
  ladderSeed?: Uint8Array
}): Promise<StandingUnlockFields> {
  const rung0 = ladderSeed
    ? await ladderRung({ ladderSeed, index: 0 })
    : undefined
  if (!rung0) {
    log.warn(
      "The old passphrase's ladder seed is not in hand, so its registry entry records no update key and the login-time repair will not retire it"
    )
  }
  const { recipientKid, keyAgreementKeyMultibase, clientDid } =
    credential.standing
  return {
    ...(recipientKid ? { rosterKid: recipientKid } : {}),
    ...(keyAgreementKeyMultibase ? { keyAgreementKeyMultibase } : {}),
    ...(clientDid ? { unlockClientDid: clientDid } : {}),
    ...(rung0 ? { updateKeyMultibase: rung0.keyMultibase } : {}),
    ...unlockKeyAgreementMembers({ unlock: credential.unlock })
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
 * @param [options.createIfMissing] {boolean}   mint a fresh registry when
 *   none has been written yet, instead of resolving null; default false
 * @returns {Promise<UnlockMethodsRecord | null>}   the updated registry, or
 *   null when there was nothing to update (or the update failed)
 */
async function recordPassphraseEntry({
  session,
  unlockSpaceId,
  manageCapability,
  standing,
  createIfMissing = false
}: {
  session: Session
  unlockSpaceId: string
  manageCapability?: IZcap
  standing?: StandingUnlockFields
  createIfMissing?: boolean
}): Promise<UnlockMethodsRecord | null> {
  try {
    return await updateUnlockMethods({
      session,
      mutate: current => {
        const base =
          current ?? (createIfMissing ? emptyUnlockMethodsRegistry() : null)
        if (!base) {
          return null
        }
        // `manageCapability` is written unconditionally: a change that minted
        // none must clear the one the retired unlock Space's entry carried.
        return upsertPassphraseUnlockMethod({
          record: base,
          unlockSpaceId,
          manageCapability,
          keepAbsentManageCapability: true,
          ...(standing ? { standing } : {})
        })
      }
    })
  } catch (err) {
    log.warn('Could not update the passphrase unlock-method entry', { err })
    return null
  }
}

/**
 * Thrown when a freshly registered passkey could not be made a standing
 * credential (and so was not connected to the account). The
 * authenticator-side credential cannot be removed (WebAuthn has no delete
 * API): it stays a resident credential registered under the account's user
 * handle, and a retry registers a second one -- the Settings failure copy
 * states that residue.
 */
export class PasskeyNotEstablishedError extends Error {
  constructor(options?: { cause?: unknown }) {
    super(
      'The passkey could not be connected to this account. It was still ' +
        "created on this device's authenticator and cannot be removed from " +
        'it by the wallet; retrying will create a second one there.',
      options
    )
    this.name = 'PasskeyNotEstablishedError'
  }
}

/**
 * Runs the add-a-passkey ceremony: registers the passkey, writes a BARE
 * registry entry, establishes the passkey as a standing credential, and
 * completes the entry with the standing members. There is no plain bind: a
 * failed establishment fails the ceremony (the no-plain-bind-fallback rule).
 *
 * The order, entry-first with completion after:
 *
 * 1. The registry is read FRESH before the WebAuthn ceremony. The
 *    wallet-wide user handle and the exclude list of authenticators already
 *    holding a passkey come from the stored record (a fresh 16-byte handle
 *    is minted when none exists yet), and a read that fails refuses the
 *    ceremony while nothing exists on the authenticator.
 * 2. The BARE entry -- identity-free members only: type, label, creation
 *    date, credential id, transports, backup flags, and the unlock Space id
 *    -- is written before the establishment starts, durably persisting the
 *    handle the passkey registered under. A torn establishment then leaves
 *    exactly the present-but-bare shape `rebuildBarePasskeyEntry` mends;
 *    writing the entry only afterwards would leave a credential the
 *    registry never names, a state with no mender that blocks the
 *    last-client transition and hides the unlock Space from account
 *    deletion's registry walk. No key-agreement member and no standing
 *    field rides the bare write: an early one would be a third partial
 *    shape no existing repair mends.
 * 3. The establishment (`establishStandingUnlock`) runs as the ceremony's
 *    body: roster wrap, verbatim document entry (the PRF output is
 *    high-entropy), bridge delegation, standing-layout record. Its failure
 *    fails `addAccountPasskey` (`PasskeyNotEstablishedError`), after the
 *    verify-then-act cleanup below.
 * 4. On success the same entry is completed in place -- the key-agreement
 *    multibase, the standing fields, and the establishment's wide
 *    management zcap -- and the passkey-safety notice is cleared once the
 *    account positively has a second unlock method. A completion write that
 *    fails reports `recorded: false`; the bare shape it leaves is the one
 *    this passkey's next login rebuilds.
 *
 * The cleanup is verify-then-act (see
 * `recoverFailedPasskeyEstablishment`): re-fetch the record first, treat a
 * standing record as a lost-response success, delete the unlock Space only
 * when nothing was published, and clean a partial establishment by an
 * actual retirement rather than by deleting the record.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.locale {string}   active i18n language code
 * @param options.userName {string}   WebAuthn user name for the ceremony
 * @param options.promptForPrfRetry {function}   resolves the user's choice
 *   when the authenticator needs a second (assertion) ceremony for the PRF
 * @returns {Promise<{ record: UnlockMethodsRecord, recorded: boolean }>}
 * @throws {PasskeyNotEstablishedError}   the passkey could not be made a
 *   standing credential; it is not connected to the account
 */
export async function addAccountPasskey({
  session,
  locale,
  userName,
  promptForPrfRetry
}: {
  session: Session
  locale: string
  userName: string
  promptForPrfRetry: () => Promise<boolean>
}): Promise<{ record: UnlockMethodsRecord; recorded: boolean }> {
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Adding a passkey'
  })
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes; on a settled session the chain resolved long ago.
  await session.registryReady
  const profile = session.profile
  const clientSeed = profile.clientSeed
  if (!clientSeed) {
    throw new Error('Adding a passkey needs this client key set.')
  }
  // 1. The fresh registry read, before anything touches the authenticator: a
  // refused read fails here, with no residue anywhere.
  const base =
    (await getUnlockMethods({ session })) ?? emptyUnlockMethodsRegistry()
  const excludeCredentialIds = base.methods
    .filter(
      (method): method is PasskeyUnlockMethod => method.type === 'passkey'
    )
    .map(method => base64urlnopad.decode(method.credentialId))
  const registration = await registerPasskey({
    userHandle: base64urlnopad.decode(base.webAuthnUserId),
    userName,
    excludeCredentialIds,
    promptForPrfRetry
  })
  // One KDF run per typed secret: the derived credential locates the unlock
  // Space here and drives the cleanup on a failure.
  const credential = await deriveUnlockCredential({
    secret: registration.prfOutput,
    kdf: PASSKEY_KDF
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
    unlockSpaceId: credential.unlock.spaceId
  }
  // 2. The bare entry-first write, merged into a fresh read (a concurrent
  // write must survive); the registry is minted with the handle the passkey
  // just registered under when none has been written yet.
  try {
    await updateUnlockMethods({
      session,
      mutate: fresh =>
        upsertPasskeyUnlockMethod({ record: fresh ?? base, entry })
    })
  } catch (err) {
    throw new PasskeyNotEstablishedError({ cause: err })
  }
  // 3. The establishment. The ladder seed is minted HERE so a failure
  // cleanup still holds rung 0 and the attribution seed an actual
  // retirement needs, even when the ceremony threw before returning them.
  const ladderSeed = generateLadderSeed()
  let established: Awaited<ReturnType<typeof establishStandingUnlock>>
  try {
    established = await establishStandingUnlock({
      session,
      secret: registration.prfOutput,
      kdf: PASSKEY_KDF,
      lowEntropy: false,
      email: session.user.email,
      credential,
      ladderSeed
    })
  } catch (err) {
    log.error('Could not establish the new passkey as a standing credential', {
      err
    })
    const recovered = await recoverFailedPasskeyEstablishment({
      session,
      secret: registration.prfOutput,
      credential,
      ladderSeed,
      entry,
      base
    })
    if (recovered) {
      return recovered
    }
    throw new PasskeyNotEstablishedError({ cause: err })
  }
  // 4. The completion write.
  return await completePasskeyEntry({
    session,
    base,
    entry: {
      ...entry,
      ...(established.manageCapability
        ? { manageCapability: established.manageCapability }
        : {}),
      ...established.standingFields
    }
  })
}

/**
 * The add-a-passkey completion write: merges the completed entry into a
 * FRESH registry read (anything written since the ceremony's own read --
 * another tab, another client, a login-time refresh -- must survive), then
 * clears the passkey-only safety notice once the account positively has a
 * second unlock method. A fresh read that comes back empty falls back to
 * the ceremony's base, so the handle the passkey registered under is the
 * one persisted; a fresh read carrying a different handle wins anyway (the
 * stored record is the source of truth).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.base {UnlockMethodsRecord}   the ceremony's registry base
 * @param options.entry {PasskeyUnlockMethod}   the completed entry
 * @returns {Promise<{ record: UnlockMethodsRecord, recorded: boolean }>}
 */
async function completePasskeyEntry({
  session,
  base,
  entry
}: {
  session: Session
  base: UnlockMethodsRecord
  entry: PasskeyUnlockMethod
}): Promise<{ record: UnlockMethodsRecord; recorded: boolean }> {
  let record: UnlockMethodsRecord = upsertPasskeyUnlockMethod({
    record: base,
    entry
  })
  try {
    record =
      (await updateUnlockMethods({
        session,
        mutate: fresh =>
          upsertPasskeyUnlockMethod({ record: fresh ?? base, entry })
      })) ?? record
  } catch (err) {
    // The passkey is standing and will log in; only the entry's completion
    // failed to persist. The registry still holds the bare shape from the
    // entry-first write, which this passkey's next login rebuilds.
    log.error('Could not record the new passkey in the registry', { err })
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
      log.warn('Could not clear the passkey-safety notice', { err })
    }
  }
  return { record, recorded: true }
}

/**
 * The verify-then-act cleanup behind a failed passkey establishment.
 *
 * Verify first: the record at the credential's unlock Space is re-fetched,
 * because the failure can be a lost response to the establishment's final
 * record PUT with the credential fully standing server-side -- deleting on
 * the error alone would destroy a succeeded credential. A standing record
 * is treated as SUCCESS: the entry is completed from the hit and the
 * ceremony returns normally (the non-null return).
 *
 * Otherwise, act by what was published. When nothing was (no document
 * `keyAgreement` entry, no roster wrap, and the record absent or plain),
 * the unlock Space and its local state are deleted and the bare registry
 * entry dropped: the credential then never exists -- the simplest mendable
 * state. When something WAS published (or that could not be told), the
 * cleanup is an ACTUAL retirement (`rotateOffUnlockCredential` with the
 * ceremony-minted ladder seed -- the tapped-removal pattern minus the tap,
 * since the PRF output's credential is in hand), never a record delete:
 * the record is the retirement's anchor. Only after the retirement do the
 * unlock Space and the bare entry go. A retirement, re-fetch, or delete
 * that itself fails leaves the bare entry and the record standing as
 * mendable residue, and the surrounding ceremony still fails.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.secret {Uint8Array}   the passkey's PRF output
 * @param options.credential {UnlockCredential}   its derived credential
 * @param options.ladderSeed {Uint8Array}   the ceremony-minted ladder seed
 * @param options.entry {PasskeyUnlockMethod}   the bare entry as written
 * @param options.base {UnlockMethodsRecord}   the ceremony's registry base
 * @returns {Promise<{ record: UnlockMethodsRecord, recorded: boolean } | null>}
 *   the ceremony outcome when the re-fetch proved the establishment
 *   succeeded, else null (the caller fails the ceremony)
 */
async function recoverFailedPasskeyEstablishment({
  session,
  secret,
  credential,
  ladderSeed,
  entry,
  base
}: {
  session: Session
  secret: Uint8Array
  credential: UnlockCredential
  ladderSeed: Uint8Array
  entry: PasskeyUnlockMethod
  base: UnlockMethodsRecord
}): Promise<{ record: UnlockMethodsRecord; recorded: boolean } | null> {
  let found: KeyringFetchResult | null
  try {
    found = await fetchKeyring({
      secret,
      kdf: PASSKEY_KDF,
      credential,
      mintManageCapability: true
    })
  } catch (err) {
    // Cannot verify, so nothing is acted on: the bare entry and whatever the
    // establishment left stand as mendable residue.
    log.warn(
      'Could not re-fetch the passkey unlock record after the failed establishment; leaving the residue for the standing menders',
      { err }
    )
    return null
  }
  if (found?.standing?.ladderSeed) {
    // The lost-response case: the record is standing, so the establishment
    // succeeded server-side after all. Complete the entry from the hit.
    log.warn(
      'The passkey unlock record is standing after all; completing the registry entry'
    )
    const standing = await standingFieldsOfKeyringHit({ found })
    return await completePasskeyEntry({
      session,
      base,
      entry: {
        ...entry,
        ...(found.manageCapability
          ? { manageCapability: found.manageCapability }
          : {}),
        ...standing
      }
    })
  }
  try {
    if (await passkeyEstablishmentPublished({ session, credential })) {
      // The retirement: document inventory out (where the entry landed), the
      // user key rotated off the roster wrap (where one landed), every
      // encrypted collection re-epoch'd. Its stages no-op over anything the
      // establishment never reached.
      const rung0 = await ladderRung({ ladderSeed, index: 0 })
      const rotation = await rotateOffUnlockCredential({
        session,
        method: {
          type: 'passkey',
          keyAgreementKeyMultibase:
            credential.standing.keyAgreementKeyMultibase,
          updateKeyMultibase: rung0.keyMultibase,
          ladderSeed
        },
        verb: 'cleaning up a failed passkey addition'
      })
      if (rotation?.rotated && rotation.userKey) {
        await adoptRotatedUserKey({
          session,
          spaceId: rotationSpaceId({ session }),
          userKey: rotation.userKey
        })
      }
    }
  } catch (err) {
    // The retirement tore: the bare entry and the record stay standing --
    // the state the standing menders already own.
    log.error(
      'Could not retire the partially established passkey credential; its bare entry and record are left for the standing menders',
      { err }
    )
    return null
  }
  // Nothing published (or the retirement swept it): the unlock Space, the
  // local state, and the bare entry go, so the credential never exists.
  try {
    await deleteUnlockMethod({ secret, kdf: PASSKEY_KDF, credential })
  } catch (err) {
    log.warn('Could not delete the failed passkey unlock Space', { err })
    return null
  }
  await dropBarePasskeyEntry({ session, credentialId: entry.credentialId })
  return null
}

/**
 * Whether a torn passkey establishment left anything published server-side:
 * the credential's verbatim `keyAgreement` entry in the verified account
 * document, or its wrap in any user-key roster epoch. A check that fails
 * resolves to `true` -- the conservative direction, since the retirement it
 * routes to no-ops over anything never published. A session with no
 * enrolled-client context resolves to `false`: the establishment refused
 * before its first write there.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.credential {UnlockCredential}
 * @returns {Promise<boolean>}
 */
async function passkeyEstablishmentPublished({
  session,
  credential
}: {
  session: Session
  credential: UnlockCredential
}): Promise<boolean> {
  const context = enrolledClientContext({ session })
  if (!context) {
    return false
  }
  try {
    const { doc } = await verifiedAccountLog({
      profile: session.profile,
      pointer: context.pointer
    })
    const listed = await documentListsCredential({
      doc,
      did: context.pointer.did,
      keyAgreementKeyMultibase: credential.standing.keyAgreementKeyMultibase,
      // A passkey's PRF-derived key is high-entropy and publishes verbatim.
      published: 'verbatim'
    })
    if (listed) {
      return true
    }
    const roster = await sessionRosterStore({
      profile: session.profile
    }).read()
    return (roster?.descriptor.epochs ?? []).some(epoch =>
      epoch.recipients.some(
        recipient => recipient.header.kid === credential.standing.recipientKid
      )
    )
  } catch (err) {
    log.warn(
      'Could not check what a failed passkey establishment published; cleaning by retirement',
      { err }
    )
    return true
  }
}

/**
 * Drops the entry-first BARE passkey entry after a cleanup that deleted the
 * credential's unlock Space, matched by its `credentialId`. Best-effort: a
 * leftover bare entry names a Space that no longer exists and is removable
 * from Settings.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.credentialId {string}
 * @returns {Promise<void>}
 */
async function dropBarePasskeyEntry({
  session,
  credentialId
}: {
  session: Session
  credentialId: string
}): Promise<void> {
  try {
    await updateUnlockMethods({
      session,
      mutate: current => {
        if (!current) {
          return null
        }
        const methods = current.methods.filter(
          method =>
            !(method.type === 'passkey' && method.credentialId === credentialId)
        )
        return methods.length === current.methods.length
          ? null
          : { ...current, methods }
      }
    })
  } catch (err) {
    log.warn('Could not drop the bare passkey entry after the cleanup', { err })
  }
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
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes; on a settled session the chain resolved long ago.
  await session.registryReady
  const record = await updateUnlockMethods({
    session,
    mutate: current => {
      if (!current) {
        throw new Error(
          'There is no unlock-methods registry to rename a passkey in.'
        )
      }
      const listed = current.methods.some(
        method =>
          method.type === 'passkey' &&
          method.credentialId === entry.credentialId
      )
      if (!listed) {
        return null
      }
      return {
        ...current,
        methods: current.methods.map(method =>
          method.type === 'passkey' &&
          method.credentialId === entry.credentialId
            ? { ...method, label }
            : method
        )
      }
    }
  })
  return record!
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
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes; on a settled session the chain resolved long ago.
  await session.registryReady
  const verb = 'removing a passkey'
  const outcome = canRevokeWithoutCeremony(entry)
    ? await revokeUnlockMethod({ session, entry, verb })
    : await revokeUnlockMethodByCeremony({ session, entry, verb })
  // The retirement adopted the fresh key in band -- re-sealing the registry
  // to it before the teardown above, which therefore ran under the same keys
  // as the record. This call returns on its id guard when that landed, and
  // retries the re-seal (then swaps) when it did not, which is the one case
  // that leaves the session on the pre-rotation keys. Internally
  // best-effort.
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
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes; on a settled session the chain resolved long ago.
  await session.registryReady
  // The bind runs as the full standing-configuration ceremony (roster wrap,
  // commitment document entry, bridge delegation, standing-layout record)
  // under the ACCOUNT controller, with management delegated to the account
  // identity so any enrolled client can later revoke this method. A failure
  // fails the ceremony: a plain pointer bind would leave a passphrase with
  // no roster wrap and no self-enrollment authority, which nothing but a
  // fresh browser's refused login would ever surface.
  const { unlockSpaceId, manageCapability, standingFields } =
    await establishStandingUnlock({
      session,
      secret: passphrase,
      kdf: KEYRING_KDF,
      lowEntropy: true,
      email: session.user.email
    })
  // The merge base is a fresh read, never the page-held record: a concurrent
  // write must not be reverted here. The upsert also makes a second run of
  // this ceremony replace the single passphrase entry instead of appending a
  // duplicate one naming a different credential.
  const record = (await updateUnlockMethods({
    session,
    mutate: current =>
      upsertPassphraseUnlockMethod({
        record: current ?? emptyUnlockMethodsRegistry(),
        unlockSpaceId,
        manageCapability,
        standing: standingFields
      })
  }))!
  // The account now has a passphrase backup, so the passkey-only safety
  // prompt is resolved. Best-effort.
  try {
    await session.profile.persistence.passkeyNotices.delete({
      controller: session.user.id
    })
  } catch (err) {
    log.warn('Could not clear the passkey-safety notice', { err })
  }
  return record
}

/**
 * Rotates this client's did:webvh update key (per-client self-rotation).
 *
 * Ordering: every changed seed set is persisted into the wrapped client-key
 * record (and the in-memory profile) before and after the log extends, so a
 * crash mid-rotation resumes from stored state -- the browser-local record
 * beside the published log.
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
  // The subject of this ceremony is this browser's own state: it rotates THIS
  // browser's did:webvh update key, and its persist-before-publish ordering
  // needs a browser-local client-key record to persist the rolled seeds into.
  // So it asserts the browser-local strategy outright. The other
  // account-management ceremonies here are reachable from a transient
  // session, but only inside a step-up, so they carry the step-up gate
  // instead.
  assertBrowserLocalSession({
    persistence: session.profile.persistence,
    ceremony: 'Update-key rotation'
  })
  // Not a registry writer, but a client-key-record writer: the rotation's
  // `persistClientKeys({ webvhUpdateKeys })` load-merge-saves the same
  // record the chain's head stage writes (the sweep's user-key adoption
  // persist), and an interleaved save can strand `webvhUpdateKeys` behind
  // the published log entry -- an unmendable state. Wait out the chain; on
  // a settled session it resolved long ago.
  await session.registryReady
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
 * `delegatedClients` delegations -- plus each method's local state,
 * best-effort per entry: this is what removes the dangling existence-oracle
 * Spaces a probe could still find after the account is gone (an entry
 * recording no management capability keeps its Space, stated residue);
 * (b1) tear down the auxiliary annex Space beside the account Space --
 * one recursive Space delete, run BEFORE the data-Space wipe because the
 * server resolves the auxiliary Space's did:webvh controller by reading the
 * account log out of the account Space; warn-only, and a failure leaves an
 * orphan the server can identify by its `DelegatedClientsSpace` type;
 * (b) wipe the remote data Space -- on failure the caller keeps the old
 * semantics: surface the error, do NOT log out, the data is still there;
 * (c) retire the passphrase keyring only after a successful wipe -- if the
 * keyring died first and the wipe then failed, the data Space would be
 * orphaned unrecoverably; non-fatal, since the data is already gone;
 * (w) run the shared wipe enumeration (`src/session/wipe.ts`) over the
 * targets snapshotted at (a2): every unlock method's local state, the
 * Space-keyed bookkeeping, the unlock-methods cache, the replica databases,
 * and the per-account localStorage families -- a surviving replica is the one fatal stage, and
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
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes (deletion walks the registry); on a settled session
  // the chain resolved long ago, and a guest session carries no chain.
  await session.registryReady
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
      log.error('Could not verify the passphrase for deletion', { err })
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
  const idb = isBrowserLocalSession(session.profile.persistence)
    ? session.profile.persistence.idb
    : undefined
  if (!isGuest) {
    try {
      registry = await getUnlockMethods({ session })
    } catch (err) {
      registryUnread = true
      log.warn(
        "Could not read the unlock-methods registry for deletion; other methods' unlock Spaces survive",
        { err }
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
      log.warn('Could not locate the auxiliary annex Space for deletion', {
        err
      })
    }

    // (b0) The registry walk: every unlock method's unlock Space (holding
    // its record with the sealed bridge and sibling delegations) and local
    // state, best-effort per entry. Run before the data-Space wipe only for
    // ordering hygiene -- each delete rides the entry's own management zcap,
    // whose unlock Space is its own root.
    for (const entry of registry?.methods ?? []) {
      try {
        await deleteUnlockMethodArtifacts({ session, entry, idb })
      } catch (err) {
        log.warn("Could not delete an unlock method's artifacts", {
          methodType: entry.type,
          err
        })
      }
    }

    // (b1) The auxiliary annex Space, before the account Space: its
    // controller is the account did:webvh, which the server resolves by
    // reading the account log out of the account Space -- once that is
    // wiped, no authority can reach the auxiliary Space again. One recursive
    // delete covers the generation collections and the embedded delegations.
    if (clientAnnex) {
      try {
        await clientAnnex.was.space(clientAnnex.spaceId).delete()
      } catch (err) {
        log.warn(
          'Could not tear down the auxiliary annex Space; it survives as a typed orphan',
          { err }
        )
      }
    }
  }
  // The wipe targets, snapshotted from the session and the discovery above
  // before any local state is deleted.
  const targets = snapshotWipeTargets({
    session,
    registry,
    registryUnread
  })
  // (b) Wipe the remote data Space. On failure keep the old semantics:
  // surface the error, do not log out (the data is still there).
  try {
    log.info('Wiping remote user data')
    await session.storage?.wipeRemoteStorage()
  } catch (err) {
    log.error('Error wiping user data', { err })
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
        log.warn('Could not delete the unlock Space during account deletion')
      }
    } catch (err) {
      log.warn('Could not retire the passphrase keyring', { err })
    }
  }
  // The local half: the shared wipe enumeration, for guests and full
  // accounts alike -- every unlock method's local state, the Space-keyed
  // bookkeeping, the caches, the replica databases, and the per-account
  // localStorage families. A surviving replica keeps the
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
