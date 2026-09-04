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
import type { ZcapClient } from '@interop/ezcap'
import { WasClient } from '@interop/was-client'
import type { DIDLog } from '@interop/did-method-webvh'
import {
  accountLogPinId,
  clientKeyAgreementController,
  didKeyZcapClient,
  isWebvhDid,
  ladderVmIds,
  relationIds,
  rotateWebvhUpdateKey
} from '@interop/wallet-core/webvh'
import {
  DELETION_ZCAP_TTL_MS,
  delegatedClientsDelegationSpaceId,
  delegatedClientsSpaceHistory,
  deleteSpaceWithCapability,
  generateLadderSeed,
  ladderRung,
  ladderVmAgent,
  ladderVmKeyMultibase,
  ladderVmZcapClient,
  mintSpaceRootVerbCapability,
  mintSpaceVerbCapability
} from '@interop/wallet-core/clientAnnex'
import { readUserKeyRoster } from '@interop/wallet-core/keys'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import { resourcePath, spacePath, toUrl } from '@interop/was-client/paths'
import {
  DATE_FMT,
  DID_LOG_RESOURCE,
  ID_COLLECTION,
  PASSKEY_KDF,
  WAS_SERVER_URL
} from '@/app.config'
import { assertPasskeyPrf, registerPasskey } from '@/lib/passkey'
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
  verifyUnlockSecret,
  WrongPassphraseError,
  type KeyringFetchResult,
  type UnlockCredential
} from '@/session/keyring'
import {
  adoptPassphraseRebind,
  emptyUnlockMethodsRegistry,
  backfillPassphraseUnlockMethod,
  canRevokeWithoutCeremony,
  deleteUnlockMethodSpace,
  getUnlockMethods,
  managementZcapClient,
  revokeUnlockMethod,
  UnlockRegistryStaleSealError,
  unlockSpaceDeletionRefusal,
  updateUnlockMethods,
  revokeUnlockMethodByCeremony,
  upsertPasskeyUnlockMethod,
  upsertPassphraseUnlockMethod,
  type PassphraseUnlockMethod,
  type PasskeyUnlockMethod,
  type UnlockMethod,
  type UnlockMethodsRecord,
  type UnlockSpaceDeletionOutcome
} from '@/session/unlockMethods'
import { sessionRosterStore } from '@/session/rosterStore'
import {
  assertAccountCeremonyAllowed,
  assertBrowserLocalSession,
  isBrowserLocalSession
} from '@/session/persistence'
import { renewTransientGenerationDelegation } from '@/session/annexReach'
import {
  findPendingPassphraseEntries,
  findUnrecordedCredentials
} from '@/session/credentialCoverage'
import { resealRegistryFromEscrow } from '@/session/registryReseal'
import { deleteUnlockLocalState } from '@/lib/sessionKey'
import { syncController } from '@/stores/syncController'
import {
  enrolledClientContext,
  type EnrolledClientContext
} from '@/session/enrolledContext'
import { documentListsCredential } from '@/session/pendingRetirement'
import { executeLocalWipe, snapshotWipeTargets } from '@/session/wipe'
import {
  isUnclaimedLadderVmRefusal,
  preflightCredentialRetirement,
  rotateOffUnlockCredential
} from '@/session/credentialRotation'
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
 * Loads the unlock-methods registry for the Settings passkeys section. Read
 * and write split by the session's persistence strategy.
 *
 * A browser-local session lazily creates/repairs the passphrase entry (the
 * registry's backfill point). A backfill failure falls back to a plain read;
 * a read failure propagates, so the caller can show a non-blocking load error
 * while the rest of the section keeps working.
 *
 * A transient session performs the plain READ alone, riding the visit's
 * generation delegation (`profile.invocationCapability`) since its
 * annex-signed root invocation would be refused under the current-key-set
 * rule. It never reaches the backfill: minting or rewriting a registry stays
 * browser-local-only. With no WAS server there is no capability and no remote
 * record, and the read serves the local cache.
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
  const { invocationCapability } = session.profile
  if (!isBrowserLocalSession(session.profile.persistence)) {
    return await getUnlockMethods({
      session,
      ...(invocationCapability ? { capability: invocationCapability } : {})
    })
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
 * @throws {UnclaimedLadderVmRetirementError}   the old credential's ladder VM
 *   cannot be claimed, so retiring it would leave it standing. Raised by the
 *   read-only pre-flight before anything is written; the same refusal from
 *   the retirement itself propagates rather than writing a pending entry
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
    // The retirement gate, read-only and before the establishment below. A
    // retirement that cannot claim the old credential's ladder VM refuses,
    // and refusing here is what keeps that refusal from landing after the
    // change has already established the new credential and torn the old
    // unlock Space down -- a state whose only registry record would be the
    // pending-shaped entry naming a credential that is still standing, which
    // no seedless repair can clear. The seed the verification just captured
    // is what the attribution needs, so the pre-flight is as strong as the
    // retirement it stands in for.
    await preflightCredentialRetirement({
      session,
      method: {
        type: 'passphrase',
        ...oldStanding,
        ...(oldLadderSeed ? { ladderSeed: oldLadderSeed } : {})
      }
    })
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
      if (isUnclaimedLadderVmRefusal(err)) {
        // The gate, firing where the pre-flight above already ran: a log
        // entry landed between the two reads. It propagates rather than
        // reporting `failed`, because `failed` writes the pending-shaped
        // entry naming the OLD credential, and that entry is exactly what
        // locks the passphrase change, the last-client transition, and the
        // torn-retirement repair for good.
        throw err
      }
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
    if (isUnclaimedLadderVmRefusal(err)) {
      // The gate, named rather than reported as a transport tear: the
      // retirement published nothing, and the credential keeps a ladder VM
      // that no seedless retry can claim. The residue is the same either
      // way -- the bare entry and the record stand -- but only this arm says
      // that a retry cannot mend it on its own.
      log.error(
        'Could not retire the partially established passkey credential: its ladder VM could not be claimed, so the retirement refused before publishing anything',
        {
          err,
          unclaimedLadderVmIds: (err as { unclaimedLadderVmIds?: string[] })
            .unclaimedLadderVmIds,
          retryableWithLadderSeed: (
            err as { retryableWithLadderSeed?: boolean }
          ).retryableWithLadderSeed
        }
      )
      return null
    }
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
 * How an account-deletion attempt ended.
 *
 * - `wrong-passphrase` -- the confirm did not authenticate; nothing was
 *   touched.
 * - `refused` -- a pre-flight refused before the first irreversible write,
 *   with nothing deleted. The reason rides on the outcome and carries its own
 *   copy key.
 * - `failed` -- a phase before the pivot failed. The account is still there,
 *   the caller stays put, and a retry re-runs the walk. A guest and a no-WAS
 *   run, which have no pivot, also report a surviving local replica this
 *   way: there the replica IS the account.
 * - `deleted` -- the account Space is gone and the caller should clear the
 *   session and leave the app.
 * - `deleted-unverified` -- the account is gone, but this browser's local
 *   replica did not verifiably go with it: either the delete failed, or it
 *   ran and could not be CONFIRMED (the engine cannot enumerate its
 *   databases). Past the pivot this REPLACES `failed`, which would tell the
 *   user their account survived.
 */
export type AccountDeletionResult =
  'wrong-passphrase' | 'refused' | 'failed' | 'deleted' | 'deleted-unverified'

/**
 * Why a pre-flight refused the whole ceremony, with nothing deleted. Each
 * reason renders its own copy ({@link accountDeletionRefusalKey}).
 */
export type AccountDeletionRefusalReason =
  | 'ladder-vm-not-anchored'
  | 'registry-unreadable'
  | 'registry-stale-seal'
  | 'discovery-failed'
  | 'space-delete-failed'

/**
 * The Settings copy key for a pre-flight refusal, in the tone
 * `transientRefusalKey` sets for the transient session's own refusals.
 *
 * @param reason {AccountDeletionRefusalReason}
 * @returns {string}
 */
export function accountDeletionRefusalKey(
  reason: AccountDeletionRefusalReason
): string {
  switch (reason) {
    // The account document anchors no ladder VM of this credential, so no
    // DELETE this walk mints would verify anywhere. A remembered browser is
    // the way through until the credential-keyed ladder VM lands.
    case 'ladder-vm-not-anchored':
      return 'settings.deleteRefusal.ladderVmNotAnchored'
    case 'registry-unreadable':
      return 'settings.deleteRefusal.registryUnreadable'
    case 'registry-stale-seal':
      return 'settings.deleteRefusal.registryStaleSeal'
    case 'discovery-failed':
      return 'settings.deleteRefusal.discoveryFailed'
    case 'space-delete-failed':
    default:
      return 'settings.deleteRefusal.spaceDeleteFailed'
  }
}

/**
 * What became of one Space the walk named.
 *
 * `unconfirmed` is the 404 rule's honest grade: the server masks an
 * authorization refusal as a 404, so a DELETE that 404'd with no independent
 * evidence of absence is not reported as a clean deletion.
 */
export interface SpaceDeletionReport {
  kind: 'annex' | 'unlock' | 'acting-unlock' | 'account'
  spaceId: string
  outcome: 'deleted' | 'unconfirmed' | 'unreachable'
  /** the unlock method the Space belongs to, when it belongs to one */
  method?: string
  /** the method's display label, when it carries one */
  label?: string
  /** why an `unreachable` Space was not deleted */
  reason?: string
}

/**
 * An unlock Space the walk could not NAME: one behind a pending-shaped
 * passphrase entry, or a standing credential the account document publishes
 * that the registry does not record. Reported rather than refused: the
 * account Space's own deletion is the mender, since that credential's next
 * login meets a dead account log and is offered the removal.
 */
export interface UnnamedUnlockSpace {
  reason: 'pending-entry' | 'unrecorded-credential'
  /** the pending entry's method type, where an entry names one */
  method?: string
}

/**
 * The ceremony's progress, for the dialog's keep-this-tab-open copy.
 */
export type AccountDeletionPhase =
  | { phase: 'authenticate' }
  | { phase: 'quiesce' }
  | { phase: 'discover' }
  | { phase: 'annex-space'; spaceId: string }
  | { phase: 'keystore' }
  | { phase: 'unlock-space'; spaceId: string }
  | { phase: 'account-space'; spaceId: string }
  | { phase: 'acting-unlock-space'; spaceId: string }
  | { phase: 'local-wipe' }

/**
 * Everything the run left behind, beside its result.
 */
export interface AccountDeletionOutcome {
  result: AccountDeletionResult
  /** set when `result` is `refused` */
  refusal?: AccountDeletionRefusalReason
  /** one entry per Space the walk named */
  spaces: SpaceDeletionReport[]
  /** unlock Spaces the walk could not name */
  unnamed: UnnamedUnlockSpace[]
  /**
   * The KMS keystore stage. Shipped skipped and reported: a keystore's
   * server-side deletion route is its own item, and an orphaned keystore is a
   * stated per-account residue until it lands.
   */
  keystore: 'skipped'
}

/**
 * The single-verb capability mints the walk needs, plus the identity that
 * invokes them. A remembered session holds none of this: it root-invokes.
 */
interface LadderDeleter {
  /** the delegating signer: the ladder VM under `<accountDid>#<multibase>` */
  zcapClient: ZcapClient
  /** the delegatee and invoker: the ladder VM's own bare did:key */
  invoker: ZcapClient
  /** the delegatee DID */
  controller: string
}

/**
 * Probes one Space for existence, so the 404 rule has a basis. A Space
 * Description read comes back `null` for a 404 (absent OR unauthorized, the
 * server masks the two), and every other failure propagates: a transport or
 * 5xx failure must refuse the run rather than pass as absence.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}
 * @param [options.capability] {IZcap}   a GET capability on the Space's own
 *   URL; the root capability is invoked otherwise
 * @returns {Promise<'present' | 'absent'>}
 */
async function probeSpace({
  zcapClient,
  spaceId,
  capability
}: {
  zcapClient: ZcapClient
  spaceId: string
  capability?: IZcap
}): Promise<'present' | 'absent'> {
  // Status-exact deliberately, rather than was-client's `Space.describe()`:
  // that read resolves `null` for a 404 AND for a 2xx whose body did not
  // parse (`dataOrNull`), so a live Space could be recorded absent, and an
  // absence recorded here is what lets a later 404 grade as a deletion. Only
  // a 404 is absence; every other failure propagates and refuses the run.
  try {
    await zcapClient.read({
      url: toUrl({
        serverUrl: WAS_SERVER_URL as string,
        path: spacePath(spaceId)
      }),
      ...(capability ? { capability } : {})
    })
  } catch (err) {
    if (httpStatusOf(err) === 404) {
      return 'absent'
    }
    throw err
  }
  return 'present'
}

/**
 * The HTTP status a thrown request error carries, or `undefined` when it
 * carries none (a transport failure). Mirrors was-client's own `httpStatus`,
 * which its export map does not reach.
 *
 * @param err {unknown}
 * @returns {number | undefined}
 */
function httpStatusOf(err: unknown): number | undefined {
  const raw = err as { status?: number; response?: { status?: number } }
  return raw?.status ?? raw?.response?.status
}

/**
 * Whether the account Space's world-readable DID log still answers.
 *
 * This is the 404 rule's one INDEPENDENT absence probe: `did.jsonl` is served
 * to anyone, so no capability gates it and its answer cannot be a masked
 * authorization refusal. While it answers, the account Space is alive and a
 * 404 on a DELETE reads as a refusal; once it stops, the Space is genuinely
 * gone.
 *
 * A fetch that fails for any other reason reports the log as still answering:
 * the walk must never read an unreachable host as corroborated absence.
 *
 * @param options {object}
 * @param options.pointer {object}
 * @param options.pointer.spaceId {string}
 * @param options.pointer.host {string}
 * @returns {Promise<boolean>}
 */
async function accountLogAnswers({
  pointer
}: {
  pointer: { spaceId: string; host: string }
}): Promise<boolean> {
  const url = toUrl({
    serverUrl: pointer.host,
    path: resourcePath(pointer.spaceId, ID_COLLECTION.id, DID_LOG_RESOURCE)
  })
  try {
    const response = await fetch(url)
    return response.status !== 404
  } catch (err) {
    log.warn(
      'Could not re-read the account log to corroborate a 404; treating the ' +
        'account as still there',
      { err }
    )
    return true
  }
}

/**
 * The 404 rule's grade for one Space DELETE that came back `not-found`.
 *
 * A 404 is already-deleted only where the discovery read of that same Space
 * already found it absent AND that absence is corroborated independently --
 * the account Space's world-readable log, which no capability gates: while it
 * answers, the account is alive and the refusal reading stands. Everything
 * else is a masked authorization refusal, which must never report as a clean
 * deletion.
 *
 * @param options {object}
 * @param options.discovery {'present' | 'absent' | 'unknown'}
 * @param options.accountGone {boolean}   the account Space is known deleted
 * @returns {'deleted' | 'unconfirmed' | 'refuse'}
 */
function grade404({
  discovery,
  accountGone
}: {
  discovery: 'present' | 'absent' | 'unknown'
  accountGone: boolean
}): 'deleted' | 'unconfirmed' | 'refuse' {
  if (discovery === 'present') {
    return 'refuse'
  }
  if (discovery === 'absent') {
    return accountGone ? 'deleted' : 'unconfirmed'
  }
  return 'unconfirmed'
}

/**
 * The display label a registry entry carries, as a spreadable fragment. A
 * passphrase entry carries none, so the fragment is empty for it.
 *
 * @param entry {UnlockMethod}
 * @returns {{ label?: string }}
 */
function labelOf(entry: UnlockMethod): { label?: string } {
  const label = (entry as { label?: string }).label
  return label ? { label } : {}
}

/**
 * Deletes the account and every Space it owns, from a remembered session or
 * from the default transient one.
 *
 * The run order is (a), (a1), (a2), (b3), (b2), (b1), (b5), (b6), (w):
 *
 * (a) authenticate and derive FRESH from the typed passphrase (or the
 * passkey's re-asserted PRF output): the credential, its unlock record, and
 * the ladder seed that signs every delegation downstream. Deriving rather
 * than reading the session's stamped seed is what makes the confirm
 * cryptographically load-bearing -- a session stealer holding the live tab
 * but not the secret cannot sign a single DELETE. The passkey arm asserts
 * against THIS session's own credential id and re-checks the account
 * controller, so a second account's passkey on the same authenticator cannot
 * be picked;
 * (a1) quiesce: stop background replication and close the local replica
 * before the first destructive phase (a remembered session only);
 * (a2) discover, under the visit's own authority: verify the account log,
 * require this credential's ladder VM in the resolved document, renew a stale
 * generation delegation, read the unlock-methods registry (repairing a stale
 * seal in place), report the two coverage states the registry cannot name,
 * enumerate every auxiliary annex Space the log's `#DelegatedClients` pointer
 * history names unioned with the acting record's own sibling target, and
 * probe every Space so the 404 rule has a basis. Every failure here refuses
 * the run with nothing deleted;
 * (b3) the auxiliary annex Space(s), each under a DELETE-only child of its
 * own Space root minted immediately before its own request;
 * (b2) the KMS keystore -- shipped skipped and reported;
 * (b1) the sibling unlock Spaces, each under a DELETE-only child of that
 * entry's management zcap. A failure with a live capability refuses; an entry
 * with no usable capability is a reported residue and the run continues;
 * (b5) the account Space, the pivot;
 * (b6) the acting credential's own unlock Space, a root invocation under the
 * credential's own unlock identity. Past the pivot, so it reports rather than
 * refuses and never returns `'failed'`;
 * (w) the shared wipe enumeration.
 *
 * Clearing the session and leaving for the landing page stay with the caller,
 * which owns the app shell.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.passphrase {string}   ignored for a guest and for a passkey
 *   session, which re-asserts instead
 * @param [options.onPhase] {Function}   per-phase progress
 * @param [options.signal] {AbortSignal}   aborts the passkey assertion
 * @returns {Promise<AccountDeletionOutcome>}
 */
export async function deleteAccount({
  session,
  passphrase,
  onPhase,
  signal
}: {
  session: Session
  passphrase: string
  onPhase?: (phase: AccountDeletionPhase) => void
  signal?: AbortSignal
}): Promise<AccountDeletionOutcome> {
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes (deletion walks the registry); on a settled session
  // the chain resolved long ago, and a guest session carries no chain.
  await session.registryReady
  const isGuest = !!session.isGuest
  const { profile } = session
  const persistence = profile.persistence
  const browserLocal = isBrowserLocalSession(persistence)
  // The Storage Access seam: a session begun from the CHAPI popup carries the
  // unpartitioned factory here, so every session-database delete below lands
  // in the first-party bucket the records actually live in.
  const idb = browserLocal ? persistence.idb : undefined
  // Read at each use rather than captured: (a2)'s renewal REPLACES
  // `profile.invocationCapability` in place, and every read after it must
  // ride the renewed delegation rather than the one the walk opened with.
  const visitCapability = (): IZcap | undefined => profile.invocationCapability
  const spaces: SpaceDeletionReport[] = []
  const unnamed: UnnamedUnlockSpace[] = []
  const done = (result: AccountDeletionResult): AccountDeletionOutcome => ({
    result,
    spaces,
    unnamed,
    keystore: 'skipped'
  })
  const refuse = (
    refusal: AccountDeletionRefusalReason
  ): AccountDeletionOutcome => ({
    result: 'refused',
    refusal,
    spaces,
    unnamed,
    keystore: 'skipped'
  })

  const pointer = profile.accountPointer
  const accountSpaceId = session.storage.spaceId
  // The WAS-scoped arms. A guest and a no-WAS deployment skip them BY SCOPE
  // rather than reaching them and catching: neither owns a Space, so neither
  // may be made undeletable by a refusal about one.
  const remote = !isGuest && !!WAS_SERVER_URL && !!accountSpaceId
  // Whether the account pointer names a did:webvh. The ladder-signed arms --
  // the (a2) ladder-VM gate, (b3), and the transient shapes of (b1) and (b5)
  // -- all verify against that document, so they need a promoted account; an
  // unpromoted one reaches its Spaces by root invocation, which only an
  // enrolled client holds.
  const promoted = !!pointer?.did && isWebvhDid(pointer.did)

  // (a) Authenticate and derive.
  onPhase?.({ phase: 'authenticate' })
  const controller = profile.accountController ?? session.user.id
  const methodType = profile.unlockMethod?.type ?? 'passphrase'
  let credential: UnlockCredential | undefined
  let ladderSeed: Uint8Array | undefined
  let registry: UnlockMethodsRecord | null = null
  let registryLoaded = false

  /**
   * The registry read, once per run: under the visit's own authority (a
   * transient session holds no root invocation), with a stale seal repaired
   * in place from the roster's escrow rather than refused.
   */
  const loadRegistry = async (): Promise<UnlockMethodsRecord | null> => {
    if (registryLoaded) {
      return registry
    }
    // The delegation the read rides must be current before it is read
    // under: a dead or GC-swapped generation delegation comes back as the
    // server's masked 404, which the registry read maps to `null`.
    await renewVisitDelegation()
    try {
      registry = await getUnlockMethods({
        session,
        ...(visitCapability() ? { capability: visitCapability() } : {})
      })
    } catch (err) {
      if (!(err instanceof UnlockRegistryStaleSealError)) {
        throw err
      }
      const repaired = await repairRegistrySealForDeletion({
        session,
        ...(visitCapability() ? { capability: visitCapability() } : {})
      })
      if (repaired !== 'repaired') {
        throw new UnlockRegistryStaleSealError({ cause: err })
      }
      registry = await getUnlockMethods({
        session,
        ...(visitCapability() ? { capability: visitCapability() } : {})
      })
    }
    // The 404 rule, applied to the registry. `getUnlockMethods` maps the
    // server's masked 404 to `null`, so on an account that MUST carry a
    // registry -- a promoted account whose log answered at (a2) -- `null` is
    // an authorization refusal, not an absence. Treating it as "no registry"
    // would empty the sibling walk: (b1) would delete nothing, (b5) would
    // still succeed, and every sibling unlock Space would be stranded behind
    // a dead account while the run reported a clean deletion. A genuinely
    // registry-less account is only established where no registry can be
    // demanded: an unpromoted account, or a no-WAS deployment.
    if (registry === null && remote && promoted) {
      throw new Error(
        "The account's unlock-methods registry read came back empty on a " +
          'promoted account, which the server masks an authorization refusal ' +
          'as; refusing rather than walking an empty sibling list.'
      )
    }
    registryLoaded = true
    return registry
  }

  /**
   * (a2)'s generation-delegation renewal, run at most once and before the
   * first read that rides it. A transient session that carries every member
   * the renewal needs and still gets `null` back has a delegation that could
   * not be renewed, and every read past it would ride a dead one -- so the
   * walk refuses rather than reading through it.
   */
  let renewalDone = false
  const renewVisitDelegation = async (): Promise<void> => {
    if (renewalDone || browserLocal || !remote || !promoted) {
      return
    }
    renewalDone = true
    const renewable =
      !!profile.ladderSeed &&
      !!profile.standingUnlock?.delegatedClients &&
      'clientAnnex' in persistence
    const renewed = await renewTransientGenerationDelegation({ session })
    if (!renewed && renewable) {
      throw new Error(
        "The visit's generation delegation could not be renewed, so every " +
          'read of this walk would ride a delegation the server may already ' +
          'refuse.'
      )
    }
  }

  if (!isGuest) {
    let secret: string | Uint8Array = passphrase
    let kdf = KEYRING_KDF
    if (methodType === 'passkey') {
      // The confirm asserts against THIS session's own credential rather than
      // any discoverable passkey for the origin: with an empty
      // `allowCredentials` a second account's passkey on the same
      // authenticator could be picked, and (a) would derive that account's
      // ladder seed while the session is this one's.
      let entry: PasskeyUnlockMethod | undefined
      try {
        const record = await loadRegistry()
        entry = (record?.methods ?? []).find(
          (method): method is PasskeyUnlockMethod =>
            method.type === 'passkey' &&
            method.unlockSpaceId === profile.unlockMethod?.unlockSpaceId
        )
      } catch (err) {
        log.warn('Could not read the unlock-methods registry for deletion', {
          err
        })
        return refuse(
          err instanceof UnlockRegistryStaleSealError
            ? 'registry-stale-seal'
            : 'registry-unreadable'
        )
      }
      if (!entry) {
        log.error(
          'This passkey session has no unlock-methods entry of its own; ' +
            'refusing to assert against a discoverable credential'
        )
        return refuse('registry-unreadable')
      }
      const { prfOutput } = await assertPasskeyPrf({
        credentialIds: [base64urlnopad.decode(entry.credentialId)],
        ...(signal ? { signal } : {})
      })
      secret = prfOutput
      kdf = PASSKEY_KDF
    }
    credential = await deriveUnlockCredential({ secret, kdf })
    try {
      // Match against the ACCOUNT controller the unlock record was bound
      // under (differs from `user.id` on an enrolled second client, and on
      // every transient visit).
      const verified = await verifyUnlockSecret({
        controller,
        secret,
        kdf,
        idb,
        credential
      })
      ladderSeed = verified.ladderSeed
    } catch (err) {
      if (err instanceof WrongPassphraseError) {
        return done('wrong-passphrase')
      }
      // Any other failure (e.g. the remote is unreachable) is a generic
      // delete failure -- do not touch the user's data.
      log.error('Could not verify the unlock secret for deletion', { err })
      return done('failed')
    }
  }

  // (a1) Quiesce: stop background replication and close the local replica
  // before the first destructive phase, so replication does not race the
  // replica delete at (w). A transient session drives neither.
  if (browserLocal) {
    onPhase?.({ phase: 'quiesce' })
    try {
      await syncController.stop()
    } catch (err) {
      log.warn('Could not stop background replication before deletion', { err })
    }
  }

  // (a2) Discover.
  let deleter: LadderDeleter | undefined
  const annexSpaces: Array<{
    spaceId: string
    discovery: 'present' | 'absent'
  }> = []
  const siblingEntries: Array<{
    entry: UnlockMethod
    discovery: 'present' | 'absent' | 'unknown'
    refusalReason?: UnlockSpaceDeletionOutcome
  }> = []
  let actingDiscovery: 'present' | 'absent' | 'unknown' = 'unknown'
  // Every enrolled client's own did:key, read off the verified document, so
  // the local wipe can name each one's replica database and cache families.
  const enrolledClientDids: string[] = []
  // The already-deleted arm: the account log answers 404, so the remote half
  // is finished before it started and the run carries straight to (b6)/(w).
  let accountAlreadyGone = false
  // Set once the account Space is known gone, by this run's own corroborated
  // DELETE or by the already-deleted arm. It gates (b6) and the 404 grades.
  let accountGone = false
  // The verified account document and log, and the DID they resolved for --
  // absent on an unpromoted account, which publishes neither.
  const accountDid = promoted ? (pointer?.did as string) : undefined
  let doc: object | undefined
  let logEntries: DIDLog | undefined

  if (remote && credential && !accountAlreadyGone) {
    onPhase?.({ phase: 'discover' })
    if (accountDid && pointer) {
      try {
        // FRESH, not the session-lifetime memo: a Settings session verified
        // its log at login, and reusing that would hide the one state this
        // arm exists for -- an account deleted since, from another tab or by
        // an earlier run of this same walk whose 2xx was lost.
        invalidateVerifiedLog({ profile })
        const verified = await verifiedAccountLog({ profile, pointer })
        doc = verified.doc
        logEntries = verified.log
      } catch (err) {
        if ((err as Error).name === 'AccountLogMissingError') {
          // The account log answers 404: this account is already gone (a
          // second tab, or a re-click after a (b5) whose 2xx was lost). The
          // remote half is finished, and the credential is already derived,
          // so the run continues into (b6) and (w) rather than refusing and
          // stranding this credential's own unlock Space and local state.
          log.info(
            'The account log is already gone; finishing the local half only'
          )
          accountAlreadyGone = true
          accountGone = true
          spaces.push({
            kind: 'account',
            spaceId: accountSpaceId as string,
            outcome: 'deleted'
          })
        } else {
          log.error('Could not verify the account log for deletion', { err })
          return refuse('discovery-failed')
        }
      }
      if (!accountAlreadyGone) {
        // Every enrolled client's own did:key, for the local wipe: its
        // signing method is `<accountDid>#<multibase>` and its client
        // did:key is `did:key:<multibase>`, which is what its replica
        // database prefix and its client-keyed cache families derive from.
        for (const vmId of relationIds(
          (doc as { capabilityInvocation?: Array<string | { id?: string }> })
            .capabilityInvocation
        )) {
          enrolledClientDids.push(
            clientKeyAgreementController({
              signingKeyMultibase: vmId.slice(vmId.lastIndexOf('#') + 1)
            })
          )
        }
      }
    }
  }

  if (remote && credential && !accountAlreadyGone) {
    // The ladder-VM gate. Without this credential's ladder VM in the resolved
    // document, no delegation the walk mints verifies anywhere -- so the run
    // refuses here with nothing deleted rather than 404ing its way through.
    // An unpromoted account has no document at all, so a transient session,
    // which holds nothing but ladder-signed authority, refuses the same way.
    if (!browserLocal) {
      if (!ladderSeed || !accountDid || !doc) {
        return refuse('ladder-vm-not-anchored')
      }
      const vmKeyMultibase = await ladderVmKeyMultibase({ ladderSeed })
      if (!ladderVmIds({ doc }).includes(`${accountDid}#${vmKeyMultibase}`)) {
        log.warn(
          'Account deletion refused: the account document anchors no ladder ' +
            "VM of this credential's",
          { accountDid }
        )
        return refuse('ladder-vm-not-anchored')
      }
      // The generation delegation every (a2) read rides must outlive the
      // walk: renew it BEFORE anything destructive runs. Already run when
      // the passkey arm's own registry read needed it.
      try {
        await renewVisitDelegation()
      } catch (err) {
        log.error('Could not renew the visit generation delegation', { err })
        return refuse('discovery-failed')
      }
      const zcapClient = await ladderVmZcapClient({ accountDid, ladderSeed })
      const agent = await ladderVmAgent({ ladderSeed })
      deleter = {
        zcapClient,
        invoker: didKeyZcapClient({ keyAgent: agent }),
        controller: agent.id
      }
    }

    // The registry, under the visit's own authority. A failed read refuses:
    // a best-effort walk over an incomplete registry strands oracle Spaces
    // the account can no longer name once its own registry is gone.
    try {
      registry = await loadRegistry()
    } catch (err) {
      log.warn('Could not read the unlock-methods registry for deletion', {
        err
      })
      return refuse(
        err instanceof UnlockRegistryStaleSealError
          ? 'registry-stale-seal'
          : 'registry-unreadable'
      )
    }

    // The registry is not the set of unlock Spaces. Both coverage states
    // REPORT rather than refuse: the account Space's deletion is their
    // mender, since the credential behind each meets a dead account log at
    // its next login and is offered the removal there. A record the detector
    // could NOT settle is a different matter and refuses the run, since a
    // walk that cannot tell a pending entry from a healthy one names neither.
    const deploymentHost = new URL(WAS_SERVER_URL as string).host
    const annexIds = new Set<string>()
    if (doc && accountDid && pointer) {
      try {
        const pending = await findPendingPassphraseEntries({
          registry,
          host: pointer.host,
          readerFor: async entry => {
            const parent = entry.manageCapability as IZcap
            if (!deleter) {
              return {
                zcapClient: managementZcapClient({
                  session,
                  capability: parent
                }),
                capability: parent
              }
            }
            if (
              unlockSpaceDeletionRefusal({
                session,
                entry,
                signer: deleter,
                verb: 'GET'
              })
            ) {
              return undefined
            }
            return {
              zcapClient: deleter.invoker,
              capability: await mintSpaceVerbCapability({
                zcapClient: deleter.zcapClient,
                parent,
                verb: 'GET',
                controller: deleter.controller,
                ttlMs: DELETION_ZCAP_TTL_MS
              })
            }
          }
        })
        for (const entry of pending) {
          unnamed.push({ reason: 'pending-entry', method: entry.type })
        }
      } catch (err) {
        log.error(
          'Could not settle the registry passphrase entries; nothing was deleted',
          { err }
        )
        return refuse('discovery-failed')
      }
      let unrecorded: string[]
      try {
        unrecorded = await findUnrecordedCredentials({
          doc,
          did: accountDid,
          registry
        })
      } catch (err) {
        // Its sibling detector's rule: a coverage check the walk could not
        // settle names no unlock Space either way, so it refuses rather than
        // reporting a clean run over a set it never established.
        log.error(
          'Could not settle the document credentials against the registry; nothing was deleted',
          { err }
        )
        return refuse('discovery-failed')
      }
      for (let index = 0; index < unrecorded.length; index++) {
        unnamed.push({ reason: 'unrecorded-credential' })
      }

      // The auxiliary annex Space(s): every `#DelegatedClients` value the log
      // history names -- a superseded pointer entry is append-only and its
      // Space survives the move -- unioned with the acting record's own
      // sibling target, which a torn establishment can converge on without any
      // pointer entry naming it.
      for (const space of delegatedClientsSpaceHistory({
        log: logEntries ?? []
      })) {
        if (space.host !== deploymentHost) {
          // An account that has migrated hosts leaves entries this deployment
          // cannot address; deleting that id here would address a different
          // Space, and its 404 would read as a clean deletion.
          spaces.push({
            kind: 'annex',
            spaceId: space.spaceId,
            outcome: 'unreachable',
            reason: 'foreign-host'
          })
          continue
        }
        annexIds.add(space.spaceId)
      }
      const sibling = profile.standingUnlock?.delegatedClients as
        IZcap | undefined
      const siblingSpaceId = sibling
        ? delegatedClientsDelegationSpaceId({ delegation: sibling })
        : undefined
      // Host-filtered like the pointer history above: a sibling delegation
      // carried over from another deployment names a Space id this host would
      // resolve to something else entirely.
      if (
        siblingSpaceId &&
        targetHost({
          target: (sibling as { invocationTarget?: string })?.invocationTarget
        }) === deploymentHost
      ) {
        annexIds.add(siblingSpaceId)
      }
    }

    // Per Space, the discovery outcome the 404 rule rests on. A read that
    // fails for a non-404 reason refuses the run; a 404 is recorded as absent.
    try {
      for (const spaceId of annexIds) {
        const discovery = deleter
          ? await probeSpace({
              zcapClient: deleter.invoker,
              spaceId,
              capability: await mintSpaceRootVerbCapability({
                zcapClient: deleter.zcapClient,
                storageServerUrl: WAS_SERVER_URL as string,
                spaceId,
                verb: 'GET',
                controller: deleter.controller,
                ttlMs: DELETION_ZCAP_TTL_MS
              })
            })
          : await probeSpace({ zcapClient: profile.zcapClient, spaceId })
        annexSpaces.push({ spaceId, discovery })
      }
      actingDiscovery = await probeSpace({
        zcapClient: credential.unlock.zcapClient,
        spaceId: credential.unlock.spaceId
      })
      for (const entry of (registry?.methods ?? []) as UnlockMethod[]) {
        if (entry.unlockSpaceId === credential.unlock.spaceId) {
          continue
        }
        const refusalReason = unlockSpaceDeletionRefusal({
          session,
          entry,
          ...(deleter ? { signer: deleter } : {})
        })
        if (refusalReason) {
          siblingEntries.push({ entry, discovery: 'unknown', refusalReason })
          continue
        }
        // A management zcap that allows DELETE but not GET is deletable and
        // unprobeable: the probe is skipped rather than minted (the mint
        // would throw and refuse the whole run), and the entry keeps an
        // `unknown` discovery, which the 404 rule already grades honestly.
        if (
          unlockSpaceDeletionRefusal({
            session,
            entry,
            ...(deleter ? { signer: deleter } : {}),
            verb: 'GET'
          })
        ) {
          log.warn(
            "An unlock method's management zcap allows no GET; its Space is " +
              'deleted unprobed',
            { methodType: entry.type, unlockSpaceId: entry.unlockSpaceId }
          )
          siblingEntries.push({ entry, discovery: 'unknown' })
          continue
        }
        const parent = entry.manageCapability as IZcap
        const delegator = deleter
          ? deleter.zcapClient
          : managementZcapClient({ session, capability: parent })
        const probeClient = deleter ? deleter.invoker : delegator
        const capability = await mintSpaceVerbCapability({
          zcapClient: delegator,
          parent,
          verb: 'GET',
          controller:
            deleter?.controller ??
            (parent as { controller: string }).controller,
          ttlMs: DELETION_ZCAP_TTL_MS
        })
        siblingEntries.push({
          entry,
          discovery: await probeSpace({
            zcapClient: probeClient,
            spaceId: entry.unlockSpaceId,
            capability
          })
        })
      }
    } catch (err) {
      log.error('A deletion discovery read failed; nothing was deleted', {
        err
      })
      return refuse('discovery-failed')
    }
  }

  // (b3) The auxiliary annex Space(s). Per Space: mint the DELETE-only child
  // of THAT Space's root, then send its recursive DELETE, which takes the
  // generation collections with it. Minting immediately before the request
  // spends the ten-minute window on the one request it exists for.
  for (const { spaceId, discovery } of annexSpaces) {
    onPhase?.({ phase: 'annex-space', spaceId })
    let outcome: 'deleted' | 'not-found'
    try {
      if (deleter) {
        const capability = await mintSpaceRootVerbCapability({
          zcapClient: deleter.zcapClient,
          storageServerUrl: WAS_SERVER_URL as string,
          spaceId,
          verb: 'DELETE',
          controller: deleter.controller,
          ttlMs: DELETION_ZCAP_TTL_MS
        })
        ;({ outcome } = await deleteSpaceWithCapability({
          storageServerUrl: WAS_SERVER_URL as string,
          zcapClient: deleter.invoker,
          spaceId,
          capability
        }))
      } else {
        ;({ outcome } = await new WasClient({
          serverUrl: WAS_SERVER_URL as string,
          zcapClient: profile.zcapClient
        })
          .space(spaceId)
          .deleteWithOutcome())
      }
    } catch (err) {
      // Pre-pivot: refuse. A failed (b3) that proceeded to the pivot would
      // orphan the annex Space permanently, while one that stops leaves the
      // account alive, enterable, and re-runnable with every unlock method
      // still standing.
      log.error('Could not delete an auxiliary annex Space', { spaceId, err })
      return refuse('space-delete-failed')
    }
    if (outcome === 'deleted') {
      spaces.push({ kind: 'annex', spaceId, outcome: 'deleted' })
      continue
    }
    const grade = grade404({ discovery, accountGone })
    if (grade === 'refuse') {
      log.error(
        'An auxiliary annex Space this run read successfully answered 404: a masked authorization refusal',
        { spaceId }
      )
      return refuse('space-delete-failed')
    }
    spaces.push({ kind: 'annex', spaceId, outcome: grade })
  }

  // (b2) The KMS keystore. Shipped skipped and reported.
  if (remote) {
    onPhase?.({ phase: 'keystore' })
  }

  // (b1) The sibling unlock Spaces, immediately before the pivot: their
  // DELETEs are the run's first eviction of a party that was never asked, so
  // the irreversible region stays two phases long. The REMOTE half only --
  // every sibling's browser-local state is left to (w), past the pivot, so a
  // run refused at (b5) has not quietly un-remembered this browser for every
  // other credential while its copy says the account is untouched.
  for (const { entry, discovery, refusalReason } of siblingEntries) {
    onPhase?.({ phase: 'unlock-space', spaceId: entry.unlockSpaceId })
    if (refusalReason) {
      // A reported residue, not a refusal and not a silent skip: that
      // credential's own next login re-delegates, or removes the Space once
      // the account behind it is gone.
      spaces.push({
        kind: 'unlock',
        spaceId: entry.unlockSpaceId,
        outcome: 'unreachable',
        method: entry.type,
        ...labelOf(entry),
        reason: refusalReason
      })
      continue
    }
    let space: UnlockSpaceDeletionOutcome
    try {
      ;({ space } = await deleteUnlockMethodSpace({
        session,
        entry,
        ...(deleter ? { signer: deleter } : {})
      }))
    } catch (err) {
      log.error("Could not delete an unlock method's Space", {
        methodType: entry.type,
        unlockSpaceId: entry.unlockSpaceId,
        err
      })
      return refuse('space-delete-failed')
    }
    if (space === 'deleted') {
      spaces.push({
        kind: 'unlock',
        spaceId: entry.unlockSpaceId,
        outcome: 'deleted',
        method: entry.type,
        ...labelOf(entry)
      })
      continue
    }
    if (space !== 'not-found') {
      spaces.push({
        kind: 'unlock',
        spaceId: entry.unlockSpaceId,
        outcome: 'unreachable',
        method: entry.type,
        ...labelOf(entry),
        reason: space
      })
      continue
    }
    const grade = grade404({ discovery, accountGone })
    if (grade === 'refuse') {
      log.error(
        'An unlock Space this run read successfully answered 404 on its DELETE: a masked authorization refusal',
        { unlockSpaceId: entry.unlockSpaceId }
      )
      return refuse('space-delete-failed')
    }
    spaces.push({
      kind: 'unlock',
      spaceId: entry.unlockSpaceId,
      outcome: grade,
      method: entry.type,
      ...labelOf(entry)
    })
  }

  // (b5) The account Space: the pivot. Everything the walk needs from the
  // account document has happened; what follows needs nothing from it.
  if (remote && accountSpaceId && !accountAlreadyGone) {
    onPhase?.({ phase: 'account-space', spaceId: accountSpaceId })
    // The account's own world-readable log is the corroboration the 404 rule
    // rests on, and reading it costs one unauthenticated GET; memoized so a
    // path that consults it twice fetches once.
    let logGone: boolean | undefined
    const accountLogIsGone = async (): Promise<boolean> => {
      if (logGone === undefined) {
        if (promoted && pointer) {
          logGone = !(await accountLogAnswers({
            pointer: { spaceId: pointer.spaceId, host: pointer.host }
          }))
        } else {
          // An unpromoted account publishes no log, so its corroborator is
          // the root invocation itself: the Space's controller is this
          // client's own did:key, and the server can mask no refusal for the
          // controller -- a 404 to it is absence. Only a remembered session
          // reaches here (a transient one refused at the ladder gate), so
          // the root invocation is always available.
          try {
            logGone =
              (await probeSpace({
                zcapClient: profile.zcapClient,
                spaceId: accountSpaceId
              })) === 'absent'
          } catch (err) {
            log.warn(
              'Could not re-probe an unpromoted account Space; treating it ' +
                'as still there',
              { err }
            )
            logGone = false
          }
        }
      }
      return logGone
    }
    let outcome: 'deleted' | 'not-found' | undefined
    try {
      if (deleter) {
        const capability = await mintSpaceRootVerbCapability({
          zcapClient: deleter.zcapClient,
          storageServerUrl: WAS_SERVER_URL as string,
          spaceId: accountSpaceId,
          verb: 'DELETE',
          controller: deleter.controller,
          ttlMs: DELETION_ZCAP_TTL_MS
        })
        ;({ outcome } = await session.storage.wipeRemoteStorage({
          capability,
          zcapClient: deleter.invoker
        }))
      } else {
        ;({ outcome } = await session.storage.wipeRemoteStorage())
      }
    } catch (err) {
      // A DELETE whose 2xx was lost to the network has already landed, and
      // concluding "pre-pivot, data still there" from a transport error would
      // skip (b6) and (w) while the account is gone. Re-probe before
      // surfacing -- under a freshly minted GET-only child on a transient
      // session, since the visit's generation delegation is scoped to the
      // items subtree and can never name the bare Space URL.
      log.error('Error wiping user data', { err })
      let probed: 'present' | 'absent' | 'unknown' = 'unknown'
      try {
        probed = deleter
          ? await probeSpace({
              zcapClient: deleter.invoker,
              spaceId: accountSpaceId,
              capability: await mintSpaceRootVerbCapability({
                zcapClient: deleter.zcapClient,
                storageServerUrl: WAS_SERVER_URL as string,
                spaceId: accountSpaceId,
                verb: 'GET',
                controller: deleter.controller,
                ttlMs: DELETION_ZCAP_TTL_MS
              })
            })
          : await probeSpace({
              zcapClient: profile.zcapClient,
              spaceId: accountSpaceId
            })
      } catch (probeErr) {
        log.warn('Could not re-probe the account Space after a failed wipe', {
          err: probeErr
        })
      }
      // The probe's own 404 is the same ambiguity the DELETE's is, so it
      // corroborates nothing on its own: only the world-readable log settles
      // it. Anything but a corroborated absence stays a pre-pivot failure,
      // which does not log out because the data is still there.
      if (probed !== 'absent' || !(await accountLogIsGone())) {
        return done('failed')
      }
      outcome = 'not-found'
    }
    if (outcome === 'deleted') {
      accountGone = true
      spaces.push({
        kind: 'account',
        spaceId: accountSpaceId,
        outcome: 'deleted'
      })
    } else if (await accountLogIsGone()) {
      // The log stopped answering, so the DELETE landed and only its response
      // was lost. That is the 404 rule's corroborated absence.
      accountGone = true
      spaces.push({
        kind: 'account',
        spaceId: accountSpaceId,
        outcome: 'deleted'
      })
    } else {
      // (a2) read this Space successfully and its log still answers, so the
      // 404 is a masked authorization refusal. Reporting a clean deletion
      // here would destroy every unlock record over a living account: refuse
      // instead, before (b6) and (w) run.
      log.error(
        'The account Space answered 404 on its DELETE while its log still ' +
          'answers: a masked authorization refusal',
        { spaceId: accountSpaceId }
      )
      spaces.push({
        kind: 'account',
        spaceId: accountSpaceId,
        outcome: 'unconfirmed'
      })
      return refuse('space-delete-failed')
    }
  }

  // (b6) The acting credential's own unlock Space: a root invocation under
  // the credential's own unlock identity, which needs nothing the account
  // held. Past the pivot, so it reports rather than refuses -- and never
  // returns 'failed', which would tell the user their account survived.
  if (credential && (accountGone || !remote)) {
    const { spaceId, zcapClient } = credential.unlock
    onPhase?.({ phase: 'acting-unlock-space', spaceId })
    if (WAS_SERVER_URL && remote) {
      let outcome: 'deleted' | 'not-found' | undefined
      // The in-run recourse comes first: the credential is derived and in
      // memory, so one bounded retry costs nothing and mends the common tear
      // (a dropped connection on the last request of the walk). Only a THROW
      // is retried -- a 404 is an answer, and the 404 rule grades it.
      for (let attempt = 0; attempt < 2 && outcome === undefined; attempt++) {
        try {
          ;({ outcome } = await new WasClient({
            serverUrl: WAS_SERVER_URL,
            zcapClient
          })
            .space(spaceId)
            .deleteWithOutcome())
        } catch (err) {
          if (attempt === 0) {
            log.warn('Retrying the acting unlock Space delete', { err })
            continue
          }
          log.warn(
            'Could not delete the acting unlock Space; it stands over a dead account until the next login with this credential',
            { err }
          )
        }
      }
      spaces.push({
        kind: 'acting-unlock',
        spaceId,
        method: methodType,
        outcome:
          outcome === 'deleted'
            ? 'deleted'
            : outcome === 'not-found'
              ? grade404({ discovery: actingDiscovery, accountGone }) ===
                'deleted'
                ? 'deleted'
                : 'unconfirmed'
              : 'unreachable'
      })
    }
    await deleteUnlockLocalState({ spaceId, idb })
  }

  // (w) The local half: the shared wipe enumeration, for guests and full
  // accounts alike. Past the pivot a surviving replica is a residue rather
  // than a failure: the remote account is gone, and returning 'failed' would
  // tell the user it survived -- and send a retry into a re-derivation whose
  // record fetch finds nothing at the deleted unlock Space, which reads as a
  // wrong passphrase on the account they just destroyed. A run that never
  // reached the pivot (a guest, a no-WAS deployment) keeps the fatal reading,
  // since there the local replica IS the account.
  onPhase?.({ phase: 'local-wipe' })
  const targets = snapshotWipeTargets({
    session,
    registry,
    enrolledClientDids
  })
  const { failed, unverified } = await executeLocalWipe({
    targets,
    storage: session.storage ?? undefined,
    idb
  })
  if (failed.includes('replica')) {
    return done(accountGone ? 'deleted-unverified' : 'failed')
  }
  if (unverified.includes('replica')) {
    return done('deleted-unverified')
  }
  return done('deleted')
}

/**
 * The host a capability's `invocationTarget` addresses, or `undefined` when
 * the target is absent or not a URL. The deletion walk compares it against
 * the deployment's own host, so a delegation carried over from another
 * deployment contributes no Space id: the same id under this host names a
 * different Space, and its DELETE's 404 would read as a clean deletion.
 *
 * @param options {object}
 * @param [options.target] {string}
 * @returns {string | undefined}
 */
function targetHost({ target }: { target?: string }): string | undefined {
  if (!target) {
    return undefined
  }
  try {
    return new URL(target).host
  } catch {
    return undefined
  }
}

/**
 * The deletion walk's in-place stale-seal repair: the login-time repair's
 * core, run from whichever session type is deleting. A transient session's
 * escrow unwrap key is the credential's own standing key-agreement key rather
 * than an enrolled client's, and every request rides the visit's generation
 * delegation.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.capability] {IZcap}
 * @returns {Promise<'repaired' | 'unrepaired' | 'reseal-failed'>}
 */
async function repairRegistrySealForDeletion({
  session,
  capability
}: {
  session: Session
  capability?: IZcap
}): Promise<'repaired' | 'unrepaired' | 'reseal-failed'> {
  const { profile } = session
  const spaceId = session.storage.spaceId
  const { userKey } = profile
  const unwrapKey =
    profile.clientKeyAgreementKey ??
    profile.standingUnlock?.standingClient?.agents?.keyAgreementKey
  if (!spaceId || !userKey || !unwrapKey) {
    return 'unrepaired'
  }
  const rosterRead = await readUserKeyRoster({
    store: sessionRosterStore({
      profile,
      ...(capability ? { capability } : {})
    }),
    clientKeyAgreementKey: unwrapKey
  })
  if (!rosterRead) {
    return 'unrepaired'
  }
  return await resealRegistryFromEscrow({
    zcapClient: profile.zcapClient,
    spaceId,
    userKey,
    descriptor: rosterRead.descriptor,
    unwrapKey,
    ...(capability ? { capability } : {})
  })
}
