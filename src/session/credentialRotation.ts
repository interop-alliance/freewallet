/**
 * Retiring a standing unlock credential -- the ceremony behind "change my
 * passphrase" and "remove this passkey". A standing credential is not a
 * stored string to overwrite: it holds a wrap in the user key roster and a
 * `keyAgreement` entry in the account's did:webvh document, so retiring one
 * is a real rotation. The ceremony itself is `retireUnlockCredential` in
 * `@interop/wallet-core/unlock`, run once for every wallet; this module
 * supplies the freewallet-shaped seams around it (the session preconditions,
 * the roster store, the epoch pin, the collections source, and the
 * persistence of a rotated key).
 *
 * The order is load-bearing: the credential's document inventory leaves first,
 * then the user key rotates off its roster wrap, then every encrypted
 * collection re-epochs onto the fresh key. A run torn anywhere after the
 * document edit leaves the roster keying a recipient the document no longer
 * backs -- exactly the state the login-time completion sweep detects and
 * finishes -- so a torn ceremony converges rather than stranding the account.
 *
 * The rotated key is adopted in band, inside the roster tail's
 * `onUserKeyAdopted`: the unlock-methods registry is re-sealed to it while
 * this browser's stored copy of the pre-rotation key still exists, and the
 * live session swaps onto it in the same step, so the callers' registry
 * teardown writes afterwards go out under the key the record now carries.
 * Their post-ceremony `adoptRotatedUserKey` call is then a no-op.
 *
 * The honest limitation is the cascade's: ciphertext the credential's holder
 * already fetched stays readable to them, and old epochs stay open to the
 * user key generations the credential already delivered. Retirement stops
 * future reads.
 */
import { equalBytes } from '@noble/ciphers/utils.js'
import { retireUnlockCredential } from '@interop/wallet-core/unlock'
import type {
  ClientAnnexInventoryRetirement,
  StandingUnlockKeys
} from '@interop/wallet-core/unlock'
import type { UserKey } from '@interop/wallet-core/keys'
import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import {
  attributeLadderRung,
  ladderRung,
  retireClientAnnexRung,
  swapClientAnnexGeneration
} from '@interop/wallet-core/clientAnnex'
import type { Session } from '@/types/auth'
import { clientAnnexReachFor } from '@/session/annexReach'
import { enrolledClientContext } from '@/session/enrolledContext'
import { sessionRosterStore } from '@/session/rosterStore'
import { adoptRotatedUserKeyInBand } from '@/session/userKeyAdoption'
import {
  cascadeCollections,
  type UserKeyCascadeResult
} from '@/session/userKeyCascade'
import {
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:rotation')

/**
 * What a completed retirement reports: whether the roster actually rotated on
 * this run (a re-run of an already-complete retirement reports `false`), the
 * per-collection fan-out outcomes, and the rotated key when there was one.
 */
export interface CredentialRotationOutcome {
  rotated: boolean
  collections: UserKeyCascadeResult
  userKey?: UserKey
  clientAnnex?: ClientAnnexInventoryRetirement
}

/**
 * Retires one standing unlock credential from the account: its document
 * inventory out, the user key rotated off its roster wrap, every encrypted
 * collection re-epoch'd onto the fresh key.
 *
 * Resolves to `null` -- nothing to retire -- when the method records no
 * standing configuration (a no-WAS bind never established one) or
 * when this session cannot act as an enrolled client on a promoted account
 * (a guest, a no-WAS deployment, an unpromoted account). Otherwise the
 * ceremony is real and its failures propagate: the caller decides whether the
 * surrounding change can still be reported as done.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.method {object}   the retired credential's public inventory,
 *   as its unlock-methods registry entry recorded it; the recorded update key
 *   is an anchor for the ceremony's ladder attribution, not trusted verbatim
 * @param options.method.type {'passphrase' | 'passkey'}
 * @param [options.method.keyAgreementKeyMultibase] {string}
 * @param [options.method.updateKeyMultibase] {string}
 * @param [options.method.ladderSeed] {Uint8Array}   the credential's ladder
 *   seed, when the surrounding ceremony holds the secret; it strengthens the
 *   attribution but is not required. Absent, the session's own login seed is
 *   taken as the retired seed when the recorded update key is a rung of its
 *   ladder (`settleLadderSeeds`) -- the tap-free removal of the credential
 *   this session logged in with
 * @param [options.survivingLadderSeed] {Uint8Array}   a SURVIVING standing
 *   credential's ladder seed (a passphrase change passes the new
 *   credential's), preferred over the session's login seed for the annex
 *   strike-or-swap stage below. The login seed stands in only when it is
 *   provably not the retired ladder
 * @param [options.onInventoryRemoved] {Function}   invoked once, after the
 *   document edit has landed and before the roster tail runs. "Landed" is
 *   proven by the callback having run: it fires from inside the annex stage,
 *   which the ceremony reaches only once `removeUnlockKey` has returned. A
 *   throw before it therefore reads as "the edit did not land", including
 *   the narrow case of a throw inside `removeUnlockKey` after its log
 *   compare-and-swap won. That is the conservative direction: the caller
 *   keeps the registry naming the OLD credential, and a re-run converges,
 *   since every stage no-ops once it is settled
 * @param options.verb {string}   what the caller is doing, for the
 *   pending-rotation refusal message (e.g. `'changing the passphrase'`)
 * @returns {Promise<CredentialRotationOutcome | null>}
 */
export async function rotateOffUnlockCredential({
  session,
  method,
  survivingLadderSeed,
  onInventoryRemoved,
  verb
}: {
  session: Session
  method: {
    type: 'passphrase' | 'passkey'
    keyAgreementKeyMultibase?: string
    updateKeyMultibase?: string
    ladderSeed?: Uint8Array
  }
  survivingLadderSeed?: Uint8Array
  onInventoryRemoved?: () => void
  verb: string
}): Promise<CredentialRotationOutcome | null> {
  const { keyAgreementKeyMultibase, updateKeyMultibase } = method
  if (!keyAgreementKeyMultibase || !updateKeyMultibase) {
    return null
  }
  const context = enrolledClientContext({ session })
  if (!context) {
    return null
  }
  const { remoteStore, pointer, clientWebvhKeys, clientKeyAgreementKey } =
    context

  // A low-entropy passphrase publishes only a hash commitment of its
  // key-agreement key; a passkey's PRF-derived key publishes verbatim. The
  // inventory the document carries is what the removal must name.
  const keyAgreement: StandingUnlockKeys['keyAgreement'] =
    method.type === 'passphrase'
      ? {
          commitment: await keyAgreementCommitment({ keyAgreementKeyMultibase })
        }
      : { publicKeyMultibase: keyAgreementKeyMultibase }

  const { epochPins } = session.profile.persistence
  const pinnedEpochId = await epochPins.load({ accountDid: pointer.did })

  // The ceremony opens with a document edit, so nothing may keep reading a
  // memo taken before it. Dropped up front and again after, so neither a
  // concurrent surface nor a later one sees the retired credential's inventory
  // still standing.
  invalidateVerifiedLog({ profile: session.profile })

  // Which ladder is retired and which one the annex stage may anchor on is
  // settled against the PRE-edit log, read fresh behind the invalidation:
  // once the document edit lands, the retired ladder's rungs are gone from it
  // and nothing could tell the two apart, and a memo from login may predate
  // a self-enrollment elsewhere that climbed the login ladder past the rung
  // the registry now records.
  const ladders = await settleLadderSeeds({
    session,
    pointer,
    method: { ...method, updateKeyMultibase },
    survivingLadderSeed
  })
  const result = await retireUnlockCredential({
    idStore: remoteStore.webvhIdStore(),
    updateKeys: clientWebvhKeys,
    unlockKeys: { keyAgreement, updateKeyMultibase },
    ...(ladders.retiredLadderSeed
      ? { ladderSeed: ladders.retiredLadderSeed }
      : {}),
    expectedDid: pointer.did,
    verb,
    rosterStore: sessionRosterStore({ profile: session.profile }),
    ...(session.profile.userKey ? { userKey: session.profile.userKey } : {}),
    clientKeyAgreementKey,
    pinnedEpochId,
    onUserKeyAdopted: async ({ userKey, latestEpochId, descriptor }) =>
      // The in-band adoption: the registry is re-sealed to the rotated key
      // BEFORE this browser's stored copy of the old one dies, so a tab
      // death during the collection fan-out below cannot strand it. The live
      // session swaps onto the key too, so the caller's registry teardown
      // writes go out under the key the record is now sealed to.
      await adoptRotatedUserKeyInBand({
        session,
        spaceId: pointer.spaceId,
        accountDid: pointer.did,
        userKey,
        latestEpochId,
        descriptor
      }),
    collections: cascadeCollections({ remoteStore }),
    retireClientAnnexInventory: async ({ document }) => {
      // The document edit has landed: this closure runs only once
      // `removeUnlockKey` has returned, and before the roster tail.
      onInventoryRemoved?.()
      return retireClientAnnexInventoryStage({
        session,
        document,
        ...ladders,
        pointer,
        clientWebvhKeys,
        remoteStore
      })
    }
  }).finally(() => invalidateVerifiedLog({ profile: session.profile }))

  // A ladder VM the seedless walk could not attribute stays standing, and a
  // retired credential then keeps a live delegation signer. Nothing here
  // can mend that, so the state is at least visible.
  if (result.ladderVm.unclaimed.length > 0) {
    log.warn(
      "The retired credential's ladder VM could not be attributed and stands unstruck",
      { unclaimed: result.ladderVm.unclaimed }
    )
  }

  return {
    rotated: result.rotated,
    collections: result.collections,
    ...(result.userKey ? { userKey: result.userKey } : {}),
    ...(result.clientAnnex ? { clientAnnex: result.clientAnnex } : {})
  }
}

/**
 * The client annex reach of the retirement (the ceremony's stage 1b):
 * strike-or-swap. A standing credential's annex rung-0 key and hash live
 * in the pointed generation's log, out of the account document edit's reach,
 * so without this stage a retired credential keeps annex-write authority
 * for the life of the generation.
 *
 * - STRIKE, when the ceremony holds the retired credential's ladder seed
 *   (to name what to drop) and a distinct surviving seed whose committed
 *   rung can sign: one atomic annex entry drops the retired rung's key
 *   and hash (`retireClientAnnexRung`); a generation the retired credential
 *   never wrote reports `clean` with no entry.
 * - SWAP, otherwise: a fresh generation minted from a surviving credential's
 *   seed is installed and re-pointed under this client's account-log update
 *   authority (`swapClientAnnexGeneration`), and the retired rung dies with
 *   the old generation, which falls to the login-time collect fan-out.
 *
 * Best-effort by the ceremony's contract: every failure is caught and
 * reported as `skipped`, so the roster rotation -- the retirement's
 * essential remedy -- always runs. The retired credential's
 * `delegatedClients` sibling needs no server-side revocation here: its
 * record dies with the unlock Space the caller deletes, and the generation
 * it targeted is struck clean or swapped away.
 *
 * The seeds arrive settled (`settleLadderSeeds`): the surviving seed, when
 * one is given, is never the retired ladder, so the swap can only ever
 * anchor the fresh generation on a credential that stays standing. Holding
 * no surviving seed is the `no-ladder-seed` skip, never a guess.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.document {object}   the post-edit account document, from the
 *   retirement's stage 1
 * @param [options.retiredLadderSeed] {Uint8Array}
 * @param [options.survivingLadderSeed] {Uint8Array}   a seed distinct from
 *   the retired ladder's
 * @param options.pointer {object}   the account pointer
 * @param options.clientWebvhKeys {object}   this client's update-key seeds
 * @param options.remoteStore {object}   the session's remote store
 * @returns {Promise<ClientAnnexInventoryRetirement>}
 */
async function retireClientAnnexInventoryStage({
  session,
  document,
  retiredLadderSeed,
  survivingLadderSeed,
  pointer,
  clientWebvhKeys,
  remoteStore
}: {
  session: Session
  document: object
  retiredLadderSeed?: Uint8Array
  survivingLadderSeed?: Uint8Array
  pointer: NonNullable<ReturnType<typeof enrolledClientContext>>['pointer']
  clientWebvhKeys: NonNullable<
    ReturnType<typeof enrolledClientContext>
  >['clientWebvhKeys']
  remoteStore: NonNullable<
    ReturnType<typeof enrolledClientContext>
  >['remoteStore']
}): Promise<ClientAnnexInventoryRetirement> {
  try {
    const doc = document as Parameters<typeof clientAnnexReachFor>[0]['doc']
    const reach = clientAnnexReachFor({ session, pointer, doc })
    if (reach === null) {
      return { action: 'skipped', reason: 'no-pointer' }
    }
    const { generationId, was } = reach
    const logPins = session.profile.persistence.logPins

    if (retiredLadderSeed !== undefined && survivingLadderSeed !== undefined) {
      try {
        const { struck } = await retireClientAnnexRung({
          store: reach.logStore(),
          retiredLadderSeed,
          actingLadderSeed: survivingLadderSeed,
          generationId,
          expectedDid: reach.clientAnnexDid,
          pinStore: logPins,
          logId: reach.logId
        })
        return { action: struck ? 'struck' : 'clean' }
      } catch (err) {
        if (
          (err as { name?: string }).name !== 'ClientAnnexRungUncommittedError'
        ) {
          throw err
        }
        // No distinct committed rung can sign the strike; fall through to
        // the generation swap.
      }
    }
    if (survivingLadderSeed === undefined) {
      return { action: 'skipped', reason: 'no-ladder-seed' }
    }
    await swapClientAnnexGeneration({
      was,
      wasServerUrl: pointer.host,
      accountSpaceId: pointer.spaceId,
      account: {
        did: pointer.did,
        doc
      },
      idStore: remoteStore.webvhIdStore(),
      updateKeys: clientWebvhKeys,
      zcapClient: session.profile.zcapClient,
      ladderSeed: survivingLadderSeed,
      pinStore: logPins
    })
    return { action: 'swapped' }
  } catch (err) {
    log.warn(
      "Could not retire the credential's annex inventory; the retired rung stands until the next generation swap",
      { err }
    )
    return { action: 'skipped', reason: 'failed' }
  }
}

/**
 * Settles the two ladder seeds the retirement acts with: the RETIRED seed
 * (what the document edit's attribution and the annex strike name) and the
 * SURVIVING seed the annex stage signs a strike or re-mints the generation
 * with -- the caller's where given, else the session's login seed, and
 * never a seed equal to the retired one.
 *
 * Whether the login seed may fill either role is decided by the recorded
 * update key rather than by seed comparison, which is vacuous with no
 * retired seed in hand: the recorded key is some rung of the retired
 * credential's ladder (rung 0 at bind, the committed rung after a
 * self-enrollment's refresh), so the login ladder IS the retired one exactly
 * when that key is one of its rungs up to the rung the pre-edit log
 * attributes to it. A login ladder the log attributes nothing to (already
 * retired by a torn run, or ambiguous) fills neither role: a swap anchored
 * on it would re-establish authority the document no longer backs.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {object}   the account pointer
 * @param options.method {object}   the retired credential's recorded update
 *   key and, when in hand, its ladder seed
 * @param [options.survivingLadderSeed] {Uint8Array}   the caller's surviving
 *   seed
 * @returns {Promise<{ retiredLadderSeed?: Uint8Array, survivingLadderSeed?: Uint8Array }>}
 */
async function settleLadderSeeds({
  session,
  pointer,
  method,
  survivingLadderSeed
}: {
  session: Session
  pointer: NonNullable<ReturnType<typeof enrolledClientContext>>['pointer']
  method: { updateKeyMultibase: string; ladderSeed?: Uint8Array }
  survivingLadderSeed?: Uint8Array
}): Promise<{
  retiredLadderSeed?: Uint8Array
  survivingLadderSeed?: Uint8Array
}> {
  const loginSeed = session.profile.ladderSeed
  let retiredLadderSeed = method.ladderSeed
  // With the retired seed in hand the comparison below settles the login
  // seed; without it, only the recorded update key can.
  let loginSeedAdmissible =
    loginSeed !== undefined && retiredLadderSeed !== undefined
  if (loginSeed !== undefined && retiredLadderSeed === undefined) {
    const standing = await loginLadderStanding({
      session,
      pointer,
      ladderSeed: loginSeed,
      updateKeyMultibase: method.updateKeyMultibase
    })
    if (standing === 'retired') {
      retiredLadderSeed = loginSeed
    }
    loginSeedAdmissible = standing === 'survives'
  }
  const survivor = [
    survivingLadderSeed,
    ...(loginSeedAdmissible ? [loginSeed] : [])
  ].find(
    (seed): seed is Uint8Array =>
      seed !== undefined &&
      (retiredLadderSeed === undefined || !equalBytes(seed, retiredLadderSeed))
  )
  return {
    ...(retiredLadderSeed ? { retiredLadderSeed } : {}),
    ...(survivor ? { survivingLadderSeed: survivor } : {})
  }
}

/**
 * Where the session's login ladder stands relative to the credential being
 * retired: `retired` when the retired credential's recorded update key is a
 * rung of this ladder, `survives` when the pre-edit log attributes a rung to
 * the ladder and the recorded key is none of its rungs up to it, and
 * `unsettled` when the log attributes it nothing -- or cannot be read at
 * all: a failed read says no more than "cannot tell", and the conservative
 * verdict is the same, so it never fails a retirement whose every later
 * stage reads the log for itself.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {object}   the account pointer
 * @param options.ladderSeed {Uint8Array}   the login credential's seed
 * @param options.updateKeyMultibase {string}   the retired credential's
 *   recorded update key
 * @returns {Promise<'retired' | 'survives' | 'unsettled'>}
 */
async function loginLadderStanding({
  session,
  pointer,
  ladderSeed,
  updateKeyMultibase
}: {
  session: Session
  pointer: NonNullable<ReturnType<typeof enrolledClientContext>>['pointer']
  ladderSeed: Uint8Array
  updateKeyMultibase: string
}): Promise<'retired' | 'survives' | 'unsettled'> {
  let attributed: Awaited<ReturnType<typeof attributeLadderRung>>
  try {
    const published = await verifiedAccountLog({
      profile: session.profile,
      pointer
    })
    attributed = await attributeLadderRung({ ladderSeed, published })
  } catch (err) {
    log.warn(
      "The login credential's ladder could not be placed in the account log; the retirement anchors no annex generation on it",
      { err }
    )
    return 'unsettled'
  }
  for (let index = 0; index <= attributed.rung.index; index++) {
    const rung =
      index === attributed.rung.index
        ? attributed.rung
        : await ladderRung({ ladderSeed, index })
    if (rung.keyMultibase === updateKeyMultibase) {
      return 'retired'
    }
  }
  return 'survives'
}
