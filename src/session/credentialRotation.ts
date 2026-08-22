/**
 * Retiring a standing unlock credential -- the ceremony behind "change my
 * passphrase" and "remove this passkey". A standing credential is not a
 * stored string to overwrite: it holds a wrap in the user key roster and a
 * `keyAgreement` posture in the account's did:webvh document, so retiring one
 * is a real rotation. The ceremony itself is `retireUnlockCredential` in
 * `@interop/wallet-core/unlock`, run once for every wallet; this module
 * supplies the freewallet-shaped seams around it (the session preconditions,
 * the roster store, the epoch pin, the collections source, and the durable
 * persistence of a rotated key).
 *
 * The order is load-bearing: the credential's document posture leaves first,
 * then the user key rotates off its roster wrap, then every encrypted
 * collection re-epochs onto the fresh key. A run torn anywhere after the
 * document edit leaves the roster keying a recipient the document no longer
 * backs -- exactly the state the login-time completion sweep detects and
 * finishes -- so a torn ceremony converges rather than stranding the account.
 *
 * The caller adopts the rotated key in the live session
 * (`adoptRotatedUserKey`) rather than this module: both call sites sequence
 * their own registry teardown under the OLD vault keys first, so the adoption
 * has to run after they are done, not inside the ceremony.
 *
 * The honest limitation is the cascade's: ciphertext the credential's holder
 * already fetched stays readable to them, and old epochs stay open to the
 * user key generations the credential already delivered. Retirement stops
 * future reads.
 */
import { equalBytes } from '@noble/ciphers/utils.js'
import { retireUnlockCredential } from '@interop/wallet-core/unlock'
import type {
  ClientAnnexPostureRetirement,
  StandingUnlockKeys
} from '@interop/wallet-core/unlock'
import type { UserKey } from '@interop/wallet-core/keys'
import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import {
  retireClientAnnexRung,
  swapClientAnnexGeneration
} from '@interop/wallet-core/clientAnnex'
import type { Session } from '@/types/auth'
import { clientAnnexReachFor } from '@/session/annexReach'
import { enrolledClientContext } from '@/session/enrolledContext'
import { sessionRosterStore } from '@/session/rosterStore'
import {
  cascadeCollections,
  type UserKeyCascadeResult
} from '@/session/userKeyCascade'
import { invalidateVerifiedLog } from '@/session/verifiedLog'

/**
 * What a completed retirement reports: whether the roster actually rotated on
 * this run (a re-run of an already-complete retirement reports `false`), the
 * per-collection fan-out outcomes, and the rotated key when there was one.
 */
export interface CredentialRotationOutcome {
  rotated: boolean
  collections: UserKeyCascadeResult
  userKey?: UserKey
  clientAnnex?: ClientAnnexPostureRetirement
}

/**
 * Retires one standing unlock credential from the account: its document
 * posture out, the user key rotated off its roster wrap, every encrypted
 * collection re-epoch'd onto the fresh key.
 *
 * Resolves to `null` -- nothing to retire -- when the method records no
 * standing posture (a pre-promotion or no-WAS bind never established one) or
 * when this session cannot act as an enrolled client on a promoted account
 * (a guest, a no-WAS deployment, an unpromoted account). Otherwise the
 * ceremony is real and its failures propagate: the caller decides whether the
 * surrounding change can still be reported as done.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.method {object}   the retired credential's public posture,
 *   as its unlock-methods registry entry recorded it; the recorded update key
 *   is an anchor for the ceremony's ladder attribution, not trusted verbatim
 * @param options.method.type {'passphrase' | 'passkey'}
 * @param [options.method.keyAgreementKeyMultibase] {string}
 * @param [options.method.updateKeyMultibase] {string}
 * @param [options.method.ladderSeed] {Uint8Array}   the credential's ladder
 *   seed, when the surrounding ceremony holds the secret; it strengthens the
 *   attribution but is not required
 * @param [options.survivingLadderSeed] {Uint8Array}   a SURVIVING standing
 *   credential's ladder seed (a passphrase change passes the new
 *   credential's), preferred over the session's login seed for the annex
 *   strike-or-swap stage below
 * @param [options.onPostureRemoved] {Function}   invoked once, after the
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
  onPostureRemoved,
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
  onPostureRemoved?: () => void
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
  // posture the document carries is what the removal must name.
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
  // concurrent surface nor a later one sees the retired credential's posture
  // still standing.
  invalidateVerifiedLog({ profile: session.profile })
  const result = await retireUnlockCredential({
    idStore: remoteStore.webvhIdStore(),
    updateKeys: clientWebvhKeys,
    unlockKeys: { keyAgreement, updateKeyMultibase },
    ...(method.ladderSeed ? { ladderSeed: method.ladderSeed } : {}),
    expectedDid: pointer.did,
    verb,
    rosterStore: sessionRosterStore({ profile: session.profile }),
    ...(session.profile.userKey ? { userKey: session.profile.userKey } : {}),
    clientKeyAgreementKey,
    pinnedEpochId,
    onUserKeyAdopted: async ({ userKey, latestEpochId, descriptor }) => {
      // The user key and the epoch pin persist together: the pin must never
      // advance without the key that authenticated the roster it advanced to.
      await epochPins.saveFromDescriptor({
        accountDid: pointer.did,
        epochId: latestEpochId,
        descriptor
      })
      await session.profile.persistClientKeys?.({ userKey })
    },
    collections: cascadeCollections({ remoteStore }),
    retireClientAnnexPosture: async ({ document }) => {
      // The document edit has landed: this closure runs only once
      // `removeUnlockKey` has returned, and before the roster tail.
      onPostureRemoved?.()
      return retireClientAnnexPostureStage({
        session,
        document,
        retiredLadderSeed: method.ladderSeed,
        survivingLadderSeed,
        pointer,
        clientWebvhKeys,
        remoteStore
      })
    }
  }).finally(() => invalidateVerifiedLog({ profile: session.profile }))

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
 * @param options {object}
 * @param options.session {Session}
 * @param options.document {object}   the post-edit account document, from the
 *   retirement's stage 1
 * @param [options.retiredLadderSeed] {Uint8Array}
 * @param [options.survivingLadderSeed] {Uint8Array}
 * @param options.pointer {object}   the account pointer
 * @param options.clientWebvhKeys {object}   this client's update-key seeds
 * @param options.remoteStore {object}   the session's remote store
 * @returns {Promise<ClientAnnexPostureRetirement>}
 */
async function retireClientAnnexPostureStage({
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
}): Promise<ClientAnnexPostureRetirement> {
  try {
    const doc = document as Parameters<typeof clientAnnexReachFor>[0]['doc']
    const reach = clientAnnexReachFor({ session, pointer, doc })
    if (reach === null) {
      return { action: 'skipped', reason: 'no-pointer' }
    }
    const { generationId, was } = reach
    const survivors = [survivingLadderSeed, session.profile.ladderSeed].filter(
      (seed): seed is Uint8Array =>
        seed !== undefined &&
        (retiredLadderSeed === undefined ||
          !equalBytes(seed, retiredLadderSeed))
    )
    const logPins = session.profile.persistence.logPins

    if (retiredLadderSeed !== undefined && survivors.length > 0) {
      try {
        const { struck } = await retireClientAnnexRung({
          store: reach.logStore(),
          retiredLadderSeed,
          actingLadderSeed: survivors[0],
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
    if (survivors.length === 0) {
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
      ladderSeed: survivors[0],
      pinStore: logPins
    })
    return { action: 'swapped' }
  } catch (err) {
    console.warn(
      "Could not retire the credential's annex posture; the retired " +
        'rung stands until the next generation swap:',
      err
    )
    return { action: 'skipped', reason: 'failed' }
  }
}
