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
import { retireUnlockCredential } from '@interop/wallet-core/unlock'
import type { StandingUnlockKeys } from '@interop/wallet-core/unlock'
import type { UserKey } from '@interop/wallet-core/keys'
import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import type { Session } from '@/types/auth'
import { enrolledClientContext } from '@/session/enrolledContext'
import { sessionRosterStore } from '@/session/rosterStore'
import { loadUserKeyEpochPin, savePinFromDescriptor } from '@/lib/sessionKey'
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
 *   as its unlock-methods registry entry recorded it
 * @param options.method.type {'passphrase' | 'passkey'}
 * @param [options.method.keyAgreementKeyMultibase] {string}
 * @param [options.method.updateKeyMultibase] {string}
 * @param options.verb {string}   what the caller is doing, for the
 *   pending-rotation refusal message (e.g. `'changing the passphrase'`)
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<CredentialRotationOutcome | null>}
 */
export async function rotateOffUnlockCredential({
  session,
  method,
  verb,
  idb
}: {
  session: Session
  method: {
    type: 'passphrase' | 'passkey'
    keyAgreementKeyMultibase?: string
    updateKeyMultibase?: string
  }
  verb: string
  idb?: IDBFactory
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

  const pinnedEpochId = await loadUserKeyEpochPin({
    accountDid: pointer.did,
    idb
  })

  // The ceremony opens with a document edit, so nothing may keep reading a
  // memo taken before it. Dropped up front and again after, so neither a
  // concurrent surface nor a later one sees the retired credential's posture
  // still standing.
  invalidateVerifiedLog({ profile: session.profile })
  const result = await retireUnlockCredential({
    idStore: remoteStore.webvhIdStore(),
    updateKeys: clientWebvhKeys,
    unlockKeys: { keyAgreement, updateKeyMultibase },
    expectedDid: pointer.did,
    verb,
    rosterStore: sessionRosterStore({ profile: session.profile, idb }),
    ...(session.profile.userKey ? { userKey: session.profile.userKey } : {}),
    clientKeyAgreementKey,
    pinnedEpochId,
    onUserKeyAdopted: async ({ userKey, latestEpochId, descriptor }) => {
      // The user key and the epoch pin persist together: the pin must never
      // advance without the key that authenticated the roster it advanced to.
      await savePinFromDescriptor({
        accountDid: pointer.did,
        epochId: latestEpochId,
        descriptor,
        idb
      })
      await session.profile.persistClientKeys?.({ userKey })
    },
    collections: cascadeCollections({ remoteStore })
  }).finally(() => invalidateVerifiedLog({ profile: session.profile }))

  return {
    rotated: result.rotated,
    collections: result.collections,
    ...(result.userKey ? { userKey: result.userKey } : {})
  }
}
