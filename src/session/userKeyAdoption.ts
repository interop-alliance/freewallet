/**
 * Adopting a rotated per-user key in a live session -- the tail every user key
 * rotation shares (a client disconnected, a recovery code spent or revoked):
 * the remote unlock-methods registry is re-sealed from the old vault keys to
 * the new ones, then the profile's vault keys and the storage ciphers are
 * swapped, so the session that drove the rotation keeps operating without a
 * re-login.
 *
 * The in-band form (`adoptRotatedUserKeyInBand`) is the one every ceremony
 * runs, from inside the roster tail's `onUserKeyAdopted`: the re-seal must
 * happen while a stored copy of the PRE-rotation user key still exists, and
 * the client-key record write inside that same callback is what destroys it
 * on a single-client account. A ceremony that re-sealed only afterwards
 * stranded the registry whenever the collection fan-out in between was torn.
 *
 * The two halves split at the fan-out. The in-band form takes the key
 * material alone, because every collection still carries the epoch the
 * rotation is about to retire. The post-ceremony form
 * (`adoptRotatedUserKey`) is what rebuilds the storage ciphers, on the
 * descriptors the fan-out has moved onto the fresh key.
 *
 * Neutral by design: both the revocation cascade and the recovery ceremonies
 * call in here, and the recovery module is itself imported by the revocation
 * one (the delegation re-mint), so a helper living in either would close a
 * cycle.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IZcap
} from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { userKeyVaultKeys, type UserKey } from '@interop/wallet-core/keys'
import { WAS_SERVER_URL } from '@/app.config'
import type { Session } from '@/types/auth'
import { rewrapUnlockMethodsRecord } from '@/session/unlockMethods'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:userkey')

/**
 * Re-seals the unlock-methods registry from one set of vault keys to another,
 * best-effort: a failure leaves the registry sealed to the old user key, which
 * the caller must know about -- a session that moved on to the new key while
 * the record stayed on the old one meets `UnlockRegistryStaleSealError` on
 * every later registry read. A registry that does not exist yet is a no-op
 * and counts as success.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   an enrolled client's signing client
 * @param options.spaceId {string}   the data Space id
 * @param options.from {object}   the pre-rotation vault keys
 * @param options.from.keyAgreementKey {IKeyAgreementKey}
 * @param options.from.keyResolver {IKeyResolver}
 * @param options.to {object}   the post-rotation vault keys
 * @param options.to.keyAgreementKey {IKeyAgreementKey}
 * @param options.to.keyResolver {IKeyResolver}
 * @param [options.capability] {IZcap}   an invocation capability every request
 *   rides (a transient session's generation delegation); the root capability
 *   is invoked otherwise
 * @returns {Promise<boolean>}   whether the registry is now sealed to `to`
 */
export async function rewrapUnlockRegistryToUserKey({
  storageServerUrl,
  zcapClient,
  spaceId,
  from,
  to,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  from: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  to: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  capability?: IZcap
}): Promise<boolean> {
  try {
    await rewrapUnlockMethodsRecord({
      storageServerUrl,
      zcapClient,
      spaceId,
      from,
      to,
      ...(capability ? { capability } : {})
    })
    return true
  } catch (err) {
    // A RecordEnvelopeDecryptError here can mean the record is not sealed to
    // `from` -- including the lost-CAS-race case where a retry's fresh base
    // was already re-sealed forward by another writer. Either way the loop
    // never wrote a record it could not open, so reporting false (and keeping
    // the session on the pre-rotation keys) is the safe reading.
    log.warn(
      'Could not re-wrap the unlock-methods registry to the rotated user key',
      { err }
    )
    return false
  }
}

/**
 * The rotation re-seal, session-shaped: re-seals the unlock-methods registry
 * from the session's CURRENT (pre-rotation) vault keys to the ones the
 * rotated user key derives. Internally best-effort, and it reports whether it
 * worked -- the caller may not move the session onto the rotated key while
 * the record is still on the old one.
 *
 * Guarded on a configured storage server (and on the session actually
 * holding vault keys) because the registry has exactly one home, the remote
 * Space: with no server there is nothing to re-seal, which counts as
 * success, as does an account with no registry written yet.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.spaceId {string}   the data Space id
 * @param options.userKey {UserKey}   the freshly rotated per-user key
 * @param [options.capability] {IZcap}   an invocation capability every request
 *   rides (a transient session's generation delegation); the root capability
 *   is invoked otherwise
 * @returns {Promise<boolean>}   whether the registry is now sealed to the
 *   rotated key
 */
export async function resealUnlockRegistryForRotation({
  session,
  spaceId,
  userKey,
  capability
}: {
  session: Session
  spaceId: string
  userKey: UserKey
  capability?: IZcap
}): Promise<boolean> {
  const { keyAgreementKey, keyResolver } = session.profile
  if (!keyAgreementKey || !keyResolver || !WAS_SERVER_URL) {
    return true
  }
  return await rewrapUnlockRegistryToUserKey({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: session.profile.zcapClient,
    spaceId,
    from: { keyAgreementKey, keyResolver },
    to: userKeyVaultKeys({ userKey }),
    ...(capability ? { capability } : {})
  })
}

/**
 * The in-band adoption: the whole body of a rotation ceremony's
 * `onUserKeyAdopted`, in the one order that leaves nothing stranded.
 *
 * 1. The unlock-methods registry is re-sealed to the adopted key. It is the
 *    only stage that needs the pre-rotation vault keys, and step 2 destroys
 *    this browser's stored copy of them, so it goes first: a run torn
 *    anywhere after this point leaves a registry the surviving keys open.
 * 2. The client-key record persists the adopted key, and the visit's epoch
 *    pin advances with it -- the pin must never advance without the key that
 *    authenticated the roster it advanced to.
 * 3. The live session takes the adopted key -- but ONLY if step 1 reported
 *    success. The ceremony's own later registry reads and writes (an entry
 *    drop, the deferred entry write, a re-mint's field refresh) must go out
 *    under the key the record is actually sealed to; a session moved onto
 *    the rotated key over a record still sealed to the old one would meet
 *    `UnlockRegistryStaleSealError` on every one of them, mid-ceremony. When
 *    the re-seal failed the session stays on the pre-rotation keys, which
 *    keep working: the fan-out escrows the old generation into every epoch.
 *    The caller's post-ceremony `adoptRotatedUserKey` then retries the
 *    re-seal from those still-held keys, and the next login's re-seal repair
 *    is the backstop after that.
 *
 * The storage ciphers are deliberately NOT rebuilt here. This callback fires
 * before the collection fan-out, so every collection still carries the epoch
 * the rotation is about to retire, and a rebuild would ask the fresh key to
 * open an epoch it is not yet a recipient of. The ciphers move at the
 * caller's post-ceremony `adoptRotatedUserKey`, past the fan-out.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.spaceId {string}   the data Space id
 * @param options.accountDid {string}   the account did:webvh, the visit's
 *   epoch pin key
 * @param options.userKey {UserKey}   the freshly rotated per-user key
 * @param options.latestEpochId {string}   the roster epoch the key came from
 * @param options.descriptor {object}   the roster descriptor that epoch was
 *   read from
 * @param [options.capability] {IZcap}   an invocation capability the re-seal's
 *   requests ride (a transient session's generation delegation); the root
 *   capability is invoked otherwise
 * @returns {Promise<void>}
 */
export async function adoptRotatedUserKeyInBand({
  session,
  spaceId,
  accountDid,
  userKey,
  latestEpochId,
  descriptor,
  capability
}: {
  session: Session
  spaceId: string
  accountDid: string
  userKey: UserKey
  latestEpochId: string
  descriptor: { epochs?: Array<{ id: string }> }
  capability?: IZcap
}): Promise<void> {
  const resealed = await resealUnlockRegistryForRotation({
    session,
    spaceId,
    userKey,
    ...(capability ? { capability } : {})
  })
  await session.profile.persistence.epochPins.saveFromDescriptor({
    accountDid,
    epochId: latestEpochId,
    descriptor
  })
  await session.profile.persistClientKeys?.({ userKey })
  if (!resealed) {
    log.warn(
      'The unlock-methods registry stayed sealed to the superseded user key; this session keeps operating under it rather than meeting a stale seal on every registry read'
    )
    return
  }
  holdSessionVaultKeys({ session, userKey })
}

/**
 * Moves a live session's key material onto a user key without rebuilding the
 * storage ciphers: the profile's vault keys are derived from it and the
 * storage manager holds them for its next rebuild. The pre-fan-out form, so
 * a ceremony's later registry reads and writes go out under the rotated key
 * while the ciphers keep opening the epochs the collections still carry.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.userKey {UserKey}   the user key to operate under
 * @returns {void}
 */
export function holdSessionVaultKeys({
  session,
  userKey
}: {
  session: Session
  userKey: UserKey
}): void {
  const vaultKeys = userKeyVaultKeys({ userKey })
  session.profile.userKey = userKey
  session.profile.keyAgreementKey = vaultKeys.keyAgreementKey
  session.profile.keyResolver = vaultKeys.keyResolver
  session.storage.holdRotatedVaultKeys(vaultKeys)
}

/**
 * Swaps a user key into a live session: the profile's vault keys are derived
 * from it, the rotated descriptors are refetched, and the storage ciphers are
 * rebuilt on them. The one place the full swap is spelled out. It belongs
 * past the collection fan-out, which is what puts the fresh key in every
 * collection's current epoch; before it, {@link holdSessionVaultKeys} is the
 * step that runs.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.userKey {UserKey}   the user key to operate under
 * @returns {Promise<void>}
 */
export async function swapSessionVaultKeys({
  session,
  userKey
}: {
  session: Session
  userKey: UserKey
}): Promise<void> {
  const vaultKeys = userKeyVaultKeys({ userKey })
  session.profile.userKey = userKey
  session.profile.keyAgreementKey = vaultKeys.keyAgreementKey
  session.profile.keyResolver = vaultKeys.keyResolver
  await session.storage.adoptRotatedVaultKeys(vaultKeys)
}

/**
 * Adopts a rotated user key in the live session: the unlock-methods registry is
 * re-sealed to it, then the profile vault keys and the storage ciphers are
 * swapped, so this session keeps operating without a re-login.
 *
 * The post-ceremony form, and the one place the storage ciphers move onto the
 * rotated key: it runs past the collection fan-out, which is what makes the
 * fresh key a recipient of every collection's current epoch. The in-band step
 * before the fan-out takes the key material alone.
 *
 * Its id guard is over the re-seal, not over the swap. A session already
 * running on the given key adopted it in band
 * (`adoptRotatedUserKeyInBand`, inside the ceremony's roster tail) with its
 * re-seal landed, so no second PUT is made. A session still on the
 * PRE-rotation key is the failed-re-seal case -- the in-band step left it
 * there deliberately -- so this call retries the re-seal from the keys it is
 * still holding. Either way the swap that follows is what rebuilds the
 * ciphers on the rotated epochs.
 *
 * The registry re-seal is guarded on a configured storage server (and on the
 * session actually holding pre-rotation vault keys) because the registry has
 * exactly one home, the remote Space: with no server there is nothing to
 * re-seal, and the rotation itself -- which only ever happens against a remote
 * roster -- must still be adopted locally. The swap below is therefore
 * deliberately outside the guard.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.spaceId {string}
 * @param options.userKey {UserKey}   the freshly rotated per-user key
 * @param [options.capability] {IZcap}   an invocation capability the re-seal's
 *   requests ride (a transient session's generation delegation); the root
 *   capability is invoked otherwise
 * @returns {Promise<void>}
 */
export async function adoptRotatedUserKey({
  session,
  spaceId,
  userKey,
  capability
}: {
  session: Session
  spaceId: string
  userKey: UserKey
  capability?: IZcap
}): Promise<void> {
  if (session.profile.userKey?.id !== userKey.id) {
    await resealUnlockRegistryForRotation({
      session,
      spaceId,
      userKey,
      ...(capability ? { capability } : {})
    })
  }
  try {
    await swapSessionVaultKeys({ session, userKey })
  } catch (err) {
    log.warn(
      'Could not rebuild the storage ciphers on the rotated user key; the next login adopts it instead',
      { err }
    )
  }
}
