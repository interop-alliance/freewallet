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
 * The follower form (`adoptFollowerUserKey`) is the other direction: this
 * session did not rotate, another client did, and the session catches up to
 * the roster's current key mid-visit. It makes no registry re-seal, since the
 * rotator already re-sealed the registry forward.
 *
 * Neutral by design: both the revocation cascade and the recovery ceremonies
 * call in here, and the recovery module is itself imported by the revocation
 * one (the delegation re-mint), so a helper living in either would close a
 * cycle.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { userKeyVaultKeys, type UserKey } from '@interop/wallet-core/keys'
import type { CollectionEncryption } from '@interop/was-client'
import { WAS_SERVER_URL } from '@/app.config'
import type { Session } from '@/types/auth'
import { rewrapUnlockMethodsRecord } from '@/session/unlockMethods'
import { isSessionDisposed } from '@/session/sessionLifecycle'
import { epochPinWriteAllowed } from '@/session/persistence'
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
 * @param options.from {UserKey}   the pre-rotation user key
 * @param options.to {UserKey}   the post-rotation user key
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
  from: UserKey
  to: UserKey
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
 * holding a user key) because the registry has exactly one home, the remote
 * Space: with no server there is nothing to re-seal, which counts as
 * success, as does an account with no registry written yet.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.spaceId {string}   the data Space id
 * @param options.userKey {UserKey}   the freshly rotated per-user key
 * @returns {Promise<boolean>}   whether the registry is now sealed to the
 *   rotated key
 */
export async function resealUnlockRegistryForRotation({
  session,
  spaceId,
  userKey
}: {
  session: Session
  spaceId: string
  userKey: UserKey
}): Promise<boolean> {
  const from = session.profile.userKey
  if (!from || !WAS_SERVER_URL) {
    return true
  }
  // The visit's own authority, read here rather than threaded by every
  // caller: a transient session holds nothing but its generation delegation
  // over the account Space, and an enrolled session holds none and
  // root-invokes.
  const capability = session.profile.invocationCapability
  return await rewrapUnlockRegistryToUserKey({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: session.profile.zcapClient,
    spaceId,
    from,
    to: userKey,
    ...(capability ? { capability } : {})
  })
}

/**
 * The data Space id a rotated user key is adopted against -- the account
 * pointer's, falling back to the session storage's.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {string}
 */
export function rotationSpaceId({ session }: { session: Session }): string {
  return session.profile.accountPointer?.spaceId ?? session.storage.spaceId!
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
 * @returns {Promise<void>}
 */
export async function adoptRotatedUserKeyInBand({
  session,
  spaceId,
  accountDid,
  userKey,
  latestEpochId,
  descriptor
}: {
  session: Session
  spaceId: string
  accountDid: string
  userKey: UserKey
  latestEpochId: string
  descriptor: { epochs?: Array<{ id: string }> }
}): Promise<void> {
  const resealed = await resealUnlockRegistryForRotation({
    session,
    spaceId,
    userKey
  })
  await session.persistence.epochPins.saveFromDescriptor({
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
 * @returns {Promise<void>}
 */
export async function adoptRotatedUserKey({
  session,
  spaceId,
  userKey
}: {
  session: Session
  spaceId: string
  userKey: UserKey
}): Promise<void> {
  if (session.profile.userKey?.id !== userKey.id) {
    await resealUnlockRegistryForRotation({
      session,
      spaceId,
      userKey
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

/**
 * Where a session's user key sits against a user key roster's current epoch
 * (see {@link userKeyRosterPosition}).
 */
type RosterPosition = 'current' | 'behind' | 'ahead' | 'unplaced'

/**
 * What a follower adoption resolves to: whether it moved the session, and
 * where the session's key sits against the read afterward.
 */
interface FollowerAdoptionResult {
  adopted: boolean
  position: RosterPosition
}

/**
 * The roster read a follower adoption is handed.
 */
interface FollowerRosterRead {
  descriptor: CollectionEncryption
  userKey: UserKey
  latestEpochId: string
}

/**
 * Where a session's user key sits in a user key roster's epoch list, against
 * the roster's current epoch: `current` when it is the current epoch,
 * `behind` when it is an earlier one, `ahead` when it is a later one (the
 * roster read is older than the session's own rotation), and `unplaced` when
 * the session holds no user key or the list does not carry it or the current
 * epoch. Each roster epoch's id is its user key's id.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.descriptor {CollectionEncryption}   the roster descriptor
 * @returns {'current' | 'behind' | 'ahead' | 'unplaced'}
 */
export function userKeyRosterPosition({
  session,
  descriptor
}: {
  session: Session
  descriptor: CollectionEncryption
}): RosterPosition {
  const keyId = session.profile.userKey?.id
  const epochIds = (descriptor.epochs ?? []).map(epoch => epoch.id)
  const currentIndex = descriptor.currentEpoch
    ? epochIds.indexOf(descriptor.currentEpoch)
    : -1
  const keyIndex = keyId ? epochIds.indexOf(keyId) : -1
  if (currentIndex === -1 || keyIndex === -1) {
    return 'unplaced'
  }
  if (keyIndex === currentIndex) {
    return 'current'
  }
  return keyIndex < currentIndex ? 'behind' : 'ahead'
}

/**
 * The follower adoptions in flight, per session and then per roster epoch.
 * Module state rather than a session member, so the session type carries no
 * flag for it.
 */
const followerAdoptions = new WeakMap<
  Session,
  Map<string, Promise<FollowerAdoptionResult>>
>()

/**
 * The rotating ceremonies of this session's own that are running, as a
 * count per session: while one runs, a follower adoption stands down.
 */
const ownRotations = new WeakMap<Session, number>()

/**
 * Whether a ceremony of this session's own that rotates the user key is
 * running. A follower adoption stands down while one is.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {boolean}
 */
export function ownUserKeyRotationInProgress({
  session
}: {
  session: Session
}): boolean {
  return (ownRotations.get(session) ?? 0) > 0
}

/**
 * Runs a ceremony of this session's own that rotates the user key (client
 * revocation, credential rotation, recovery-code revocation, the forget
 * ceremony), or the account deletion walk, beside which no adoption may
 * move the session either. It marks the rotation as running, waits out any
 * follower adoption already in flight, runs the ceremony, and clears the
 * mark however
 * the ceremony ends.
 *
 * The mark closes the window a join alone leaves open. An adoption that
 * starts after the join may hold a roster read taken before this ceremony
 * rotated, so it would move the session and persist the client-key record
 * onto the older key after the ceremony persisted the newer one. An
 * adoption asked for while the mark is held stands down with no write.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.run {Function}   `() => Promise<T>`, the ceremony
 * @returns {Promise<T>}   what the ceremony returns
 */
export async function withOwnUserKeyRotation<T>({
  session,
  run
}: {
  session: Session
  run: () => Promise<T>
}): Promise<T> {
  ownRotations.set(session, (ownRotations.get(session) ?? 0) + 1)
  try {
    await joinFollowerAdoption({ session })
    return await run()
  } finally {
    const remaining = (ownRotations.get(session) ?? 1) - 1
    if (remaining > 0) {
      ownRotations.set(session, remaining)
    } else {
      ownRotations.delete(session)
    }
  }
}

/**
 * Wraps a ceremony body so each call runs as this session's own user key
 * rotation ({@link withOwnUserKeyRotation}), with the session taken from the
 * call's options. No follower adoption then lands an older key beside the
 * ceremony.
 *
 * @param body {Function}   `(options) => Promise<T>`, the ceremony body
 * @returns {Function}   `(options) => Promise<T>`, the held ceremony
 */
export function heldAsOwnUserKeyRotation<
  Options extends { session: Session },
  T
>(body: (options: Options) => Promise<T>): (options: Options) => Promise<T> {
  return async options =>
    await withOwnUserKeyRotation({
      session: options.session,
      run: () => body(options)
    })
}

/**
 * Waits for every follower adoption in flight on this session to settle,
 * whatever each one's result. {@link withOwnUserKeyRotation} calls it before
 * running a ceremony of this session's own that rotates the user key, so an
 * adoption onto an older key cannot land after the ceremony moved the
 * session onto a newer one. Never rejects.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<void>}
 */
export async function joinFollowerAdoption({
  session
}: {
  session: Session
}): Promise<void> {
  const flights = followerAdoptions.get(session)
  if (!flights || flights.size === 0) {
    return
  }
  await Promise.allSettled([...flights.values()])
}

/**
 * The follower adoption: moves a live session that is behind the user key
 * roster onto the roster's current key, after another client rotated it.
 * Shared by every site that finds the session behind.
 *
 * The caller reads the roster first, after refreshing the account log, and
 * hands the read over. That read did the unwrap: it ran with the key
 * this session holds a roster wrap for (a remembered session's
 * `profile.clientKeyAgreementKey`, a transient one's
 * `standingKeyAgreementKey`) and the visit's epoch pin. Then, in order:
 *
 * 1. It adopts only when the session's key sits BEHIND the roster's current
 *    epoch in the roster's own epoch list. It does not compare against the
 *    epoch pin, since the pin can already be ahead of the session's key (an
 *    in-band adoption saves the pin whatever its re-seal result).
 * 2. The epoch pin advances (forward-only already) and a remembered session
 *    persists the key to its client-key record, in the in-band order. A
 *    failed record write is logged and the session still moves, as at login:
 *    the next login re-reads the roster.
 * 3. The key position is checked again, and the session moves only if it is
 *    still behind. The profile takes the key material
 *    (`holdSessionVaultKeys`) and the storage refetches its descriptors and
 *    rebuilds its ciphers, refusing a collection whose epochs name no
 *    recipient of the new key. Such a collection is recorded as stranded
 *    rather than thrown on, so the rest of the session moves.
 * 4. It makes no registry re-seal. The rotator re-sealed the registry to the
 *    new key already, and a re-seal from the session's old key would fail.
 *
 * The disposal signal is checked before each write and before the session
 * moves: a session torn down mid-adoption (a logout, a forget ceremony about
 * to wipe this browser) writes nothing further. The epoch pin and the
 * client-key record are the writes that would be wrong after teardown. An
 * adoption asked for while a rotating ceremony of this session's own runs
 * ({@link withOwnUserKeyRotation}) stands down at once, so it cannot land an
 * older key after that ceremony's own. One already in flight when the
 * ceremony began runs to its end, since the ceremony waits for it.
 *
 * The visit's epoch pin is checked again before the client-key record
 * write and before the session moves. A pin that has moved past the read (a
 * rotation of this session's persisted a newer key since the read was
 * taken) stands the adoption down, so an older key never overwrites a newer
 * record.
 *
 * Single-flight per session and roster epoch: a second call for the same
 * epoch while one runs joins it, then re-checks the key position rather than
 * assuming the first one moved the session. A joiner never adopts itself.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.read {object}   the fresh roster read
 * @param options.read.descriptor {CollectionEncryption}   the roster
 *   descriptor
 * @param options.read.userKey {UserKey}   the roster's current user key,
 *   unwrapped
 * @param options.read.latestEpochId {string}   the roster's current epoch id
 * @param [options.holdsOwnRotation] {boolean}   the caller is the ceremony
 *   holding this session's own-rotation mark (the account deletion walk's
 *   stale-seal repair), so the mark does not stand this adoption down
 * @returns {Promise<{ adopted: boolean, position: string }>}   whether this
 *   call moved the session, and where the session's key sits against the
 *   read afterward (see {@link userKeyRosterPosition})
 */
export async function adoptFollowerUserKey({
  session,
  read,
  holdsOwnRotation = false
}: {
  session: Session
  read: FollowerRosterRead
  holdsOwnRotation?: boolean
}): Promise<FollowerAdoptionResult> {
  let flights = followerAdoptions.get(session)
  if (!flights) {
    flights = new Map()
    followerAdoptions.set(session, flights)
  }
  // A rotating ceremony of this session's own owns the key while it runs.
  // It waited out every adoption already in flight when it began, so only
  // one starting now must stand down, and this check and the registration
  // below run with no await between them.
  if (!holdsOwnRotation && ownUserKeyRotationInProgress({ session })) {
    return {
      adopted: false,
      position: userKeyRosterPosition({ session, descriptor: read.descriptor })
    }
  }
  const epochId = read.latestEpochId
  const running = flights.get(epochId)
  if (running) {
    await Promise.allSettled([running])
    return {
      adopted: false,
      position: userKeyRosterPosition({ session, descriptor: read.descriptor })
    }
  }
  const run = runFollowerAdoption({ session, read })
  flights.set(epochId, run)
  try {
    return await run
  } finally {
    if (flights.get(epochId) === run) {
      flights.delete(epochId)
    }
  }
}

/**
 * The body of {@link adoptFollowerUserKey}, run once per session and epoch.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.read {object}
 * @param options.read.descriptor {CollectionEncryption}
 * @param options.read.userKey {UserKey}
 * @param options.read.latestEpochId {string}
 * @returns {Promise<{ adopted: boolean, position: string }>}
 */
async function runFollowerAdoption({
  session,
  read: { descriptor, userKey, latestEpochId }
}: {
  session: Session
  read: FollowerRosterRead
}): Promise<FollowerAdoptionResult> {
  const position = userKeyRosterPosition({ session, descriptor })
  if (position !== 'behind') {
    return { adopted: false, position }
  }
  if (userKey.id !== descriptor.currentEpoch || latestEpochId !== userKey.id) {
    throw new Error(
      "The follower adoption was handed a user key that is not the roster's " +
        'current epoch.'
    )
  }
  const accountDid = session.profile.accountPointer?.did
  if (!accountDid) {
    throw new Error(
      'The follower adoption needs an account pointer naming a DID; this ' +
        'session holds none.'
    )
  }
  // A torn-down session writes nothing further.
  const standDown = (): boolean => isSessionDisposed({ session })
  if (standDown()) {
    return { adopted: false, position }
  }
  await session.persistence.epochPins.saveFromDescriptor({
    accountDid,
    epochId: latestEpochId,
    descriptor
  })
  // The read's continuity was checked when it was taken. Another rotation
  // of this session's since (a ceremony that persisted a newer key and then
  // threw before moving the session, or a second adoption holding a later
  // read) has moved the pin past this read. The read's key is then older
  // than the record's, and nothing more may be written from it. The pin
  // still stands while it is absent, or at or before the read's current
  // epoch in the read's epoch order: the test `readUserKeyRoster` applies
  // when the read is taken, applied again later.
  const epochIds = (descriptor.epochs ?? []).map(epoch => epoch.id)
  const pinStands = async (): Promise<boolean> =>
    epochPinWriteAllowed({
      stored: await session.persistence.epochPins.load({ accountDid }),
      epochId: latestEpochId,
      epochIds
    })
  // Checked again right before the client-key record write: the pin write
  // let other work of this session run.
  if (
    !(await pinStands()) ||
    standDown() ||
    userKeyRosterPosition({ session, descriptor }) !== 'behind'
  ) {
    return {
      adopted: false,
      position: userKeyRosterPosition({ session, descriptor })
    }
  }
  try {
    await session.profile.persistClientKeys?.({ userKey })
  } catch (err) {
    log.warn(
      'Could not persist the adopted user key; this session moves onto it and the next login adopts it again',
      { err }
    )
  }
  // The awaits above let another stage of this session run. Move the
  // session only if its key is still the one this adoption found behind.
  const pinStillStands = await pinStands()
  const recheck = userKeyRosterPosition({ session, descriptor })
  if (recheck !== 'behind' || !pinStillStands || standDown()) {
    return { adopted: false, position: recheck }
  }
  holdSessionVaultKeys({ session, userKey })
  await session.storage.refreshEncryptedDescriptors()
  return { adopted: true, position: 'current' }
}
