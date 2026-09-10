/**
 * The login-time cascade-completion sweep: the roster stage that converges
 * the user key wrap-set roster onto the account's verified did:webvh
 * document, then the collection fan-out that carries every encrypted
 * collection onto the key that convergence settled on.
 *
 * It is one registration of the remembered login's mender block, reporting
 * two invariants: the roster wraps exactly the document's key set, and every
 * collection epoch names the current user key. Staleness is read from
 * server-held state alone, so a cascade another client crashed partway is
 * completed here and a healthy account writes nothing.
 */
import type { CollectionEncryption } from '@interop/was-client'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { convergeUserKeyRosterToAccount } from '@interop/wallet-core/clients'
import type {
  SealableEncryptionDescriptorStore,
  UserKey,
  UserKeyCascadeResult,
  UserKeyRosterReadResult
} from '@interop/wallet-core/keys'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import { WAS_SERVER_URL } from '@/app.config'
import type { Session } from '@/types/auth'
import type { SessionPersistence } from '@/session/persistence'
import { sessionCollectionStores } from '@/session/collectionLogStore'
import { promotedAccountPointer } from '@/session/registryPasses'
import { adoptRotatedUserKeyInBand } from '@/session/userKeyAdoption'
import { cascadeCollectionsToUserKey } from '@/session/userKeyCascade'

/**
 * The roster stage of the cascade-completion sweep: converges the wrap-set
 * roster onto the account's locally verified did:webvh document, so a
 * revocation torn between its document edit and its roster rotation is
 * finished here rather than leaving the current per-user key wrapped to a
 * client the document no longer keys.
 *
 * When the convergence rotates, the fresh key is read back and adopted the
 * ordinary way -- persisted into this client's client-key record, pinned, and
 * swapped into the live session's vault keys and storage ciphers -- and
 * handed back for the collection fan-out to run against. A healthy account
 * reads the descriptor and writes nothing; a document that cannot be fetched
 * or verified (offline, an unpromoted account) leaves the login's own roster
 * read in place, since the sweep is best-effort by design.
 *
 * The sweep writes through the store instance the login read came through,
 * seeded with that read's validator, so a convergence that rotates or
 * escrows acquires the roster log no second time: on a log-governed store
 * every acquisition is a hash-chain walk with per-entry proof and
 * chain-head-pin verification.
 *
 * @param options {object}
 * @param options.session {Session}   the live session, whose vault keys and
 *   ciphers adopt a rotation
 * @param [options.pointer] {AccountPointer & { did: string }}   the account
 *   pointer, once it names a promoted did:webvh
 * @param options.store {SealableEncryptionDescriptorStore}   the roster store
 *   the login read came through
 * @param options.userKey {UserKey}   the login's current per-user key
 * @param options.read {UserKeyRosterReadResult}   the login's roster read
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) KAK -- its roster entry
 * @param options.persistence {SessionPersistence}   the session's persistence
 *   strategy (the pins ride it)
 * @returns {Promise<object>}   the key and roster descriptor the collection
 *   fan-out should use, whether the convergence rotated the roster or sealed
 *   its log, and how many recipients it found stale or escrowed
 */
async function convergeRosterToDocument({
  session,
  pointer,
  store,
  userKey,
  read,
  clientKeyAgreementKey,
  persistence
}: {
  session: Session
  pointer?: AccountPointer & { did: string }
  store: SealableEncryptionDescriptorStore
  userKey: UserKey
  read: UserKeyRosterReadResult
  clientKeyAgreementKey: IKeyAgreementKey
  persistence: SessionPersistence
}): Promise<{
  userKey: UserKey
  rosterDescriptor: CollectionEncryption
  rotated: boolean
  sealed: boolean
  staleRecipients: number
  escrowedRecipients: number
}> {
  const { keyAgent } = session.profile
  const descriptor = read.descriptor
  if (!pointer || !WAS_SERVER_URL || !keyAgent) {
    return {
      userKey,
      rosterDescriptor: descriptor,
      rotated: false,
      sealed: false,
      staleRecipients: 0,
      escrowedRecipients: 0
    }
  }
  const {
    userKey: convergedUserKey,
    descriptor: convergedDescriptor,
    rotated,
    sealed,
    staleRecipientIds,
    escrowedRecipientIds
  } = await convergeUserKeyRosterToAccount({
    pointer: {
      did: pointer.did,
      spaceId: pointer.spaceId,
      host: pointer.host
    },
    store,
    userKey,
    descriptor,
    ...(read.etag !== undefined ? { etag: read.etag } : {}),
    clientKeyAgreementKey,
    pinnedEpochId: await persistence.epochPins.load({
      accountDid: pointer.did
    }),
    accountLogPinStore: persistence.logPins,
    // Adoption is app-side and in band: the unlock-methods registry is
    // re-sealed to the adopted key first (while this browser's local
    // copy of the pre-rotation one still exists), then the key is
    // persisted for the next login, pinned, and swapped into the live
    // session -- all before the collection fan-out runs against it. A
    // failed re-seal leaves the session on the pre-rotation keys and no
    // backstop runs here (the sweep has no post-ceremony adoption step);
    // the next login's re-seal repair is the mender.
    onUserKeyAdopted: async ({
      userKey: adopted,
      latestEpochId,
      descriptor: read
    }) =>
      await adoptRotatedUserKeyInBand({
        session,
        spaceId: pointer.spaceId,
        accountDid: pointer.did,
        userKey: adopted,
        latestEpochId,
        descriptor: read
      })
  })
  // On a convergence that did not rotate, wallet-core hands back the
  // descriptor this login read rather than the post-escrow one. That is the
  // right input for the fan-out either way: an escrow mints no epoch and
  // adds wraps for OTHER recipients, so the user key generations this
  // client's own key-agreement key unwraps are identical in both.
  return {
    userKey: convergedUserKey,
    rosterDescriptor: convergedDescriptor,
    rotated: rotated ?? false,
    sealed: sealed ?? false,
    staleRecipients: staleRecipientIds?.length ?? 0,
    escrowedRecipients: escrowedRecipientIds?.length ?? 0
  }
}

/**
 * One cascade-completion sweep for a live remembered session: the roster
 * stage first, then the collection fan-out under the key it settled on.
 *
 * The roster stage runs first because a disconnect torn between the document
 * edit and the roster rotation leaves the roster still wrapping the CURRENT
 * key to a recipient the document no longer keys -- server-held and silent,
 * since the disconnected client's document edit will never be re-run.
 * Converging it before the fan-out is what makes the collections below take
 * a key the disconnected client cannot open.
 *
 * The session's ciphers were built before the sweep ran, and the sweep's own
 * adoption deliberately leaves them alone (the collections still carried the
 * pre-rotation epochs then). The descriptors and ciphers are refreshed when
 * the sweep adopted a rotated key, or when the fan-out moved any
 * collection's current epoch, so the rest of the session seals writes under
 * the fresh epoch instead of the retired one.
 *
 * @param options {object}
 * @param options.session {Session}   the live session, whose vault keys and
 *   ciphers adopt a rotation
 * @param options.store {SealableEncryptionDescriptorStore}   the roster store
 *   the login read came through, so the convergence is seeded from that read
 * @param options.userKey {UserKey}   the login's current per-user key
 * @param options.read {UserKeyRosterReadResult}   the login's roster read
 * @returns {Promise<object>}   what the roster convergence did (rotated the
 *   user key, sealed the roster log, escrowed a torn client's wraps, and how
 *   many recipients it found stale), and the fan-out's result
 */
export async function sweepUserKeyToDocument({
  session,
  store,
  userKey,
  read
}: {
  session: Session
  store: SealableEncryptionDescriptorStore
  userKey: UserKey
  read: UserKeyRosterReadResult
}): Promise<{
  rotated: boolean
  sealed: boolean
  staleRecipients: number
  escrowedRecipients: number
  cascade: UserKeyCascadeResult
}> {
  const { profile, storage, persistence } = session
  const pointer = promotedAccountPointer({ session })
  const remoteStore = storage.remoteStore
  const clientKeyAgreementKey = profile.clientKeyAgreementKey
  const { keyAgent } = profile
  if (!remoteStore || !clientKeyAgreementKey || !keyAgent) {
    throw new Error(
      'The cascade-completion sweep needs a remote store, this client key ' +
        'agent, and its key-agreement key; this session holds none.'
    )
  }
  const {
    userKey: sweepUserKey,
    rosterDescriptor,
    rotated: convergenceRotated,
    sealed,
    staleRecipients,
    escrowedRecipients
  } = await convergeRosterToDocument({
    session,
    ...(pointer ? { pointer } : {}),
    store,
    userKey,
    read,
    clientKeyAgreementKey,
    persistence
  })
  const cascade = await cascadeCollectionsToUserKey({
    remoteStore,
    storeFor: sessionCollectionStores({ session, remoteStore, keyAgent }),
    rosterDescriptor,
    clientKeyAgreementKey,
    userKey: sweepUserKey
  })
  const rotated = convergenceRotated || sweepUserKey.id !== userKey.id
  if (
    rotated ||
    Object.values(cascade.outcomes).some(outcome => outcome === 'rotated')
  ) {
    await storage.refreshEncryptedDescriptors()
  }
  return { rotated, sealed, staleRecipients, escrowedRecipients, cascade }
}
