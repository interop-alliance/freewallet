/**
 * Adopting a rotated per-user key in a live session -- the tail every user key
 * rotation shares (a client disconnected, a recovery code spent or revoked):
 * the remote unlock-methods registry is re-sealed from the old vault keys to
 * the new ones, then the profile's vault keys and the storage ciphers are
 * swapped, so the session that drove the rotation keeps operating without a
 * re-login.
 *
 * Neutral by design: both the revocation cascade and the recovery ceremonies
 * call in here, and the recovery module is itself imported by the revocation
 * one (the delegation re-mint), so a helper living in either would close a
 * cycle.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { userKeyVaultKeys, type UserKey } from '@interop/wallet-core/keys'
import { WAS_SERVER_URL } from '@/app.config'
import type { Session } from '@/types/auth'
import { rewrapUnlockMethodsRecord } from '@/session/unlockMethods'

/**
 * Re-seals the unlock-methods registry from one set of vault keys to another,
 * best-effort: a failure leaves the registry sealed to the old user key, which the
 * next login surfaces as a warning rather than losing the rotation.
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
 * @returns {Promise<void>}
 */
export async function rewrapUnlockRegistryToUserKey({
  storageServerUrl,
  zcapClient,
  spaceId,
  from,
  to
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  from: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  to: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
}): Promise<void> {
  try {
    await rewrapUnlockMethodsRecord({
      storageServerUrl,
      zcapClient,
      spaceId,
      from,
      to
    })
  } catch (err) {
    console.warn(
      'Could not re-wrap the unlock-methods registry to the rotated user key:',
      err
    )
  }
}

/**
 * Adopts a rotated user key in the live session: the unlock-methods registry is
 * re-sealed to it, then the profile vault keys and the storage ciphers are
 * swapped, so this session keeps operating without a re-login.
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
  const { keyAgreementKey, keyResolver } = session.profile
  if (keyAgreementKey && keyResolver && WAS_SERVER_URL) {
    await rewrapUnlockRegistryToUserKey({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: session.profile.zcapClient,
      spaceId,
      from: { keyAgreementKey, keyResolver },
      to: userKeyVaultKeys({ userKey })
    })
  }
  const vaultKeys = userKeyVaultKeys({ userKey })
  session.profile.userKey = userKey
  session.profile.keyAgreementKey = vaultKeys.keyAgreementKey
  session.profile.keyResolver = vaultKeys.keyResolver
  try {
    await session.storage.adoptRotatedVaultKeys(vaultKeys)
  } catch (err) {
    console.warn(
      'Could not rebuild the storage ciphers on the rotated user key; the next ' +
        'login adopts it instead:',
      err
    )
  }
}
