/**
 * Client revocation: disconnecting an enrolled wallet client from the
 * account. The cascade itself -- document edit, PUK rotation, collection
 * fan-out, recovery re-mints, in that dependency order, with its convergence
 * story -- is `revokeAccountClient` in `@interop/wallet-core/clients`, run
 * once for every wallet. This module supplies the freewallet-shaped stages
 * around it: the session preconditions, the recovery registry's latent
 * commitment hashes, the collections source (the standard encrypted set plus
 * the remotely listed app-provisioned ones), the recovery-delegation re-mint,
 * the adoption side effects (epoch pin, client-key record, unlock-methods
 * re-wrap, live vault keys and storage ciphers), and the audit record.
 *
 * The honest ceiling is unchanged: ciphertext the revoked client already
 * fetched stays readable to it, and old epochs open to the keys it already
 * held.
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import {
  clientSigningKeyMultibase,
  isWebvhDid,
  type RevokedClientKeys
} from '@interop/wallet-core/webvh'
import { pukVaultKeys, type Puk } from '@interop/wallet-core/keys'
import { revokeAccountClient } from '@interop/wallet-core/clients'
import { WAS_SERVER_URL } from '@/app.config'
import type { Session } from '@/types/auth'
import { savePukEpochPin, loadPukEpochPin } from '@/lib/sessionKey'
import {
  getUnlockMethods,
  rewrapUnlockMethodsRecord
} from '@/session/unlockMethods'
import { remintRecoveryDelegations } from '@/session/recovery'
import { cascadeCollections, type PukCascadeResult } from '@/session/pukCascade'

export type { RevokedClientKeys } from '@interop/wallet-core/webvh'

/**
 * What a completed revocation cascade reports: whether the roster actually
 * rotated on this run (a naive re-run of an already-complete revocation
 * reports `false` everywhere), the per-collection outcomes, and the recovery
 * re-mint counts.
 */
export interface RevocationOutcome {
  rotated: boolean
  collections: PukCascadeResult
  recovery: { reminted: number; skipped: number }
}

/**
 * The revocation preconditions, resolved from a live session: a configured
 * WAS server and remote store, a promoted did:webvh account pointer, and
 * this client's own key material. Mirrors the recovery-issuance gate -- an
 * enrolled wallet client holding its key material is what can revoke.
 *
 * @param session {Session}
 * @returns {object}   the resolved pieces
 */
function requireRevocationPreconditions(session: Session) {
  const remoteStore = session.storage.remoteStore
  if (!WAS_SERVER_URL || !remoteStore) {
    throw new Error('Client revocation requires a configured storage server.')
  }
  const { profile } = session
  const pointer = profile.accountPointer
  if (!pointer || !isWebvhDid(pointer.did)) {
    throw new Error(
      'Client revocation requires a promoted did:webvh account; this ' +
        'account has not finished provisioning.'
    )
  }
  if (!profile.clientWebvhKeys) {
    throw new Error(
      "Client revocation requires this client's did:webvh update keys."
    )
  }
  if (!profile.clientKeyAgreementKey) {
    throw new Error(
      "Client revocation requires this client's key-agreement key."
    )
  }
  return {
    remoteStore,
    pointer,
    clientWebvhKeys: profile.clientWebvhKeys,
    clientKeyAgreementKey: profile.clientKeyAgreementKey
  }
}

/**
 * The standing recovery codes' update-key hashes, so the document edit can
 * tell the revoked client's staged commitment apart from a latent recovery
 * commitment (the one ambiguous log shape). Best-effort: an unreadable
 * registry falls back to attribution without them.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<string[]>}
 */
async function latentRecoveryHashes({
  session,
  idb
}: {
  session: Session
  idb?: IDBFactory
}): Promise<string[]> {
  try {
    const record = await getUnlockMethods({ session, idb })
    return await Promise.all(
      (record?.methods ?? [])
        .filter(method => method.type === 'recovery-code')
        .map(method => deriveNextKeyHash(method.updateKeyMultibase))
    )
  } catch (err) {
    console.warn(
      'Could not read the recovery registry for the revocation edit:',
      err
    )
    return []
  }
}

/**
 * Adopts a rotated PUK in the live session: the unlock-methods registry is
 * re-sealed to it, then the profile vault keys and the storage ciphers are
 * swapped, so this session keeps operating without a re-login.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.spaceId {string}
 * @param options.puk {Puk}   the freshly rotated per-user key
 * @returns {Promise<void>}
 */
export async function adoptRotatedPuk({
  session,
  spaceId,
  puk
}: {
  session: Session
  spaceId: string
  puk: Puk
}): Promise<void> {
  const { keyAgreementKey, keyResolver } = session.profile
  if (keyAgreementKey && keyResolver && WAS_SERVER_URL) {
    try {
      await rewrapUnlockMethodsRecord({
        storageServerUrl: WAS_SERVER_URL,
        zcapClient: session.profile.zcapClient,
        spaceId,
        from: { keyAgreementKey, keyResolver },
        to: pukVaultKeys({ puk })
      })
    } catch (err) {
      console.warn(
        'Could not re-wrap the unlock-methods registry to the rotated PUK:',
        err
      )
    }
  }
  const vaultKeys = pukVaultKeys({ puk })
  session.profile.puk = puk
  session.profile.keyAgreementKey = vaultKeys.keyAgreementKey
  session.profile.keyResolver = vaultKeys.keyResolver
  try {
    await session.storage.adoptRotatedVaultKeys(vaultKeys)
  } catch (err) {
    console.warn(
      'Could not rebuild the storage ciphers on the rotated PUK; the next ' +
        'login adopts it instead:',
      err
    )
  }
}

/**
 * Runs the whole revocation cascade for one enrolled wallet client. Throws
 * before touching anything on a call that must not proceed (self-revocation,
 * missing key material); once the document edit lands, every later stage is
 * best-effort-but-resumable -- a thrown stage leaves durable state a naive
 * re-run (or the login-time completion sweep) converges from. An account with
 * no PUK roster yet reports a completed cascade with nothing rotated: the
 * document edit has landed, so the client IS disconnected.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.client {RevokedClientKeys}   the revoked client's public
 *   halves (its two verification-method multibases and its active update key)
 * @param [options.label] {string}   a display label for the history record
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<RevocationOutcome>}
 */
export async function revokeEnrolledClient({
  session,
  client,
  label,
  idb
}: {
  session: Session
  client: RevokedClientKeys
  label?: string
  idb?: IDBFactory
}): Promise<RevocationOutcome> {
  const { remoteStore, pointer, clientWebvhKeys, clientKeyAgreementKey } =
    requireRevocationPreconditions(session)
  const { keyAgent } = session.profile

  const result = await revokeAccountClient({
    idStore: remoteStore.webvhIdStore(),
    updateKeys: clientWebvhKeys,
    revokedClient: client,
    knownLatentHashes: await latentRecoveryHashes({ session, idb }),
    ...(keyAgent
      ? { ownSigningKeyMultibase: clientSigningKeyMultibase({ keyAgent }) }
      : {}),
    rosterStore: remoteStore.pukRosterStore(),
    ...(session.profile.puk ? { puk: session.profile.puk } : {}),
    clientKeyAgreementKey,
    pinnedEpochId: await loadPukEpochPin({ spaceId: pointer.spaceId, idb }),
    onPukAdopted: async ({ puk, latestEpochId, descriptor }) => {
      // The PUK and the epoch pin persist together: the pin must never advance
      // without the key that authenticated the roster it advanced to.
      await savePukEpochPin({
        spaceId: pointer.spaceId,
        epochId: latestEpochId,
        epochIds: (descriptor.epochs ?? []).map(epoch => epoch.id),
        idb
      })
      await session.profile.persistClientKeys?.({ puk })
    },
    collections: cascadeCollections({ remoteStore }),
    remintRecoveryDelegations: async ({ document }) =>
      await remintRecoveryDelegations({
        session,
        doc: document as Parameters<typeof remintRecoveryDelegations>[0]['doc'],
        idb
      }),
    onRotationAdopted: async ({ puk }) =>
      await adoptRotatedPuk({ session, spaceId: pointer.spaceId, puk })
  })

  // The audit record, written after the adoption so it lands under the fresh
  // epoch. Best-effort.
  try {
    await session.storage.addHistoryClientRevoked({
      user: session.user,
      signingKeyMultibase: client.signingKeyMultibase,
      label,
      rotated: Object.values(result.collections.outcomes).filter(
        outcome => outcome === 'rotated'
      ).length,
      failed: result.collections.failed.length
    })
  } catch (err) {
    console.warn('Could not record the client-revocation activity:', err)
  }

  return {
    rotated: result.rotated,
    collections: result.collections,
    recovery: result.recovery ?? { reminted: 0, skipped: 0 }
  }
}
