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
  type RevokedClientKeys
} from '@interop/wallet-core/webvh'
import { revokeAccountClient } from '@interop/wallet-core/clients'
import type { Session } from '@/types/auth'
import { savePukEpochPin, loadPukEpochPin } from '@/lib/sessionKey'
import { getUnlockMethods } from '@/session/unlockMethods'
import type { RecoveryCodeUnlockMethod } from '@/session/unlockMethods'
import { requireEnrolledClientContext } from '@/session/enrolledContext'
import { adoptRotatedPuk } from '@/session/pukAdoption'
import { remintRecoveryDelegations } from '@/session/recovery'
import { cascadeCollections, type PukCascadeResult } from '@/session/pukCascade'
import { invalidateVerifiedLog } from '@/session/verifiedLog'

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
 * The account's recovery-code registry entries, read once for the whole
 * cascade (the document edit's latent commitments, then the delegation
 * re-mint). Best-effort: an unreadable registry degrades both stages rather
 * than failing the revocation.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<RecoveryCodeUnlockMethod[]>}
 */
async function recoveryEntries({
  session,
  idb
}: {
  session: Session
  idb?: IDBFactory
}): Promise<RecoveryCodeUnlockMethod[]> {
  try {
    const record = await getUnlockMethods({ session, idb })
    return (record?.methods ?? []).filter(
      (method): method is RecoveryCodeUnlockMethod =>
        method.type === 'recovery-code'
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
 * The standing recovery codes' update-key hashes, so the document edit can
 * tell the revoked client's staged commitment apart from a latent recovery
 * commitment (the one ambiguous log shape).
 *
 * @param options {object}
 * @param options.entries {RecoveryCodeUnlockMethod[]}
 * @returns {Promise<string[]>}
 */
async function latentRecoveryHashes({
  entries
}: {
  entries: RecoveryCodeUnlockMethod[]
}): Promise<string[]> {
  return await Promise.all(
    entries.map(entry => deriveNextKeyHash(entry.updateKeyMultibase))
  )
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
    requireEnrolledClientContext({ session, action: 'Client revocation' })
  const { keyAgent } = session.profile
  // One registry read for the whole cascade: the latent commitment hashes the
  // document edit needs, and the entries the delegation re-mint walks.
  const entries = await recoveryEntries({ session, idb })

  // The cascade opens with a document edit, so nothing may keep reading a
  // memo taken before it. Dropped up front (the edit lands early in the call)
  // and again after, so neither a concurrent surface nor a later one sees the
  // revoked client still listed.
  invalidateVerifiedLog({ profile: session.profile })
  const result = await revokeAccountClient({
    idStore: remoteStore.webvhIdStore(),
    updateKeys: clientWebvhKeys,
    revokedClient: client,
    knownLatentHashes: await latentRecoveryHashes({ entries }),
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
        entries,
        idb
      }),
    onRotationAdopted: async ({ puk }) =>
      await adoptRotatedPuk({ session, spaceId: pointer.spaceId, puk })
  }).finally(() => invalidateVerifiedLog({ profile: session.profile }))

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
