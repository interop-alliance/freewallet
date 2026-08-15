/**
 * Client revocation: disconnecting an enrolled wallet client from the
 * account. The cascade itself -- document edit, user key rotation, collection
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
import { sessionRosterStore } from '@/session/rosterStore'
import { savePinFromDescriptor, loadUserKeyEpochPin } from '@/lib/sessionKey'
import { getUnlockMethods } from '@/session/unlockMethods'
import type { RecoveryCodeUnlockMethod } from '@/session/unlockMethods'
import { requireEnrolledClientContext } from '@/session/enrolledContext'
import { adoptRotatedUserKey } from '@/session/userKeyAdoption'
import {
  recoveryEntriesOf,
  remintRecoveryDelegations
} from '@/session/recovery'
import {
  cascadeCollections,
  type UserKeyCascadeResult
} from '@/session/userKeyCascade'
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
  collections: UserKeyCascadeResult
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
    return recoveryEntriesOf({
      record: await getUnlockMethods({ session, idb })
    })
  } catch (err) {
    console.warn(
      'Could not read the recovery registry for the revocation edit:',
      err
    )
    return []
  }
}

/**
 * Runs the whole revocation cascade for one enrolled wallet client. Throws
 * before touching anything on a call that must not proceed (self-revocation,
 * missing key material); once the document edit lands, every later stage is
 * best-effort-but-resumable -- a thrown stage leaves durable state a naive
 * re-run (or the login-time completion sweep) converges from. An account with
 * no user key roster yet reports a completed cascade with nothing rotated: the
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
  const {
    remoteStore,
    pointer,
    clientWebvhKeys,
    clientKeyAgreementKey,
    keyAgent
  } = requireEnrolledClientContext({ session, action: 'Client revocation' })
  // One registry read for the whole cascade: the latent commitment hashes the
  // document edit needs, and the entries the delegation re-mint walks. It is
  // independent of the epoch pin read, so the two round trips run together.
  const [entries, pinnedEpochId] = await Promise.all([
    recoveryEntries({ session, idb }),
    loadUserKeyEpochPin({ accountDid: pointer.did, idb })
  ])

  // The cascade opens with a document edit, so nothing may keep reading a
  // memo taken before it. Dropped up front (the edit lands early in the call)
  // and again after, so neither a concurrent surface nor a later one sees the
  // revoked client still listed.
  invalidateVerifiedLog({ profile: session.profile })
  const result = await revokeAccountClient({
    idStore: remoteStore.webvhIdStore(),
    updateKeys: clientWebvhKeys,
    revokedClient: client,
    // The cascade's own did.jsonl read must resolve to the account the
    // session's pointer names.
    expectedDid: pointer.did,
    // The standing recovery codes' update-key hashes, so the document edit can
    // tell the revoked client's staged commitment apart from a latent recovery
    // commitment (the one ambiguous log shape).
    knownLatentHashes: await Promise.all(
      entries.map(entry => deriveNextKeyHash(entry.updateKeyMultibase))
    ),
    ownSigningKeyMultibase: clientSigningKeyMultibase({ keyAgent }),
    // The log-governed roster store resolves its controller view through the
    // session's verified-log memo -- invalidated just above and again by the
    // cascade's own document edit -- so the rotation's log append anchors at
    // the post-edit head: the sealing append.
    rosterStore: sessionRosterStore({ profile: session.profile, idb }),
    ...(session.profile.userKey ? { userKey: session.profile.userKey } : {}),
    clientKeyAgreementKey,
    pinnedEpochId,
    onUserKeyAdopted: async ({ userKey, latestEpochId, descriptor }) => {
      // The user key and the epoch pin persist together: the pin must never advance
      // without the key that authenticated the roster it advanced to.
      await savePinFromDescriptor({
        accountDid: pointer.did,
        epochId: latestEpochId,
        descriptor,
        idb
      })
      await session.profile.persistClientKeys?.({ userKey })
    },
    collections: cascadeCollections({ remoteStore }),
    remintRecoveryDelegations: async ({ document }) =>
      await remintRecoveryDelegations({
        session,
        doc: document as Parameters<typeof remintRecoveryDelegations>[0]['doc'],
        entries,
        idb
      }),
    onRotationAdopted: async ({ userKey }) =>
      await adoptRotatedUserKey({ session, spaceId: pointer.spaceId, userKey })
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
