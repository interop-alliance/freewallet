/**
 * Client revocation: disconnecting an enrolled wallet client from the
 * account. The cascade itself -- document edit, user key rotation, collection
 * fan-out, recovery re-mints, the generation-delegation re-mint, in that
 * dependency order, with its convergence story -- is `revokeAccountClient` in
 * `@interop/wallet-core/clients`, run once for every wallet. This module
 * supplies the freewallet-shaped stages around it: the session
 * preconditions, the recovery registry's latent commitment hashes, the
 * collections source (the standard encrypted set plus the remotely listed
 * app-provisioned ones), the recovery-delegation re-mint, the
 * generation-delegation re-mint (an annex entry replacing the embedded
 * delegation when the revoked client's key signed it), the adoption side
 * effects (epoch pin, client-key record, unlock-methods re-wrap, live vault
 * keys and storage ciphers), and the audit record.
 *
 * The honest ceiling is unchanged: ciphertext the revoked client already
 * fetched stays readable to it, and old epochs open to the keys it already
 * held.
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import { WasClient } from '@interop/was-client'
import {
  clientSigningKeyMultibase,
  type PublishedKeyDocument,
  type RevokedClientKeys
} from '@interop/wallet-core/webvh'
import {
  clientAnnexDidParts,
  clientAnnexLogPinId,
  clientAnnexLogStore,
  delegatedClientsPointer,
  ensureGenerationDelegationCurrent,
  mintGenerationDelegation
} from '@interop/wallet-core/clientAnnex'
import { revokeAccountClient } from '@interop/wallet-core/clients'
import type { GenerationDelegationRemint } from '@interop/wallet-core/clients'
import type { Session } from '@/types/auth'
import { sessionRosterStore } from '@/session/rosterStore'
import { getUnlockMethods } from '@/session/unlockMethods'
import type { UnlockMethodsRecord } from '@/session/unlockMethods'
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
import { assertAccountCeremonyAllowed } from '@/session/persistence'

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
  generation: GenerationDelegationRemint
}

/**
 * The account's recovery-code registry entries, read once for the whole
 * cascade (the document edit's latent commitments, then the delegation
 * re-mint). Best-effort: an unreadable registry degrades both stages rather
 * than failing the revocation.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<RecoveryCodeUnlockMethod[]>}
 */
async function unlockRegistry({
  session
}: {
  session: Session
}): Promise<UnlockMethodsRecord | null> {
  try {
    return await getUnlockMethods({ session })
  } catch (err) {
    console.warn(
      'Could not read the unlock-methods registry for the revocation edit:',
      err
    )
    return null
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
 * @returns {Promise<RevocationOutcome>}
 */
export async function revokeEnrolledClient({
  session,
  client,
  label
}: {
  session: Session
  client: RevokedClientKeys
  label?: string
}): Promise<RevocationOutcome> {
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Disconnecting a wallet client'
  })
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
  const { epochPins } = session.profile.persistence
  const [registryRecord, pinnedEpochId] = await Promise.all([
    unlockRegistry({ session }),
    epochPins.load({ accountDid: pointer.did })
  ])
  const entries = recoveryEntriesOf({ record: registryRecord })
  // The standing passphrase/passkey credentials commit a ladder rung the
  // same way a recovery code commits its update key; both sets are latent
  // hashes the document edit must tell apart from the revoked client's
  // staged commitment. The recorded rung may lag the ladder (self-enrolled
  // logins refresh it best-effort), in which case the edit's attribution
  // fails closed rather than guessing.
  const latentMultibases = [
    ...entries.map(entry => entry.updateKeyMultibase),
    ...(registryRecord?.methods ?? []).flatMap(method =>
      (method.type === 'passphrase' || method.type === 'passkey') &&
      method.updateKeyMultibase
        ? [method.updateKeyMultibase]
        : []
    )
  ]

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
      latentMultibases.map(multibase => deriveNextKeyHash(multibase))
    ),
    ownSigningKeyMultibase: clientSigningKeyMultibase({ keyAgent }),
    // The log-governed roster store, handed over unwrapped: the orchestrator
    // sets its controller floor from the document edit's own post-edit log
    // before any roster-side work, so the rotation and the sealing append
    // anchor at the post-edit head no matter what view the memo still serves.
    // The memo invalidation above (and in the `.finally`) is for the other
    // session surfaces, which must not read the revoked client as still
    // listed.
    rosterStore: sessionRosterStore({ profile: session.profile }),
    ...(session.profile.userKey ? { userKey: session.profile.userKey } : {}),
    clientKeyAgreementKey,
    pinnedEpochId,
    onUserKeyAdopted: async ({ userKey, latestEpochId, descriptor }) => {
      // The user key and the epoch pin persist together: the pin must never advance
      // without the key that authenticated the roster it advanced to.
      await epochPins.saveFromDescriptor({
        accountDid: pointer.did,
        epochId: latestEpochId,
        descriptor
      })
      await session.profile.persistClientKeys?.({ userKey })
    },
    collections: cascadeCollections({ remoteStore }),
    remintRecoveryDelegations: async ({ document }) =>
      await remintRecoveryDelegations({
        session,
        doc: document as Parameters<typeof remintRecoveryDelegations>[0]['doc'],
        registryRecord
      }),
    remintGenerationDelegation: async ({ document }) =>
      await remintGenerationDelegation({ session, document }),
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
    recovery: result.recovery ?? { reminted: 0, skipped: 0 },
    generation: result.generation ?? { renewed: false, skipped: 'no-pointer' }
  }
}

/**
 * The cascade's generation-delegation re-mint stage: when the revoked
 * durable client is the one whose key signed the current generation's
 * embedded delegation, the document edit just rotted it under the
 * current-key-set rule -- silently, mid-generation, with no registry entry
 * tracking it. This closure runs `ensureGenerationDelegationCurrent` with
 * the post-edit document as its signer-death axis: a rotted (or expiring)
 * delegation is replaced by one annex entry, the fresh delegation signed
 * by this session's promoted account key and the entry by the login
 * credential's static annex rung 0. A healthy delegation is one no-op
 * read.
 *
 * Best-effort by the cascade's contract: failures are reported, never
 * thrown, and the login-time generation-delegation self-heal retries from
 * durable state. What stays dead is stated elsewhere: App Connect grants a
 * transient session minted under the old delegation -- mid-generation grant
 * death is a consequence of ordinary disconnects, healed by the app
 * reconnecting.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.document {PublishedKeyDocument}   the post-edit account
 *   document, from the cascade's stage 1
 * @returns {Promise<GenerationDelegationRemint>}
 */
async function remintGenerationDelegation({
  session,
  document
}: {
  session: Session
  document: PublishedKeyDocument
}): Promise<GenerationDelegationRemint> {
  try {
    const pointer = session.profile.accountPointer
    const pointedDid = delegatedClientsPointer({
      doc: document as Parameters<typeof delegatedClientsPointer>[0]['doc']
    })
    if (!pointer || pointedDid === undefined) {
      return { renewed: false, skipped: 'no-pointer' }
    }
    const ladderSeed = session.profile.ladderSeed
    if (ladderSeed === undefined) {
      return { renewed: false, skipped: 'no-ladder-seed' }
    }
    const { spaceId: clientAnnexSpaceId, generationId } = clientAnnexDidParts({
      did: pointedDid
    })
    const was = new WasClient({
      serverUrl: pointer.host,
      zcapClient: session.profile.zcapClient
    })
    const { renewed } = await ensureGenerationDelegationCurrent({
      store: clientAnnexLogStore({
        was,
        spaceId: clientAnnexSpaceId,
        generationId
      }),
      ladderSeed,
      generationId,
      mintGenerationDelegation: async ({ clientAnnexDid }) =>
        mintGenerationDelegation({
          zcapClient: session.profile.zcapClient,
          wasServerUrl: pointer.host,
          spaceId: pointer.spaceId,
          clientAnnexDid
        }),
      expectedDid: pointedDid,
      accountDoc: document,
      pinStore: session.profile.persistence.logPins,
      logId: clientAnnexLogPinId({ spaceId: clientAnnexSpaceId, generationId })
    })
    return { renewed }
  } catch (err) {
    console.warn(
      'Could not re-mint the generation delegation after the revocation; ' +
        'the next login retries:',
      err
    )
    return { renewed: false, skipped: 'failed' }
  }
}
