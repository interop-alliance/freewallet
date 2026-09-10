/**
 * Client revocation: disconnecting an enrolled wallet client from the
 * account. The cascade itself -- document edit, user key rotation, collection
 * fan-out, the generation-delegation re-mint, in that dependency order, with
 * its convergence story -- is `revokeAccountClient` in
 * `@interop/wallet-core/clients`, run once for every wallet. This module
 * supplies the freewallet-shaped stages around it: the session
 * preconditions, the recovery registry's latent commitment hashes, the
 * collections source (the standard encrypted set plus the remotely listed
 * app-provisioned ones), the generation-delegation re-mint (an annex entry
 * replacing the embedded delegation when the revoked client's key signed
 * it), the adoption side effects (epoch pin, client-key record,
 * unlock-methods re-wrap, live vault keys and storage ciphers), and the
 * audit record.
 *
 * It runs on both account-ceremony kinds. On the ENROLLED kind the removal
 * entry is signed by this client's own did:webvh update keys and every
 * request root-invokes, which is the path this module has always taken. On
 * the LADDER kind (a transient session on a standing unlock credential) the
 * entry is signed by a rung of that credential's ladder through the record's
 * bridge delegation, the licensed convergence append by its ladder VM, and
 * every request is invoked by the per-visit annex key under the generation
 * delegation. That branch has no self to refuse and no last client to
 * refuse: the account simply lands ladder-anchored, the shape a
 * credential-anchored signup produces.
 *
 * Two refusals run before the ladder branch writes anything, both of them
 * the last-client transition's: a registry this session cannot read, and a
 * pending-shaped passphrase entry. The second is what the first exists for,
 * since the check is computed from the registry. Neither branch re-seals an
 * unlock record: every record's frame proof, bridge, and sibling delegation
 * are signed by its own credential's unlock identity and ladder VM, which
 * this entry does not strike.
 *
 * The honest limitation is unchanged: ciphertext the revoked client already
 * fetched stays readable to it, and old epochs open to the keys it already
 * held.
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import {
  clientSigningKeyMultibase,
  type PublishedKeyDocument,
  type RevokedClientKeys
} from '@interop/wallet-core/webvh'
import { revokeAccountClient } from '@interop/wallet-core/clients'
import type { GenerationDelegationRemint } from '@interop/wallet-core/clients'
import {
  errorNameOf,
  type MendReport,
  type MendReportEntry
} from '@interop/wallet-core/menders'
import type { Session } from '@/types/auth'
import type { FreewalletCeremonyId } from '@/session/ceremonies'
import {
  clientAnnexReachFor,
  ensureGenerationDelegation,
  renewTransientGenerationDelegation
} from '@/session/annexReach'
import { getUnlockMethods } from '@/session/unlockMethods'
import type { UnlockMethodsRecord } from '@/session/unlockMethods'
import {
  accountCeremonyContext,
  type AccountCeremonyContext
} from '@/session/accountCeremonyContext'
import { assertNoPendingPassphraseEntry } from '@/session/forget'
import {
  adoptRotatedUserKey,
  adoptRotatedUserKeyInBand
} from '@/session/userKeyAdoption'
import { recoveryEntriesOf } from '@/session/recovery'
import {
  cascadeCollections,
  type UserKeyCascadeResult
} from '@/session/userKeyCascade'
import {
  invalidateVerifiedLog,
  reprimeVerifiedAccountLog
} from '@/session/verifiedLog'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:revocation')

export type { RevokedClientKeys } from '@interop/wallet-core/webvh'

/**
 * What a completed revocation cascade reports: whether the roster actually
 * rotated on this run (a naive re-run of an already-complete revocation
 * reports `false` everywhere), the per-collection outcomes, and the
 * ceremony-tail mend report -- one entry, the generation delegation's: the
 * enrolled branch's post-entry re-mint stage, or the ladder branch's
 * pre-entry replacement. The entry carries no registration, so the caller
 * reports it (`reportCeremonyTail`).
 */
export interface RevocationOutcome {
  rotated: boolean
  collections: UserKeyCascadeResult
  mended: MendReport<FreewalletCeremonyId>
}

/**
 * The cascade's one ceremony-tail mend entry: what this run's generation
 * delegation stage made of `generation-delegation-is-current`. A renewal
 * reports `clean`, a delegation the stage found healthy `noop`, a stage that
 * could not run `refused` with its reason, and a caught failure `failed`
 * with the error's class name (never its message, which may carry a DID or a
 * Space id).
 *
 * @param remint {object}   the stage's report -- the enrolled branch's
 *   re-mint or the ladder branch's pre-entry replacement -- carrying the
 *   error class name this module's own catch recorded
 * @returns {MendReportEntry<FreewalletCeremonyId>}
 */
function generationDelegationEntry(
  remint: GenerationDelegationRemint & { errorName?: string }
): MendReportEntry<FreewalletCeremonyId> {
  const reported = {
    invariant: 'generation-delegation-is-current',
    ceremonies: ['client-revocation']
  } as const
  if (remint.skipped === 'failed') {
    return {
      ...reported,
      outcome: 'failed',
      ...(remint.errorName ? { errorName: remint.errorName } : {})
    }
  }
  if (remint.skipped) {
    return {
      ...reported,
      outcome: 'refused',
      detail: { reason: remint.skipped }
    }
  }
  return { ...reported, outcome: remint.renewed ? 'clean' : 'noop' }
}

/**
 * The account's unlock-methods registry, read once for the whole cascade
 * (the document edit's latent commitments), on the ENROLLED kind.
 * Best-effort there: an unreadable registry degrades the edit's attribution
 * rather than failing the revocation. The ladder kind reads it as a
 * precondition instead, since its pre-pivot refusal is computed from it.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<UnlockMethodsRecord | null>}
 */
async function unlockRegistry({
  session
}: {
  session: Session
}): Promise<UnlockMethodsRecord | null> {
  try {
    return await getUnlockMethods({ session })
  } catch (err) {
    log.warn(
      'Could not read the unlock-methods registry for the revocation edit',
      { err }
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
 * @param [options.context] {AccountCeremonyContext}   this session's ceremony
 *   context, when the caller already resolved one; resolved here otherwise
 * @param [options.label] {string}   a display label for the history record
 * @returns {Promise<RevocationOutcome>}
 */
export async function revokeEnrolledClient({
  session,
  context: supplied,
  client,
  label
}: {
  session: Session
  context?: AccountCeremonyContext | null
  client: RevokedClientKeys
  label?: string
}): Promise<RevocationOutcome> {
  const context =
    supplied !== undefined
      ? supplied
      : await accountCeremonyContext({ session })
  if (!context) {
    throw new Error(
      'Disconnecting a wallet needs an account on a storage server, reached ' +
        'either from a connected browser or with a standing passphrase or ' +
        'passkey; this session holds neither.'
    )
  }
  const { remoteStore, pointer } = context
  const ladder = context.kind === 'ladder'
  // One registry read for the whole cascade: the latent commitment hashes the
  // document edit needs. It is independent of the epoch pin read, so the two
  // round trips run together. On the ladder branch the read is a
  // precondition rather than a convenience: the pre-pivot refusal below is
  // computed from it, and a walk over a registry this session could not read
  // would miss exactly the state that makes the removal entry unsafe.
  const { epochPins } = session.profile.persistence
  const [registryRecord, pinnedEpochId] = await Promise.all([
    ladder
      ? getUnlockMethods({ session }).catch((err: unknown) => {
          throw new Error(
            'Could not read the unlock-methods registry, which disconnecting ' +
              'from this session needs in order to check the account is safe ' +
              'to disconnect from; try again.',
            { cause: err }
          )
        })
      : unlockRegistry({ session }),
    epochPins.load({ accountDid: pointer.did })
  ])
  if (ladder) {
    // The last-client transition's pre-pivot refusal, run on every
    // ladder-branch disconnect. A pending-shaped passphrase entry is the
    // residue of a change torn before its retirement landed, and the in-band
    // registry re-seal at the tail would rewrite that half-retired entry.
    // It is mended by the torn-retirement repair at that credential's own
    // next login rather than by anything here.
    await assertNoPendingPassphraseEntry({
      session,
      pointer,
      registry: registryRecord,
      signer: context.ladderDeleter
    })
  }
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
  // What this branch's own pre-entry replacement made of
  // `generation-delegation-is-current`. The cascade below runs no re-mint
  // stage on the ladder branch, so this stage is what the ceremony-tail
  // entry reports there.
  let ladderRenewal:
    (GenerationDelegationRemint & { errorName?: string }) | undefined
  if (ladder) {
    // The rule for a struck signer: the removal entry takes the revoked
    // client's account key out of the document, and on an account whose
    // generation was minted by that client it is what signed the generation
    // delegation this visit's every request rides. The replacement is signed
    // by the acting credential's ladder VM, which stands throughout, and is
    // adopted into the live session before the entry lands. A delegation the
    // policy leaves standing costs one read.
    const invoked = session.profile.invocationCapability?.id
    try {
      const replacement = await renewTransientGenerationDelegation({
        session,
        retiringKeyMultibases: [client.signingKeyMultibase]
      })
      // The renewal resolves with the delegation the generation now embeds:
      // an id this visit was not already invoking is one it minted, the id it
      // was invoking is one the policy left standing, and `null` is a
      // replacement it did not install -- a session pointing at no annex
      // generation, or a renewal that failed inside (it logs its own reason
      // there rather than throwing).
      if (replacement) {
        ladderRenewal = { renewed: replacement.id !== invoked }
      } else if ('clientAnnex' in session.profile.persistence) {
        ladderRenewal = { renewed: false, skipped: 'failed' }
      } else {
        ladderRenewal = { renewed: false, skipped: 'no-pointer' }
      }
    } catch (err) {
      ladderRenewal = {
        renewed: false,
        skipped: 'failed',
        errorName: errorNameOf(err)
      }
      log.warn(
        'Could not replace the generation delegation before the removal ' +
          "entry; the visit may lose its authority when the revoked client's " +
          'key leaves the document',
        { err }
      )
    }
  }
  const result = await revokeAccountClient({
    idStore: context.idStore,
    signer: context.signer,
    revokedClient: client,
    // The post-removal did:web projection, PUT immediately BEFORE the
    // removal entry. A ladder-signed entry writes `did.jsonl` alone (the
    // bridge delegation is a PUT on exactly that resource), so without this
    // the served `id/did.json` would keep naming the client the log has
    // struck -- a revocation bypass for a did:web verifier, though WAS
    // authorization reads the log and never the projection. The store is
    // aimed at the capability held at call time, since the renewal above may
    // have replaced it.
    ...(context.kind === 'ladder'
      ? { projectionStore: context.projectionStore }
      : {}),
    // The cascade's own did.jsonl read must resolve to the account the
    // session's pointer names.
    expectedDid: pointer.did,
    // The standing recovery codes' update-key hashes, so the document edit can
    // tell the revoked client's staged commitment apart from a latent recovery
    // commitment (the one ambiguous log shape).
    knownLatentHashes: await Promise.all(
      latentMultibases.map(multibase => deriveNextKeyHash(multibase))
    ),
    // The self refusal is a property of the acting signer, so it is stated
    // only on the enrolled branch. A ladder rung has no self to refuse, and
    // the last enrolled client is removable there too: the account lands
    // ladder-anchored.
    ...(context.kind === 'enrolled'
      ? {
          ownSigningKeyMultibase: clientSigningKeyMultibase({
            keyAgent: context.keyAgent
          })
        }
      : {}),
    // The log-governed roster store, handed over unwrapped: the orchestrator
    // sets its controller floor from the document edit's own post-edit log
    // before any roster-side work, so the rotation and the sealing append
    // anchor at the post-edit head no matter what view the memo still serves.
    // The memo invalidation above (and in the `.finally`) is for the other
    // session surfaces, which must not read the revoked client as still
    // listed.
    rosterStore: context.rosterStore,
    ...(session.profile.userKey ? { userKey: session.profile.userKey } : {}),
    // Who unwraps each epoch to re-wrap it: this client's own key-agreement
    // key when one is enrolled here, the acting credential's standing key on
    // the ladder branch, which its wrap in every epoch is what makes usable.
    clientKeyAgreementKey:
      context.kind === 'enrolled'
        ? context.clientKeyAgreementKey
        : context.standingKeyAgreementKey,
    pinnedEpochId,
    onUserKeyAdopted: async ({ userKey, latestEpochId, descriptor }) =>
      // The in-band adoption: the registry is re-sealed to the rotated key
      // BEFORE this browser's stored copy of the old one dies, so a tab
      // death during the collection fan-out below cannot strand it.
      await adoptRotatedUserKeyInBand({
        session,
        spaceId: pointer.spaceId,
        accountDid: pointer.did,
        userKey,
        latestEpochId,
        descriptor
      }),
    collections: cascadeCollections({
      remoteStore,
      storeFor: context.collectionStore
    }),
    // No unlock record is re-sealed on either branch: every record's frame
    // proof, bridge, and sibling delegation are signed by its OWN
    // credential's unlock identity and ladder VM, which this entry does not
    // strike. Only the generation delegation is re-minted, and only on the
    // enrolled branch; the ladder branch replaced it above, before the entry
    // rather than after it.
    ...(context.kind === 'enrolled'
      ? {
          remintGenerationDelegation: async ({
            document
          }: {
            document: PublishedKeyDocument
          }) => await remintGenerationDelegation({ session, document })
        }
      : {}),
    // The re-seal retry. On the ordinary path the in-band callback above
    // already re-sealed and swapped, and this returns on its id guard. It
    // does real work in exactly one case: an in-band re-seal that failed
    // left the session on the pre-rotation keys, and this retries the
    // re-seal from them before swapping.
    onRotationAdopted: async ({ userKey }) =>
      await adoptRotatedUserKey({
        session,
        spaceId: pointer.spaceId,
        userKey
      })
  }).finally(() => invalidateVerifiedLog({ profile: session.profile }))

  if (ladder) {
    // Nothing else on a transient session re-settles the verified-log memo,
    // and the listing that reloads next would otherwise re-fetch anyway.
    await reprimeVerifiedAccountLog({ profile: session.profile, pointer })
  }

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
    log.warn('Could not record the client-revocation activity', { err })
  }

  // The ladder branch passes no re-mint closure (it replaced the delegation
  // before the removal entry instead), so the cascade reports no stage there
  // and the pre-entry replacement's own report stands in its place. The
  // fallback, neither branch reporting a stage, is an account with no annex
  // generation to renew.
  const remint: GenerationDelegationRemint & { errorName?: string } =
    result.generation ??
      ladderRenewal ?? { renewed: false, skipped: 'no-pointer' }
  return {
    rotated: result.rotated,
    collections: result.collections,
    mended: [generationDelegationEntry(remint)]
  }
}

/**
 * The cascade's generation-delegation re-mint stage: when the revoked
 * enrolled client is the one whose key signed the current generation's
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
 * @returns {Promise<GenerationDelegationRemint & { errorName?: string }>}
 *   the stage's report, carrying the caught error's class name so the
 *   cascade's mend entry can report it
 */
async function remintGenerationDelegation({
  session,
  document
}: {
  session: Session
  document: PublishedKeyDocument
}): Promise<GenerationDelegationRemint & { errorName?: string }> {
  try {
    const pointer = session.profile.accountPointer
    const reach =
      pointer === undefined
        ? null
        : clientAnnexReachFor({
            session,
            pointer,
            doc: document as Parameters<typeof clientAnnexReachFor>[0]['doc']
          })
    if (!pointer || reach === null) {
      return { renewed: false, skipped: 'no-pointer' }
    }
    const ladderSeed = session.profile.ladderSeed
    if (ladderSeed === undefined) {
      return { renewed: false, skipped: 'no-ladder-seed' }
    }
    const { renewed } = await ensureGenerationDelegation({
      session,
      pointer,
      reach,
      ladderSeed,
      accountDoc: document
    })
    return { renewed }
  } catch (err) {
    log.warn(
      'Could not re-mint the generation delegation after the revocation; the next login retries',
      { err }
    )
    return {
      renewed: false,
      skipped: 'failed',
      errorName: errorNameOf(err)
    }
  }
}
