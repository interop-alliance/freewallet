/**
 * The passes both login chains share, plus the promoted-account reads and
 * the single registry read their registrations sit on.
 *
 * Every login-time registry pass rides one registration block, run by the
 * mender runner in registration order and settled on `session.registryReady`
 * (the registry-writing part) and `session.mends` (the whole block). The
 * order is the point: several passes compare-and-swap the same registry
 * entry, and two of them racing would spend the retry budget undoing each
 * other.
 *
 * Four passes run on both compositions, in this order: the stale-seal
 * repair, the torn-retirement repair, the bare-passkey rebuild, and the
 * registry backfill. Each is its own registration, so the runner's one try,
 * warn, and skip discipline covers it: a throwing re-seal warns with its
 * declared `warn` string, reports `failed`, and the block carries on to the
 * backfill. The remembered block adds its own registrations around them (the
 * provisioning seed and the user key sweep ahead, the standing-delegation
 * and ladder-rung refreshes, the pointer heal, the generation-delegation
 * heal, then the app-key sweep, the annex GC and the keystore report); the
 * transient block adds the management-zcap refresh last.
 */
import type { MendOutcome } from '@interop/wallet-core/menders'
import type { UserKeyRosterReadResult } from '@interop/wallet-core/keys'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type { VerifiedAccountLog } from '@interop/wallet-core/clients'
import { isWebvhDid } from '@interop/wallet-core/webvh'
import type { Session } from '@/types/auth'
import { verifiedAccountLog } from '@/session/verifiedLog'
import type { KeyringFetchResult, UnlockCredential } from '@/session/keyring'
import type { AccountCeremonyContext } from '@/session/accountCeremonyContext'
import { repairStaleUnlockRegistrySeal } from '@/session/registryReseal'
import {
  rebuildBarePasskeyEntry,
  repairTornPassphraseRetirement
} from '@/session/pendingRetirement'
import {
  backfillPassphraseUnlockMethod,
  getUnlockMethods,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'

/**
 * The account pointer a registration acts on, read when the registration
 * RUNS rather than when the block was built, so a registration behind the
 * pointer heal sees the pointer that heal wrote. An account still on a
 * did:key resolves `null`, and its registration reports a no-op.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {(AccountPointer & { did: string }) | null}
 */
export function promotedAccountPointer({
  session
}: {
  session: Session
}): (AccountPointer & { did: string }) | null {
  const pointer = session.profile.accountPointer
  if (!pointer || !isWebvhDid(pointer.did)) {
    return null
  }
  return { ...pointer, did: pointer.did }
}

/**
 * The promoted account a registration acts on: the pointer above, plus the
 * account log through the session's verified-log memo (so every registration
 * on one block shares one verification instead of each fetching and
 * re-checking the chain).
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<object | null>}   `{ pointer, verified }`, or `null` on
 *   an unpromoted account
 */
export async function promotedAccountView({
  session
}: {
  session: Session
}): Promise<{
  pointer: AccountPointer & { did: string }
  verified: VerifiedAccountLog
} | null> {
  const pointer = promotedAccountPointer({ session })
  if (!pointer) {
    return null
  }
  const verified = await verifiedAccountLog({ session })
  return { pointer, verified }
}

/**
 * The block's one unlock-methods registry read, shared by the passes that
 * only need to see the record as it stands. `read` resolves the memoised
 * read (and re-throws its refusal, exactly as an un-memoised read would);
 * `invalidate` drops it, which a pass that wrote the registry calls so the
 * passes behind it read the record it left.
 */
export interface BlockRegistryRead {
  read: () => Promise<UnlockMethodsRecord | null>
  invalidate: () => void
}

/**
 * Creates the block's memoised registry read over one live session. The
 * writers behind these passes (the backfill, the standing-delegation
 * refresh) compare-and-swap over their own fresh reads and do not ride this
 * memo, since a compare-and-swap must be seeded by the read it swaps on.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {BlockRegistryRead}
 */
export function blockRegistryRead({
  session
}: {
  session: Session
}): BlockRegistryRead {
  let pending: Promise<UnlockMethodsRecord | null> | undefined
  return {
    read: () => {
      if (!pending) {
        pending = getUnlockMethods({ session })
        // A refused read (a stale seal) is the re-seal pass's own signal,
        // and it is awaited there. Marking it handled keeps a memo nobody
        // else reaches out of the unhandled-rejection log.
        pending.catch(() => undefined)
      }
      return pending
    },
    invalidate: () => {
      pending = undefined
    }
  }
}

/**
 * What every shared pass reads. One object per block, built once by the
 * registrations and handed to whichever passes need which members.
 */
export interface SharedRegistryPassOptions {
  session: Session
  /**
   * The login credential's keyring hit.
   */
  found: KeyringFetchResult
  /**
   * The block's account-ceremony context, resolved once for the whole
   * block.
   */
  context: AccountCeremonyContext | null
  /**
   * The block's one registry read.
   */
  registry: BlockRegistryRead
  /**
   * The login's roster read, the stale-seal repair's source of escrowed
   * generations; without one that pass is skipped.
   */
  rosterRead?: UserKeyRosterReadResult
  /**
   * The login credential, for the torn-retirement repair's re-derivation.
   */
  credential?: { secret?: string | Uint8Array; derived?: UnlockCredential }
}

/**
 * The stale-seal repair, first because every writer after it reads the
 * record, and a stale seal would make each warn and skip on a registry this
 * same login can mend.
 *
 * @param options {SharedRegistryPassOptions}
 * @returns {Promise<MendOutcome>}
 */
export async function resealRegistryPass({
  session,
  context,
  registry,
  rosterRead
}: SharedRegistryPassOptions): Promise<MendOutcome> {
  if (!rosterRead) {
    return { outcome: 'noop', detail: { reason: 'no-roster-read' } }
  }
  const repaired = await repairStaleUnlockRegistrySeal({
    session,
    rosterRead,
    context,
    readRegistry: registry.read
  })
  if (repaired === 'ok') {
    return { outcome: 'noop' }
  }
  if (repaired === 'repaired') {
    // The record the passes behind this one read is the re-sealed one.
    registry.invalidate()
    return { outcome: 'clean' }
  }
  return {
    outcome: repaired === 'unrepaired' ? 'partial' : 'failed',
    detail: { reason: repaired }
  }
}

/**
 * The torn-retirement repair: which credential the registry's passphrase
 * entry names, settled before the backfill refreshes fields on whatever it
 * leaves standing.
 *
 * @param options {SharedRegistryPassOptions}
 * @returns {Promise<MendOutcome>}
 */
export async function tornRetirementPass({
  session,
  found,
  context,
  registry,
  credential
}: SharedRegistryPassOptions): Promise<MendOutcome> {
  const repaired = await repairTornPassphraseRetirement({
    session,
    found,
    context,
    readRegistry: registry.read,
    ...(credential ? { credential } : {})
  })
  if (repaired === 'repaired') {
    registry.invalidate()
    return { outcome: 'clean' }
  }
  return { outcome: 'noop' }
}

/**
 * The bare-passkey rebuild, the passkey half of the same question.
 *
 * @param options {SharedRegistryPassOptions}
 * @returns {Promise<MendOutcome>}
 */
export async function barePasskeyPass({
  session,
  found,
  context,
  registry
}: SharedRegistryPassOptions): Promise<MendOutcome> {
  const rebuilt = await rebuildBarePasskeyEntry({
    session,
    found,
    context,
    readRegistry: registry.read
  })
  if (rebuilt === 'repaired') {
    registry.invalidate()
    return { outcome: 'clean' }
  }
  return { outcome: 'noop' }
}

/**
 * The registry backfill, last: it refreshes fields on the entries the two
 * repairs above left standing. Its own compare-and-swap re-reads the
 * registry, so the pass drops the block's memo behind it.
 *
 * @param options {SharedRegistryPassOptions}
 * @returns {Promise<MendOutcome>}
 */
export async function backfillRegistryPass({
  session,
  registry
}: SharedRegistryPassOptions): Promise<MendOutcome> {
  const record = await backfillPassphraseUnlockMethod({ session })
  registry.invalidate()
  // A null return covers two states. A session holding no user key can read
  // no registry at all, which is a refusal; a registry needing no change is a
  // no-op.
  if (record) {
    return { outcome: 'clean' }
  }
  return session.profile.userKey
    ? { outcome: 'noop' }
    : { outcome: 'refused', detail: { reason: 'no-user-key' } }
}
