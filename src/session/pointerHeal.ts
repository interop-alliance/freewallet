/**
 * The did:webvh heal: an account whose signup-time backfill never ran (a KMS
 * or WAS hiccup left the pointer naming a did:key) re-attempts the pointer
 * backfill and the controller promotion, behind provisioning -- which is
 * where `ensureDidWebvh` publishes (or adopts) the log and sets
 * `profile.didWebvh`.
 *
 * Signup was once the only site that ran these, so one transient
 * provisioning failure left the account permanently unpromoted: enrollment,
 * recovery codes, and client revocation all refused forever. Best-effort
 * like the signup original, and re-derivable from server-held state, so a
 * failed heal warns and the next login retries.
 */
import { errorNameOf, type MendOutcome } from '@interop/wallet-core/menders'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import { isWebvhDid } from '@interop/wallet-core/webvh'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:registry')

/**
 * One heal pass. The two outcomes it reports are the two predicates it
 * converges: the unlock record's pointer names the account did:webvh, and
 * the data Space's controller is that DID. The keystore promotion the
 * Space-side promotion fires is handed back unawaited, for the block's tail
 * registration to report; awaiting a KMS round trip here would put every
 * `registryReady` awaiter behind it.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.persistAccountPointer] {Function}   the hit's pointer
 *   writer; without one nothing can be healed
 * @param [options.pointer] {AccountPointer}   the pointer the unlock record
 *   served this login, which the backfill rewrites
 * @returns {Promise<object>}   one outcome per predicate (the pointer and
 *   the Space controller), plus the fired keystore promotion where one ran
 */
export async function healAccountPointer({
  session,
  persistAccountPointer,
  pointer: servedPointer
}: {
  session: Session
  persistAccountPointer?: (pointer: AccountPointer) => Promise<void>
  pointer?: AccountPointer
}): Promise<{
  pointer: MendOutcome
  controller: MendOutcome
  keystorePromotion?: Promise<MendOutcome>
}> {
  if (!persistAccountPointer || !servedPointer) {
    return {
      pointer: { outcome: 'noop', detail: { reason: 'no-record-writer' } },
      controller: { outcome: 'noop' }
    }
  }
  if (isWebvhDid(servedPointer.did)) {
    return {
      pointer: { outcome: 'noop' },
      controller: { outcome: 'noop' }
    }
  }
  const did = session.profile.didWebvh?.did
  if (!did || !isWebvhDid(did)) {
    return {
      pointer: { outcome: 'noop', detail: { reason: 'no-account-did' } },
      controller: { outcome: 'noop' }
    }
  }
  const fullPointer = { ...servedPointer, did }
  await persistAccountPointer(fullPointer)
  session.profile.accountPointer = fullPointer
  // Past the persisted pointer the two predicates part ways: the pointer
  // one holds whatever the promotion does, so the promotion's failure is
  // reported against the controller alone rather than against both.
  try {
    const { promoted, keystorePromotion } =
      await session.storage.ensurePromotedController({
        profile: session.profile
      })
    return {
      pointer: { outcome: 'clean' },
      controller: promoted
        ? { outcome: 'clean' }
        : { outcome: 'noop', detail: { reason: 'no-promotion' } },
      ...(keystorePromotion ? { keystorePromotion } : {})
    }
  } catch (err) {
    log.warn(
      'Could not backfill the did:webvh pointer and promote the controller; the next login retries',
      { err }
    )
    return {
      pointer: { outcome: 'clean' },
      controller: { outcome: 'failed', errorName: errorNameOf(err) }
    }
  }
}
