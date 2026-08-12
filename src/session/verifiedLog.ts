/**
 * The session-lifetime verified-log cache: one locally verified `did.jsonl`
 * per session instead of one per surface.
 *
 * Verifying the account log is not a cheap read -- it fetches the
 * world-readable log and re-checks every entry's hash chain, prerotation
 * commitments, and update-key signatures (O(entries) signature checks) -- yet
 * a single login plus a Settings visit asks for it three or four times (the
 * recovery health check, the enrolled-client listing, the Applications
 * surface's signer check), and a label RENAME re-verifies the whole log
 * because the panel reloads its listing afterwards.
 *
 * So the result is memoized on the `ControllerProfile` (the object every
 * session member already shares), keyed on the account pointer it was
 * verified against, and held as the in-flight PROMISE so two surfaces
 * mounting together share one fetch. A rejected verification is not cached:
 * the next caller retries.
 *
 * What makes the memo safe is that its invalidation is explicit and local:
 * the log only changes under a ceremony this client runs (enrollment
 * approval, client revocation, recovery-code issuance / revocation /
 * continuation, update-key rotation, did:webvh provisioning), and every one
 * of those calls `invalidateVerifiedLog` after its durable write. A log
 * another client extends is picked up at the next login, which is the same
 * freshness every other cached account read has. When in doubt, invalidate:
 * an extra verification costs a fetch, a missed one shows a stale document.
 *
 * Ceremonies that verify a log for an account this session is not (the
 * `/recover` page before a session exists, the enrollee's cold-client
 * verify) call `verifyAccountLog` directly -- there is no session profile to
 * cache against, and no ownership of what would invalidate it.
 */
import { verifyAccountLog } from '@interop/wallet-core/webvh'
import type {
  AccountLogPointer,
  VerifiedAccountLog
} from '@interop/wallet-core/clients'
import type { ControllerProfile } from '@/types/auth'
import { accountLogPinStore } from '@/lib/sessionKey'

/**
 * One memoized verification, keyed on the pointer it was verified against.
 */
export interface VerifiedLogCache {
  get: (options: { pointer: AccountLogPointer }) => Promise<VerifiedAccountLog>
  invalidate: () => void
}

/**
 * The cache key: a pointer naming a different DID, Space, or host is a
 * different log, so it must never hit a memo taken against the old one (a
 * signup promoting its controller changes the pointer mid-session).
 *
 * @param options {object}
 * @param options.pointer {AccountLogPointer}
 * @returns {string}
 */
function pointerKey({ pointer }: { pointer: AccountLogPointer }): string {
  return `${pointer.did}|${pointer.spaceId}|${pointer.host}`
}

/**
 * Creates an empty verified-log cache.
 *
 * @returns {VerifiedLogCache}
 */
export function createVerifiedLogCache(): VerifiedLogCache {
  let key: string | undefined
  let pending: Promise<VerifiedAccountLog> | undefined
  return {
    get({ pointer }) {
      const wanted = pointerKey({ pointer })
      if (pending && key === wanted) {
        return pending
      }
      key = wanted
      const verification = verifyAccountLog({
        did: pointer.did,
        spaceId: pointer.spaceId,
        host: pointer.host,
        // The durable account-log chain-head pin: a served log that forks,
        // rolls back, or switches identity against it is refused here, before
        // anything downstream reads the memo.
        pinStore: accountLogPinStore({ spaceId: pointer.spaceId })
      }).catch(err => {
        // A failed verification is never the cached answer: drop it so the
        // next caller re-reads (an unreachable host is transient; a genuinely
        // broken log fails again, loudly, at the same place).
        if (key === wanted) {
          key = undefined
          pending = undefined
        }
        throw err
      })
      pending = verification
      return verification
    },
    invalidate() {
      key = undefined
      pending = undefined
    }
  }
}

/**
 * The account's locally verified did:webvh log, from this session's memo when
 * it holds one for the same pointer, else verified now and memoized.
 *
 * The cache is created on first use rather than at session construction, so
 * every path that builds a `ControllerProfile` (login, signup, guest, the
 * CHAPI popups) gets one without each remembering to install it; a session
 * that never reads the log never allocates one.
 *
 * @param options {object}
 * @param options.profile {ControllerProfile}   the live session's profile
 * @param [options.pointer] {object}   the account pointer to verify against;
 *   defaults to the profile's own
 * @returns {Promise<VerifiedAccountLog>}
 */
export async function verifiedAccountLog({
  profile,
  pointer
}: {
  profile: ControllerProfile
  pointer?: { did?: string; spaceId: string; host: string }
}): Promise<VerifiedAccountLog> {
  const target = pointer ?? profile.accountPointer
  if (!target?.did) {
    throw new Error(
      'Verifying the account log needs an account pointer naming a DID; ' +
        'this session holds none.'
    )
  }
  profile.verifiedLog ??= createVerifiedLogCache()
  return await profile.verifiedLog.get({
    pointer: { did: target.did, spaceId: target.spaceId, host: target.host }
  })
}

/**
 * Drops the memoized verification after a ceremony extended the log. Safe to
 * call on a session that never cached one.
 *
 * @param options {object}
 * @param options.profile {ControllerProfile}
 * @returns {void}
 */
export function invalidateVerifiedLog({
  profile
}: {
  profile: ControllerProfile
}): void {
  profile.verifiedLog?.invalidate()
}
