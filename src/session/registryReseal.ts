/**
 * The login-time re-seal repair: an unlock-methods registry left sealed to a
 * superseded user key generation is re-opened from the roster escrow and
 * re-sealed to the account's current one.
 *
 * The state it mends is a torn rotation. Every ceremony that rotates the user
 * key now re-seals the registry in band, while this browser's durable copy of
 * the pre-rotation key still exists (`adoptRotatedUserKeyInBand`), but a run
 * torn before that -- or one from a client that never had the duty -- leaves
 * the record sealed to a key no login derives any more. Nothing else can open
 * it: the registry is a single-recipient envelope to the vault KAK.
 *
 * What makes the repair possible is the roster's escrow rule: every prior user
 * key generation stays wrapped to each enrolled client's own key-agreement
 * key, so this login's verified roster read carries the superseded key that
 * opens the record. Durable state alone suffices, which is what makes this a
 * repair rather than a re-run -- and it is strictly best-effort: a registry
 * that opens under the current key is one read and no write, and a failure
 * leaves the state exactly as it was for the next login.
 */
import {
  unwrapUserKeyGenerations,
  userKeyVaultKeys,
  type UserKeyRosterReadResult
} from '@interop/wallet-core/keys'
import { isWebvhDid } from '@interop/wallet-core/webvh'
import { WAS_SERVER_URL } from '@/app.config'
import type { Session } from '@/types/auth'
import { isDurableSession } from '@/session/persistence'
import { RecordEnvelopeDecryptError } from '@/session/recordEnvelope'
import {
  getUnlockMethods,
  rewrapUnlockMethodsRecord,
  UnlockRegistryStaleSealError
} from '@/session/unlockMethods'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:reseal')

/**
 * Detects and mends a stale-sealed unlock-methods registry.
 *
 * Runs only for a durable session on a promoted account with a WAS server and
 * a successful login roster read (the escrow's source). Detection is the
 * ordinary read: a `UnlockRegistryStaleSealError` is the stale seal, and every
 * other outcome -- a registry that opened, an absent registry, a version or
 * frame refusal, a network failure -- rethrows or returns untouched.
 *
 * The mend tries each superseded generation the roster escrows, newest first
 * (the likeliest is the one the lost rotation superseded), until the record
 * opens; the successful attempt re-seals it to the current vault keys and PUTs
 * it back. A final read refreshes the local cache from the served record, the
 * way every other registry read does.
 *
 * The two failure modes are kept apart. A generation that does not open the
 * record is the expected outcome for every candidate but one, so the walk
 * moves on; a failure AFTER the record opened (the re-wrap, or the PUT) stops
 * the walk -- the right generation has been found and the mend is one
 * transient error away, so retrying the remaining generations would only
 * report the wrong thing.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.rosterRead {UserKeyRosterReadResult}   this login's verified
 *   roster read
 * @returns {Promise<'ok' | 'repaired' | 'unrepaired' | 'reseal-failed'>}
 *   `ok` when the registry opened (or none exists), `repaired` when a
 *   superseded generation opened it and it was re-sealed, `unrepaired` when
 *   no escrowed generation opened it, `reseal-failed` when one did but the
 *   re-seal write did not land
 */
export async function repairStaleUnlockRegistrySeal({
  session,
  rosterRead
}: {
  session: Session
  rosterRead: UserKeyRosterReadResult
}): Promise<'ok' | 'repaired' | 'unrepaired' | 'reseal-failed'> {
  const pointer = session.profile.accountPointer
  const spaceId = session.storage.spaceId
  const { clientKeyAgreementKey, userKey } = session.profile
  if (
    !WAS_SERVER_URL ||
    !isDurableSession(session.profile.persistence) ||
    !pointer ||
    !isWebvhDid(pointer.did) ||
    !spaceId ||
    !clientKeyAgreementKey ||
    !userKey
  ) {
    return 'ok'
  }
  try {
    await getUnlockMethods({ session })
    return 'ok'
  } catch (err) {
    if (!(err instanceof UnlockRegistryStaleSealError)) {
      throw err
    }
  }

  const to = userKeyVaultKeys({ userKey })
  const generations = await unwrapUserKeyGenerations({
    descriptor: rosterRead.descriptor,
    clientKeyAgreementKey
  })
  // Oldest first from the roster; the superseded generation a lost rotation
  // left the seal on is the newest of them.
  const superseded = generations
    .filter(generation => generation.id !== userKey.id)
    .reverse()
  for (const generation of superseded) {
    try {
      await rewrapUnlockMethodsRecord({
        storageServerUrl: WAS_SERVER_URL,
        zcapClient: session.profile.zcapClient,
        spaceId,
        from: userKeyVaultKeys({ userKey: generation }),
        to
      })
    } catch (err) {
      if (err instanceof RecordEnvelopeDecryptError) {
        // The wrong generation: expected for every candidate but one, so it
        // is not worth a warning. The caller reports the state once the loop
        // runs out. (The same error can also mean a lost CAS race: the first
        // read opened under this generation, the PUT conflicted, and the
        // retry's fresh base is already sealed forward -- a healthy registry
        // then reads as unrepaired here. Inert: the outcome is advisory and
        // Settings re-detects from its own read.)
        continue
      }
      // The record opened under this generation and the re-wrap or the PUT
      // failed. The registry is untouched and still stale-sealed; the next
      // login runs the same repair.
      log.warn(
        'The unlock-methods registry opened under a superseded user key but could not be re-sealed to the current one; the next login retries',
        { err }
      )
      return 'reseal-failed'
    }
    // Refresh the local cache from the record as served, the way an ordinary
    // read does.
    await getUnlockMethods({ session })
    return 'repaired'
  }
  return 'unrepaired'
}
