/**
 * The one classifier over a failed envelope decrypt. Every store that reads
 * encrypted Resources sorts a decrypt failure into the same four buckets, and
 * each bucket has its own handling: an unknown-epoch Resource is skipped
 * uncached and drives a descriptor refresh, a Resource this wallet holds no
 * epoch key for is skipped but is real data no refresh can reach, a Resource
 * that fails its integrity check is skipped and never collected, and anything
 * else is purgeable garbage.
 *
 * The integrity bucket narrows what is left in the purgeable one. A Resource
 * sealed under a KAK this wallet holds no key for raises `KeyUnwrapError`, and
 * a body that fails to authenticate or was served under an id it was not sealed
 * for raises `IntegrityError`, so `undecryptable` now names structural garbage
 * alone: an envelope that will not parse or decode at all.
 */
import {
  isIntegrityError,
  isKeyUnwrapError,
  isUnknownEpochError
} from '@interop/was-client/sync'

export type DecryptFailure =
  'unknown-epoch' | 'no-epoch-key' | 'integrity' | 'undecryptable'

/**
 * Sorts one decrypt failure into its bucket. The verdict is decided by the
 * error's NAME rather than by `instanceof`, since a wallet whose
 * `@interop/was-client` resolves to a second copy throws a class the store
 * never imported (every predicate is name-based for that reason).
 *
 * The integrity check is asked first, so a body that failed to authenticate or
 * that was served under another resource's id can never reach the purgeable
 * bucket by a later predicate's accident.
 *
 * @param err {unknown}   the error a `cipher.decrypt` call threw
 * @returns {DecryptFailure}
 */
export function classifyDecryptFailure(err: unknown): DecryptFailure {
  if (isIntegrityError(err)) {
    return 'integrity'
  }
  if (isUnknownEpochError(err)) {
    return 'unknown-epoch'
  }
  if (isKeyUnwrapError(err)) {
    return 'no-epoch-key'
  }
  return 'undecryptable'
}
