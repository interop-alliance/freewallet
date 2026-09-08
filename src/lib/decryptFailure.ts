/**
 * The one classifier over a failed envelope decrypt. Every store that reads
 * encrypted rows sorts a decrypt failure into the same three buckets, and each
 * bucket has its own handling: an unknown-epoch row is skipped uncached and
 * drives a descriptor refresh, a row this wallet holds no epoch key for is
 * skipped but is real data no refresh can reach, and anything else is
 * purgeable garbage.
 */
import { isKeyUnwrapError, isUnknownEpochError } from '@interop/was-client/sync'

export type DecryptFailure = 'unknown-epoch' | 'no-epoch-key' | 'undecryptable'

/**
 * Sorts one decrypt failure into its bucket. The verdict is decided by the
 * error's NAME rather than by `instanceof`, since a wallet whose
 * `@interop/was-client` resolves to a second copy throws a class the store
 * never imported (both predicates are name-based for that reason).
 *
 * @param err {unknown}   the error a `cipher.decrypt` call threw
 * @returns {DecryptFailure}
 */
export function classifyDecryptFailure(err: unknown): DecryptFailure {
  if (isUnknownEpochError(err)) {
    return 'unknown-epoch'
  }
  if (isKeyUnwrapError(err)) {
    return 'no-epoch-key'
  }
  return 'undecryptable'
}
