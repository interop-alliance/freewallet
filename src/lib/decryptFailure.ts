/**
 * The one classifier over a failed envelope decrypt. Every store that reads
 * encrypted Resources sorts an unreadable Resource into the same five buckets,
 * and each bucket has its own handling: an unknown-epoch Resource is skipped
 * uncached and drives a descriptor refresh, a Resource this wallet holds no
 * epoch key for is skipped but is real data no refresh can reach, a Resource
 * that fails its integrity check is skipped and never collected, a plaintext
 * body in an encrypted collection is skipped and never collected, and
 * anything else is purgeable garbage.
 *
 * The integrity bucket narrows what is left in the purgeable one. A Resource
 * sealed under a KAK this wallet holds no key for raises `KeyUnwrapError`, and
 * a body that fails to authenticate or was served under an id it was not sealed
 * for raises `IntegrityError`, so `undecryptable` now names structural garbage
 * alone: an envelope that will not parse or decode at all. `IntegrityError`
 * has a third source, the key epoch rather than the body: a descriptor
 * recipient entry whose `kid` is this wallet's own key id but whose wrapped
 * epoch key fails its AES-KW check, raised at the first decrypt under that
 * epoch, or restated by the refusing cipher a build-time failure leaves. A
 * malformed entry still raises `KeyUnwrapError`.
 */
import {
  isIntegrityError,
  isKeyUnwrapError,
  isUnknownEpochError
} from '@interop/pws-client/sync'

/**
 * The bucket an unreadable Resource of an encrypted collection lands in.
 * `plaintext` names a body that is not an envelope at all, so no decrypt was
 * attempted. The stores assign it before calling the cipher, and
 * `classifyDecryptFailure` never returns it. Like `integrity`, it is never
 * purged: nothing about such a body says it is garbage.
 */
export type DecryptFailure =
  'unknown-epoch' | 'no-epoch-key' | 'integrity' | 'plaintext' | 'undecryptable'

/**
 * Sorts one decrypt failure into its bucket. The verdict is decided by the
 * error's NAME rather than by `instanceof`, since a wallet whose
 * `@interop/pws-client` resolves to a second copy throws a class the store
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
