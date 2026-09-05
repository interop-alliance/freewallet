/**
 * Helpers for classifying errors thrown by the WAS storage client, so the UI
 * can distinguish "the storage server could not be reached" from ordinary
 * application errors and show an appropriate on-screen message.
 */
import {
  PreconditionFailedError,
  WasError,
  WasServerError
} from '@interop/was-client'

/**
 * Returns true when the given error indicates the remote WAS storage server
 * could not be reached or is failing -- i.e. a network/CORS failure (the fetch
 * never returned a usable response, so `WasError.status` is undefined) or a 5xx
 * server fault. Used to offer the user a guest-mode fallback at login time.
 *
 * Some call sites (e.g. `WASRemoteStore.ensureUserCollections`) rethrow the
 * underlying `WasError` wrapped in a plain `Error` with the original as
 * `cause`, so the `cause` chain is walked (with a depth/cycle guard) before
 * classifying.
 *
 * @param err {unknown}   the caught error
 * @returns {boolean}
 */
export function isStorageUnreachable(err: unknown): boolean {
  const seen = new Set<unknown>()
  let current: unknown = err
  // Walk the `cause` chain so a WasError wrapped in a plain Error is still
  // classified. The depth cap and `seen` set guard against runaway or cyclic
  // chains.
  for (let depth = 0; depth < 16 && current != null; depth++) {
    if (seen.has(current)) {
      break
    }
    seen.add(current)
    if (current instanceof WasServerError) {
      return true
    }
    // A base WasError with no HTTP status means the request never reached the
    // server (network failure, CORS block, DNS error, connection refused).
    if (current instanceof WasError && current.status === undefined) {
      return true
    }
    current = current instanceof Error ? current.cause : undefined
  }
  return false
}

/**
 * Whether `err` is the compare-and-swap conflict a conditional PUT raises
 * (`PreconditionFailedError`, 412). Matched by `name` as well as
 * `instanceof`: in a dependency tree that resolves was-client twice the class
 * object differs, and an `instanceof`-only check would turn every lost race
 * into a hard failure instead of a rebase.
 *
 * @param err {unknown}   the caught error
 * @returns {boolean}
 */
export function isPreconditionFailed(err: unknown): boolean {
  return (
    err instanceof PreconditionFailedError ||
    (err instanceof Error && err.name === 'PreconditionFailedError')
  )
}
