/**
 * Helpers for classifying errors thrown by the WAS storage client, so the UI
 * can distinguish "the storage server could not be reached" from ordinary
 * application errors and show an appropriate on-screen message.
 *
 * Every was-client class here is matched on its `name` rather than by
 * `instanceof`: in a dependency tree that resolves was-client twice (a
 * linked checkout, or a duplicate through the tree) the class object
 * differs, and an `instanceof` check silently takes the wrong branch. A
 * subclass overrides `name`, so a check that must catch a subtype names
 * every concrete subclass. `src/lib/errorName.test.ts` holds the rule for
 * the whole app.
 */
import { errorNameOf } from '@interop/wallet-core/menders'

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
  // Walk the `cause` chain so a WasError wrapped in a plain Error is still
  // classified.
  for (const current of causeChain(err)) {
    const name = errorNameOf(current)
    if (name === 'WasServerError') {
      return true
    }
    // A base WasError with no HTTP status means the request never reached the
    // server (network failure, CORS block, DNS error, connection refused).
    // The subclasses (a 404, a 412, a pre-request encryption failure) each
    // carry their own name, so only the base class matches here.
    if (
      name === 'WasError' &&
      (current as { status?: number }).status === undefined
    ) {
      return true
    }
  }
  return false
}

/**
 * An error and every `cause` beneath it, outermost first. The depth cap and
 * the `seen` set guard against runaway or cyclic chains, so a classifier can
 * read a wrapped error's whole chain with one loop.
 *
 * @param err {unknown}   the caught error
 * @returns {Generator<unknown>}
 */
export function* causeChain(err: unknown): Generator<unknown> {
  const seen = new Set<unknown>()
  let current: unknown = err
  for (let depth = 0; depth < 16 && current != null; depth++) {
    if (seen.has(current)) {
      return
    }
    seen.add(current)
    yield current
    current = current instanceof Error ? current.cause : undefined
  }
}

/**
 * Whether `err` is the compare-and-swap conflict a conditional PUT raises
 * (`PreconditionFailedError`, 412), or its sync-driver subclass
 * `WasSyncConflictError`. An `instanceof`-only check would turn every lost
 * race into a hard failure instead of a rebase under a duplicated was-client.
 *
 * @param err {unknown}   the caught error
 * @returns {boolean}
 */
export function isPreconditionFailed(err: unknown): boolean {
  const name = errorNameOf(err)
  return name === 'PreconditionFailedError' || name === 'WasSyncConflictError'
}
