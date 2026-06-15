/**
 * Helpers for classifying errors thrown by the WAS storage client, so the UI
 * can distinguish "the storage server could not be reached" from ordinary
 * application errors and show an appropriate on-screen message.
 */
import { WasError, WasServerError } from '@interop/was-client'

/**
 * Returns true when the given error indicates the remote WAS storage server
 * could not be reached or is failing -- i.e. a network/CORS failure (the fetch
 * never returned a usable response, so `WasError.status` is undefined) or a 5xx
 * server fault. Used to offer the user a guest-mode fallback at login time.
 *
 * @param err {unknown}   the caught error
 * @returns {boolean}
 */
export function isStorageUnreachable(err: unknown): boolean {
  if (err instanceof WasServerError) {
    return true
  }
  // A base WasError with no HTTP status means the request never reached the
  // server (network failure, CORS block, DNS error, connection refused).
  return err instanceof WasError && err.status === undefined
}
