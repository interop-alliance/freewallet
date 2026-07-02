/**
 * First-party storage acquisition for embedded contexts (the CHAPI popup
 * half of refresh-surviving sessions). The wallet's
 * /wallet/get and /wallet/store pages load as a third-party iframe inside
 * the authn.io mediator popup, where the global `indexedDB` is a
 * PARTITIONED bucket -- the session key and delegated zcaps persisted by the
 * top-level wallet are invisible there.
 *
 * Per the 2026-07-02 storage-partitioning experiment: Chrome's Storage
 * Access API "beyond cookies" extension
 * (`document.requestStorageAccess({ indexedDB: true, localStorage: true })`)
 * returns a handle exposing the FIRST-PARTY storage after a user gesture
 * plus the `storage-access` permission (one prompt; the grant persists, and
 * with a prior grant the call also resolves without a gesture, enabling a
 * silent retry on later visits). Firefox and Safari resolve the call like
 * the plain cookies-only form -- no handle -- so this helper reports
 * unavailability there and callers fall back to the passphrase login.
 */

/** The types-bag overload + handle of the SAA "beyond cookies" extension
 * (Chrome 125+); not yet in TypeScript's DOM lib. */
interface StorageAccessHandle {
  indexedDB?: IDBFactory
  localStorage?: Storage
}
type RequestStorageAccessBeyondCookies = (types: {
  indexedDB: boolean
  localStorage: boolean
}) => Promise<StorageAccessHandle | undefined>

/** First-party storage and how it was reached. */
export interface FirstPartyStorage {
  idb: IDBFactory
  via: 'top-level' | 'storage-access-handle'
}

/**
 * Whether this document is embedded in another page (the CHAPI popup shape)
 * rather than top-level.
 *
 * @returns {boolean}
 */
export function isEmbedded(): boolean {
  return window.self !== window.top
}

/**
 * Whether attempting the Storage Access API flow is worthwhile here: an
 * embedded document in a browser that has `requestStorageAccess` at all.
 * (Whether the beyond-cookies handle is supported is only discoverable by
 * calling -- see `requestFirstPartyStorage`.)
 *
 * @returns {boolean}
 */
export function storageAccessAvailable(): boolean {
  return isEmbedded() && typeof document.requestStorageAccess === 'function'
}

/**
 * Returns first-party storage for this origin, or `null` when it cannot be
 * reached from this context. Top-level documents get the global factory
 * directly. Embedded documents go through the Storage Access API
 * beyond-cookies flow -- which prompts the user on first use, so call this
 * from a click handler (with a prior grant it also succeeds without a
 * gesture, making a silent on-mount attempt worthwhile). Returns `null`
 * when the API is missing, the user (or browser) denies, or the browser
 * grants cookies-only access without a storage handle (Firefox/Safari).
 *
 * @returns {Promise<FirstPartyStorage | null>}
 */
export async function requestFirstPartyStorage(): Promise<FirstPartyStorage | null> {
  if (!isEmbedded()) {
    return { idb: indexedDB, via: 'top-level' }
  }
  if (typeof document.requestStorageAccess !== 'function') {
    return null
  }
  try {
    const handle = await (
      document.requestStorageAccess as unknown as RequestStorageAccessBeyondCookies
    )({ indexedDB: true, localStorage: true })
    if (handle?.indexedDB) {
      return { idb: handle.indexedDB, via: 'storage-access-handle' }
    }
  } catch {
    // Denied, or no user gesture and no prior grant -- the caller falls
    // back to offering a button / the passphrase form.
  }
  return null
}
