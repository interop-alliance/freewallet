/**
 * Unpartitioned-storage access for the CHAPI popup pages. The popup runs in
 * a third-party iframe, where IndexedDB is partitioned under current
 * browser defaults -- the first-party `freewallet-session` database (this
 * client's key record, the account-pointer and roster-epoch pins) is
 * invisible there, so without help every popup login lands in the
 * not-enrolled state. The Storage Access API's handle extension hands an
 * embedded document its UNPARTITIONED IndexedDB factory after a user
 * gesture, provided the user has interacted with the wallet origin
 * top-level before -- exactly the "open the wallet app and sign in there
 * first" precondition the popup's guidance states. Browsers without the
 * handle extension resolve without a handle, and the popup stays
 * remote-direct in its degraded not-enrolled state rather than erroring.
 */

/**
 * Requests unpartitioned IndexedDB through the Storage Access API handle
 * extension. Must run during a user gesture (the popup's login submit).
 * Resolves `undefined` -- never throws -- when the API or its handle
 * extension is unavailable, or the browser/user denies access; callers fall
 * back to the partitioned default.
 *
 * @returns {Promise<IDBFactory | undefined>}
 */
export async function requestUnpartitionedIdb(): Promise<
  IDBFactory | undefined
> {
  if (typeof document === 'undefined') {
    return undefined
  }
  const doc = document as Document & {
    requestStorageAccess?: (types?: { indexedDB?: boolean }) => Promise<unknown>
  }
  if (typeof doc.requestStorageAccess !== 'function') {
    return undefined
  }
  try {
    const handle = (await doc.requestStorageAccess({ indexedDB: true })) as
      { indexedDB?: IDBFactory } | undefined
    return handle?.indexedDB
  } catch (err) {
    // Denied, unsupported argument shape, or no prior top-level interaction
    // with the wallet origin: all land in the partitioned fallback.
    console.warn('Unpartitioned storage access was not granted:', err)
    return undefined
  }
}
