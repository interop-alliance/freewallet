/**
 * The browser-local binding over `@interop/was-sync`'s writer-id mint: an
 * unkeyed, clearable, unrecoverable attribution label saying which writing
 * agent produced a revision. Its only jobs are history attribution and
 * breaking last-write-wins ties. It lives in `localStorage`, dies with a
 * wallet reset, and is deliberately not derived from any secret -- it is never
 * an identity.
 *
 * The package owns the mint and its clear; this module supplies the two things
 * that are this app's: the storage key prefix and the storage itself.
 */

import {
  clearPersistedWriterId,
  getWriterId,
  type WriterIdStorage
} from '@interop/was-sync'

/**
 * The one place the key prefix is written. The persisted key is
 * `freewallet:writerId`, and the no-unlock-material wipe grade enumerates
 * `localStorage` keys by this prefix, so every clear site must agree with it.
 */
const STORAGE_KEY_PREFIX = 'freewallet:'

/**
 * This browser's `localStorage`, or a stand-in that answers nothing where
 * there is none (a non-DOM test environment). The mint then produces a fresh
 * id per call and remembers nothing.
 *
 * @returns {WriterIdStorage}
 */
function writerIdStorage(): WriterIdStorage {
  if (typeof localStorage === 'undefined') {
    return {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {}
    }
  }
  return localStorage
}

/**
 * Returns this browser's writer id, minting and persisting it on first access.
 *
 * @returns {string}
 */
export function getOrCreateWriterId(): string {
  return getWriterId({
    storageKeyPrefix: STORAGE_KEY_PREFIX,
    storage: writerIdStorage()
  })
}

/**
 * Deletes the persisted writer id; the next browser-local use mints a fresh
 * one. Consumed by the forget grade of the shared wipe enumeration: the id is
 * account-agnostic and never an identity, but it is still a browser-local
 * "this wallet wrote here" trace, so forgetting a browser clears it.
 *
 * @returns {void}
 */
export function clearWriterId(): void {
  clearPersistedWriterId({
    storageKeyPrefix: STORAGE_KEY_PREFIX,
    storage: writerIdStorage()
  })
}
