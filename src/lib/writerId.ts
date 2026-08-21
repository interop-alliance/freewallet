/**
 * Mints and persists this browser profile's writer id: an unkeyed, clearable,
 * unrecoverable attribution label saying which writing agent produced a
 * revision. Its only jobs are history attribution and breaking last-write-wins
 * ties. It lives in `localStorage`, dies with a wallet reset, and is
 * deliberately not derived from any secret -- it is never an identity.
 */

import { uuidv7 } from 'uuidv7'

const STORAGE_KEY = 'freewallet:writerId'

/**
 * Returns this browser's writer id, minting and persisting it on first access.
 */
export function getOrCreateWriterId(): string {
  if (typeof localStorage === 'undefined') {
    return uuidv7()
  }
  const existing = localStorage.getItem(STORAGE_KEY)
  if (existing) {
    return existing
  }
  const writerId = uuidv7()
  localStorage.setItem(STORAGE_KEY, writerId)
  return writerId
}

/**
 * Deletes the persisted writer id; the next durable use mints a fresh one.
 * Consumed by the forget grade of the shared wipe enumeration: the id is
 * account-agnostic and never an identity, but it is still a durable "this
 * wallet wrote here" trace, so forgetting a browser clears it.
 */
export function clearWriterId(): void {
  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem(STORAGE_KEY)
  }
}
