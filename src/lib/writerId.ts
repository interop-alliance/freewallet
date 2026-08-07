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
