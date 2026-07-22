import { uuidv7 } from 'uuidv7'

const STORAGE_KEY = 'freewallet:deviceId'

/**
 * Returns this browser's device id, minting and persisting it on first access.
 */
export function getOrCreateDeviceId(): string {
  if (typeof localStorage === 'undefined') {
    return uuidv7()
  }
  const existing = localStorage.getItem(STORAGE_KEY)
  if (existing) {
    return existing
  }
  const deviceId = uuidv7()
  localStorage.setItem(STORAGE_KEY, deviceId)
  return deviceId
}
