// import type { IKeyPair } from '@digitalcredentials/ssi'
import { StorageManager } from '@/stores/storageManager'

/**
 * Session and User types broadly compatible with Auth.js / 'next-auth'
 */
export interface User {
  id: string
  name?: string
  email?: string
  image?: string
}

// TODO: Need a better name, ControllerProfile is not quite right
//  it's more of a "bootstrap cryptographic materials"
// In memory only, never persisted
export interface ControllerProfile {
  passphrase?: string
}

export interface Session {
  user: User
  expires?: string // ISO date string, matches Auth.js convention
  profile: ControllerProfile
  storage?: StorageManager
}
