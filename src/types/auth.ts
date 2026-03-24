import { StorageManager } from '@/stores/storageManager'
import type { ISigner } from '@digitalcredentials/ssi'
import type { ZcapClient } from '@digitalcredentials/ezcap'

export interface ICapabilityAgent {
  id: string
  keyName: string
  handle: string
  getSigner: () => ISigner
}

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
  keyAgent: ICapabilityAgent
  zcapClient: ZcapClient
}

export interface Session {
  user: User
  profile: ControllerProfile
  storage?: StorageManager
  expires?: string // ISO date string, matches Auth.js convention
}
