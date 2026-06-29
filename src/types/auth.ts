/**
 * Core session and identity types. Session is the single source of truth for
 * who is logged in; it lives in-memory only (authStore.ts) and is discarded on
 * page refresh — the passphrase is never persisted.
 *
 * Shape is broadly compatible with Auth.js / next-auth for future portability.
 */
import type { StorageManager } from '@/stores/storageManager'
import type {
  ISigner,
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'

/**
 * Minimal interface over @digitalbazaar/webkms-client's CapabilityAgent.
 */
export interface ICapabilityAgent {
  id: string
  keyName: string
  handle: string
  getSigner: () => ISigner
  // The underlying Ed25519VerificationKey2020 key pair used for invocation
  // signing. Underscore-private on CapabilityAgent, but read directly to derive
  // the X25519 key agreement key (the Montgomery form of this same key).
  _keyPair: {
    publicKeyMultibase?: string
    privateKeyMultibase?: string
    controller?: string
  }
}

/**
 * Wallet user — compatible with Auth.js / next-auth. `id` is a did:key DID.
 */
export interface User {
  id: string
  name?: string
  email?: string
  image?: string
}

/**
 * Cryptographic identity bundle for a logged-in user: the key agent that holds
 * the Ed25519 key pair and the ZCap client that signs HTTP requests with it.
 * In-memory only; never persisted.
 */
export interface ControllerProfile {
  keyAgent: ICapabilityAgent
  zcapClient: ZcapClient
  // X25519 key agreement key, derived deterministically from the passphrase
  // (the Montgomery form of the Ed25519 signing key). Used to encrypt/decrypt
  // the EDV-over-WAS `private-credentials` collection.
  keyAgreementKey: IKeyAgreementKey
  // Resolves `keyAgreementKey.id` to its public form during encrypt.
  keyResolver: IKeyResolver
}

/**
 * Full in-memory session for a logged-in user. Holds identity (user),
 * cryptographic credentials (profile), and the active storage backend
 * (storage). Discarded on page refresh.
 */
export interface Session {
  user: User
  profile: ControllerProfile
  storage: StorageManager
  expires?: string // ISO date string, matches Auth.js convention
  isGuest: boolean
}
