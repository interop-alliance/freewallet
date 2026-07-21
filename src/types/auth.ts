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
import type { IZcap } from '@interop/data-integrity-core'
import type { KeystoreAgent } from '@interop/webkms-client'
import type { DidWebKeyMap } from '@/lib/didWeb'
import type { WebvhUpdateKey, WebvhStagedKey } from '@/lib/didWebvh'

/**
 * Minimal interface over @interop/webkms-client's CapabilityAgent.
 */
export interface ICapabilityAgent {
  id: string
  handle: string
  getSigner: () => ISigner
  // Returns the underlying Ed25519 verification key descriptor (with
  // `controller` set to the agent's did:key id), used to derive the X25519
  // key agreement key for encrypted storage.
  getVerificationKeyPair: () => {
    type: string
    controller: string
    publicKeyMultibase: string
    privateKeyMultibase?: string
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
  keyAgent?: ICapabilityAgent
  zcapClient: ZcapClient
  // X25519 key agreement key, derived deterministically from the passphrase
  // (the Montgomery form of the Ed25519 signing key). Used to encrypt/decrypt
  // the EDV-over-WAS `private-credentials` collection.
  keyAgreementKey?: IKeyAgreementKey
  // Resolves `keyAgreementKey.id` to its public form during encrypt.
  keyResolver?: IKeyResolver
  // WebKMS keystore agent, bound to the user's keystore on the configured
  // KMS server (KMS_SERVER_URL). Absent for guests, when no KMS server is
  // configured, or when keystore provisioning failed at login.
  keystoreAgent?: KeystoreAgent
  // The user's published did:web DID and its key-id map, present once
  // provisioning has succeeded. Absent for guests, without a KMS/WAS server,
  // or when provisioning failed.
  didWeb?: { did: string; keys: DidWebKeyMap }
  // The user's published did:webvh DID and its update-key refs (Phase 2),
  // present once the log has been published. Key refs only, never secrets.
  // Absent when the did:webvh flag is off, without a KMS/WAS server, or when
  // provisioning failed -- everything degrades to did:web behavior.
  didWebvh?: {
    did: string
    updateKey: WebvhUpdateKey
    stagedKey: WebvhStagedKey
  }
  // The 32-byte data seed behind `keyAgent`, held in memory so Settings can
  // re-bind the passphrase (keyring v2). Never persisted.
  dataSeed?: Uint8Array
  // Which unlock method produced this session, and the management zcap it
  // delegated to the data identity at bind time. In-memory only, never
  // persisted: it lets Settings backfill the unlock-methods registry
  // (recording the passphrase entry's unlock Space and its management
  // capability) without re-prompting for the secret.
  unlockMethod?: {
    type: 'passphrase' | 'passkey'
    unlockSpaceId: string
    manageCapability?: IZcap
  }
}

/**
 * Router location state passed between the auth pages (login / signup) to
 * surface a one-shot banner message: either an i18n key or a literal string.
 */
export type AuthLocationState = {
  authMessageKey?: string
  userMessage?: string
}

/**
 * Full in-memory session for a logged-in user. Holds identity (user),
 * cryptographic credentials (profile), and the active storage backend
 * (storage). Discarded on page refresh -- a refresh logs the user out.
 */
export interface Session {
  user: User
  profile: ControllerProfile
  storage: StorageManager
  // Resolves once the session's collections have been provisioned/opened by
  // the session-creation seam (`initSessionFromSeed`). It is fired -- not awaited
  // -- inside session creation, so hot post-login reads (the CHAPI popup's
  // credential list) can run concurrently with provisioning; callers that need
  // provisioning finished `await session.storageReady`. Absent on the
  // new-wallet flows (signup, guest), whose provisioning is owned by
  // `provisionNewWallet` in a deliberate order.
  storageReady?: Promise<void>
  expires?: string // ISO date string, matches Auth.js convention
  isGuest: boolean
}
