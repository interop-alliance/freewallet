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
 *
 * In the `delegated` session tier (a refresh-restored session,
 * `src/session/delegatedSession.ts`) `zcapClient` signs with the browser
 * session key and invokes the persisted delegated zcaps; `keyAgreementKey` /
 * `keyResolver` are present only when the session vault envelope
 * (`src/session/vault.ts`) yielded the vault KAK. The root `keyAgent` always
 * requires a fresh login.
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
  // The keystore id, when known without a keystore agent (the delegated tier
  // restores it from the persisted session record for display).
  keystoreId?: string
  // The delegated `sign` capability on the keystore, restored from the
  // persisted record in the `delegated` tier. Paired with the browser session
  // key, it lets a restored session sign with the KMS-held keys (e.g. DIDAuth)
  // without the passphrase. Absent in the `full` tier (the root key invokes
  // the keystore's root capability directly).
  keystoreCapability?: IZcap
  // The user's published did:web DID and its key-id map, present once
  // provisioning has succeeded (`full` tier) or been restored from the
  // persisted record (`delegated` tier). Absent for guests, without a
  // KMS/WAS server, or when provisioning failed.
  didWeb?: { did: string; keys: DidWebKeyMap }
  // The user's published did:webvh DID and its update-key refs (Phase 2),
  // present once the log has been published (`full` tier) or restored from the
  // persisted record (`delegated` tier). Key refs only, never secrets. Absent
  // when the did:webvh flag is off, without a KMS/WAS server, or when
  // provisioning failed -- everything degrades to did:web behavior.
  didWebvh?: {
    did: string
    updateKey: WebvhUpdateKey
    stagedKey: WebvhStagedKey
  }
  // The 32-byte data seed behind `keyAgent`, held in memory in the `full` tier
  // so Settings can re-bind the passphrase (keyring v2). Never persisted.
  dataSeed?: Uint8Array
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
 * (storage). Discarded on page refresh -- though a `full` session leaves
 * behind delegated zcaps that let `restoreDelegatedSession()` reconstitute
 * a restricted `delegated` session on the next load.
 */
export interface Session {
  user: User
  profile: ControllerProfile
  storage: StorageManager
  expires?: string // ISO date string, matches Auth.js convention
  isGuest: boolean
  // `full`: passphrase-derived root key present (fresh login). `delegated`:
  // restored from persisted zcaps + the browser session key; no root key, and
  // the vault unlocks only if the session vault envelope yielded the KAK
  // (fail closed -- otherwise encrypted collections stay locked until
  // re-login). Gate UI on `storage.vaultLocked`, not on the tier.
  tier: 'full' | 'delegated'
}
