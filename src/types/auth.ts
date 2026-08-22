/**
 * Core session and identity types. Session is the single source of truth for
 * who is logged in; it lives in-memory only (authStore.ts) and is discarded on
 * page refresh -- the passphrase is never persisted.
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
import type {
  ClientWebvhUpdateKeys,
  DidWebKeyMap
} from '@interop/wallet-core/webvh'
import type { UserKey } from '@interop/wallet-core/keys'
import type { StandingUnlockClient } from '@interop/wallet-core/unlock'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type { PersistableClientKeys } from '@/session/keyring'
import type { ClientAnnexGcReport } from '@interop/wallet-core/clientAnnex'
import type { UserKeyCascadeResult } from '@/session/userKeyCascade'
import type { VerifiedLogCache } from '@/session/verifiedLog'
import type { SessionPersistence } from '@/session/persistence'

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
 * Wallet user -- compatible with Auth.js / next-auth. `id` is a did:key DID.
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
  // X25519 key agreement key used to encrypt/decrypt the EDV-over-WAS
  // encrypted collections (recipient zero of every key-epoch roster): the
  // user key's KAK when the account carries one, else the legacy seed-derived
  // vault KAK (the Montgomery form of the Ed25519 signing key).
  keyAgreementKey?: IKeyAgreementKey
  // Resolves `keyAgreementKey.id` to its public form during encrypt.
  keyResolver?: IKeyResolver
  // This client's own (identity) X25519 key-agreement key -- the Montgomery
  // twin of the client's Ed25519 did:key pair, kept distinct from the
  // user-key-backed `keyAgreementKey` above. It is the client's entry in the user key
  // wrap-set roster (`key-map/user-key.jsonl`): rotation wraps the fresh user key to it,
  // and a roster read unwraps with it.
  clientKeyAgreementKey?: IKeyAgreementKey
  // WebKMS keystore agent, bound to the user's keystore on the configured
  // KMS server (KMS_SERVER_URL). Absent for guests, when no KMS server is
  // configured, or when keystore provisioning failed at login.
  keystoreAgent?: KeystoreAgent
  // The user's published did:web DID and its key-id map, present once
  // provisioning has succeeded. Absent for guests, without a KMS/WAS server,
  // or when provisioning failed.
  didWeb?: { did: string; keys: DidWebKeyMap }
  // The user's published did:webvh DID, present once the log has been
  // published. The update keys behind the log are client-held
  // (`clientWebvhKeys` below), so the profile carries only the id. Absent
  // when the did:webvh flag is off, without a WAS server, or when
  // provisioning failed -- everything degrades to did:web behavior.
  didWebvh?: { did: string }
  // This client's did:webvh update-key seeds (active + staged), recovered
  // from the local client-key record at login or minted at signup. Held in
  // memory for the session so provisioning can extend the log and Settings
  // can self-rotate; never persisted unwrapped (at rest they live only in
  // the wrapped client-key record).
  clientWebvhKeys?: ClientWebvhUpdateKeys
  // Re-wraps this client's client-key record with changed members (a rotated
  // user key, rolled update-key seeds) without re-prompting for the unlock
  // secret: a closure over the unlock identity that produced this session
  // (login) or the freshest bind (signup). In-memory only, same trust class
  // as `clientSeed` above. Absent for guests and not-enrolled states.
  persistClientKeys?: (changes: PersistableClientKeys) => Promise<void>
  // The 32-byte client seed behind `keyAgent` -- this client's locally minted
  // key set, never derived from any shared secret -- held in memory so
  // Settings can re-bind unlock methods (keyring v2). Never persisted
  // unwrapped (at rest it lives only in the wrapped client-key record).
  clientSeed?: Uint8Array
  // The account controller the keyring record was bound under -- the FIRST
  // client's did:key, which every keyring/recovery record carries and every
  // unlock-Space management zcap is delegated to. On the first client it
  // equals `user.id`; on an enrolled (second) client it differs. Stamped from
  // the keyring hit at login; flows that mint further unlock records (a
  // recovery-code issuance) carry it forward so any client can issue.
  accountController?: string
  // The account pointer { did, spaceId, host } this client holds as local
  // state (recovered from the keyring record at login, or stamped at
  // provisioning). Discovery only; absent for guests and no-WAS sessions.
  accountPointer?: AccountPointer
  // The per-user key (user key) recovered from the local client-key record (or
  // freshly minted at provisioning), held in memory so bind flows can carry
  // it into new client-key records. Absent on legacy accounts minted before
  // the user key, whose recipient zero stays the seed-derived vault KAK until they
  // are re-provisioned. Never persisted unwrapped.
  userKey?: UserKey
  // Which unlock method produced this session -- or, after a same-session
  // passphrase change, the freshest passphrase bind -- and the management
  // zcap it delegated to the data identity at bind time. In-memory only,
  // never persisted: it lets Settings backfill the unlock-methods registry
  // (recording the passphrase entry's unlock Space and its management
  // capability) without re-prompting for the secret.
  unlockMethod?: {
    type: 'passphrase' | 'passkey'
    unlockSpaceId: string
    manageCapability?: IZcap
  }
  // The login credential's ladder seed, from its unlock record's standing
  // members. Client annex log entries are signed by the credential's static
  // rung 0 (derived from this seed and the generation id), so the ceremonies
  // that write the annex mid-session -- the revocation cascade's
  // generation-delegation re-mint and the rotation's strike-or-swap -- read
  // it from here. In-memory only, same trust class as `clientSeed`; absent
  // for guests and for records without standing authority.
  ladderSeed?: Uint8Array
  // The login credential's other standing members, stamped from the keyring
  // hit beside `ladderSeed`: the pre-minted PUT-on-`did.jsonl` bridge
  // delegation (and the annex-Space sibling where the record carries one),
  // the credential-derived client identity that invokes them, the
  // credential's unlock Space id (its registry key), and the hit's record
  // re-bind closure (re-wraps and re-PUTs the unlock record with fresh
  // bridge and sibling delegations, everything else restated verbatim). The
  // forget ceremony signs its ladder-signed removal entry through these
  // without re-prompting for the secret, and the last-client transition
  // re-binds the record through the closure before its removal entry.
  // In-memory only, same trust class as `clientSeed`; absent for guests and
  // for records without standing authority.
  standingUnlock?: {
    delegation: IZcap
    delegatedClients?: IZcap
    standingClient: StandingUnlockClient
    unlockSpaceId: string
    rebindRecord?: (options: {
      delegation: IZcap
      delegatedClients?: IZcap
    }) => Promise<void>
  }
  // The invocation capability the session's WAS requests ride, when the
  // session's authority over the data Space is a delegated Space-subtree
  // zcap rather than the root capability -- the transient session's
  // generation delegation. Absent for durable sessions, whose invocations
  // root on the Space controller. In-memory only, never persisted.
  invocationCapability?: IZcap
  // The session-lifetime memo of this account's locally verified did:webvh
  // log (`src/session/verifiedLog.ts`): one verification per session instead
  // of one per surface, keyed on the account pointer and invalidated by every
  // ceremony that extends the log. Created on first use; absent until then,
  // and on sessions that never read the log (guests, no-WAS).
  verifiedLog?: VerifiedLogCache
  // The typed persistence handle chosen at login (`src/session/persistence.ts`):
  // every durability-sensitive local write -- the continuity pins, the
  // descriptor/meta caches, the writer id -- travels through it, so a write's
  // durability is a property of the handle's type, never a flag a write site
  // consults. The durable variant alone reaches the `freewallet-session`
  // database (it carries the `idb` factory); the transient variant is
  // in-memory throughout and dies with the tab.
  persistence: SessionPersistence
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
  // The cascade-completion sweep fired by session creation when the login's
  // roster read succeeded and a remote store is attached: re-runs the
  // collection fan-out of the user key cascade (staleness detected from durable
  // state alone), so a cascade another client crashed partway completes on
  // the next login. Chained behind `storageReady`, strictly best-effort --
  // resolves `null` when the sweep itself failed (never rejects) -- and
  // absent when there was nothing to sweep from (guest, no WAS, no roster).
  userKeySweep?: Promise<UserKeyCascadeResult | null>
  // The app-key sweep fired by session creation: deletes app keys stranded in
  // `private-credentials` by a version that stored them there, now that they
  // live in `app-connections`. Chained behind `storageReady`, strictly
  // best-effort -- resolves the counts of private rows deleted and orphaned
  // public copies retracted, or `null` when the sweep itself failed (it never
  // rejects) -- and absent on the flows that own their own provisioning.
  appKeySweep?: Promise<{ deleted: number; retracted: number } | null>
  // The annex GC sweep fired by the keyring logins: the quarterly
  // generation swap (when due and the pointed generation is GC-quiet) plus
  // the collect fan-out over every non-pointed `gen-` collection. Chained
  // behind `storageReady` (durable sessions only), strictly best-effort --
  // resolves wallet-core's per-pass report, or `null` when the session
  // cannot run it or the pass itself failed (it never rejects).
  clientAnnexGcSweep?: Promise<ClientAnnexGcReport | null>
  // Set when the login's roster read adopted a rotated user key (or advanced
  // the epoch pin) but the durable local copy -- the client-key record or the
  // epoch pin -- could not be written. The session itself is fine (it runs on
  // the freshly adopted key, and the next login re-fetches it); the login
  // page surfaces it as "this browser could not be remembered".
  userKeyPersistFailed?: boolean
  expires?: string // ISO date string, matches Auth.js convention
  isGuest: boolean
}
