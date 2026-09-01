/**
 * Keyring v2 -- the unlock layer, protecting this client's key set.
 *
 * A freewallet account is no longer a shared data seed. Each client (a
 * browser profile) generates its own key set locally on first run -- a random
 * 32-byte client seed behind an Ed25519 signing pair and its X25519
 * (Montgomery) twin -- and the private halves never leave the client and are
 * never derived from any shared secret. Two identities meet here:
 *
 * - The **client identity** is this client's local root: the Ed25519 key pair
 *   behind its did:key and the X25519 twin. The client also caches the
 *   account's per-user key (user key, the roster identity for encrypted
 *   collections) beside its own keys, under the same unlock layer.
 * - The **unlock identity** is derived from an unlock secret at login -- the
 *   passphrase today; a passkey PRF output or a recovery code are further
 *   methods on the same seam (`unlockSeed = KDF(secret)` per the method's
 *   `UnlockKdf`, then `CapabilityAgent.fromSeed` with a distinct `'unlock'`
 *   handle so it can never collide with the client identity's `'bootstrap'`
 *   derivation). It controls nothing but its own minimal Space. One unlock
 *   method = one unlock identity = one unlock Space; each method's KDF salt
 *   differs, so two methods can never derive the same Space.
 *
 * The unlock layer protects two records per unlock method:
 *
 * - The **unlock record** lives in the unlock identity's own Space
 *   (`keyring/keyring.json`) -- the only placement that is locatable before
 *   the account is known. In the STANDING layout (every credential bound on
 *   a promoted account) it is wallet-core's unlock record: the account core
 *   (controller, email, pointer) sealed to the unlock KAK and authenticated
 *   by a MAC under a credential-derived key the host never holds, beside
 *   the sealed bridge delegation (a pre-minted PUT-on-`did.jsonl` zcap) and
 *   the sealed update-key ladder seed -- which is what lets a fresh browser
 *   holding nothing but the credential self-enroll as an ordinary client.
 *   The reduced (no-WAS) layout stays the plain keyring record: the
 *   pointer, never key material or authority. Both layouts are
 *   SIGNED by the unlock identity's own Ed25519 key. The remote copy is the
 *   source of truth and is consulted first on every login; a **local
 *   cache** in the `freewallet-session` IndexedDB serves no-WAS deployments
 *   and, within `KEYRING_CACHE_TTL_MS`, offline logins.
 * - The **client-key record** lives only in the `freewallet-session`
 *   IndexedDB: this client's key set (the client seed) and its cached copy of
 *   the user key, wrapped to the same unlock KAK. It is primary state, not a cache
 *   -- the private keys exist nowhere else -- so it is deleted only by the
 *   explicit unlock-method lifecycle flows, never on a server answer.
 *
 * **Record authenticity and freshness**: the record's proof is what stops a
 * storage host forging one. Its signing key derives from the unlock secret, so
 * a client that has only ever typed the secret already holds the verification
 * prior, and the host never holds the signing key -- a substituted record is
 * refused (`KeyringRecordForgedError`) before it is decrypted, at first contact
 * as much as at the thousandth. What the signature cannot catch is a REPLAY: a
 * record the account has since moved off is authentic forever, and this
 * wallet keeps no cross-session prior to catch one with
 * (`decisions/0012-no-durable-continuity-pins.md`), so a replayed record is
 * a stated bound: a login can land in an account the user has moved off,
 * visible and reversible by logging in again once the host serves the
 * current record. A pointer that differs from anything this client has seen
 * is simply followed: a rebind, a host migration, or a fresh account under a
 * reused passphrase all produce a newer, validly signed record, and the
 * honest answer to one is to log in.
 *
 * A passphrase change re-wraps both records under a new unlock identity, PUTs
 * the keyring record to the new unlock Space, then deletes the old unlock
 * Space and the old local records -- which is what retires the old passphrase
 * (nothing about the account is derivable from a passphrase, so once its
 * unlock Space is gone the old passphrase resolves to nothing). Because login
 * checks the remote first, other clients see the retirement on their next
 * online login; offline, a stale cache stops answering once its TTL lapses.
 *
 * Account deletion retires the keyring the same way -- it deletes the unlock
 * Space and every local record outright, after the caller has wiped the data
 * Space.
 */
import type { ZcapClient } from '@interop/ezcap'
import { spacePath, toUrl } from '@interop/was-client/paths'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import {
  KEYRING_CACHE_TTL_MS,
  UNLOCK_MANAGE_ZCAP_TTL_MS,
  WAS_SERVER_URL
} from '@/app.config'
import {
  isWebvhDid,
  keyAgreementCommitment,
  type ClientWebvhUpdateKeys
} from '@interop/wallet-core/webvh'
import {
  decodeClientKeyRecord,
  encodeClientKeyRecord,
  type ClientKeyRecord,
  type ClientKeyRecordPending,
  type UserKey
} from '@interop/wallet-core/keys'
import {
  deleteUnlockSpace,
  deriveUnlockIdentity,
  deriveUnlockSeed,
  ensureUnlockSpace,
  getUnlockKeyring,
  putUnlockKeyring,
  unlockIdentityFromSeed,
  unwrapKeyringRecord,
  verifyRecordProof,
  wrapKeyringRecord,
  KEYRING_KDF,
  type AccountPointer,
  type KeyringRecordContents,
  type UnlockIdentity,
  type UnlockKdf
} from '@interop/wallet-core/keyring'
import {
  standingClientFromUnlockSeed,
  unlockKeyVmId,
  unwrapUnlockRecord,
  wrapUnlockRecord,
  type StandingUnlockClient,
  type UnlockRecordProofState
} from '@interop/wallet-core/unlock'
import { currentAccountRecordSigners } from '@interop/wallet-core/clients'
import {
  memoryResourceLogPinStore,
  type ResourceLogPinStore
} from '@interop/vh-resource-log'
import { isStorageUnreachable } from '@/lib/storageErrors'
import {
  unwrapRecordEnvelope,
  wrapRecordEnvelope
} from '@/session/recordEnvelope'
import {
  deleteClientKeyRecord,
  deleteKeyringCache,
  deleteUnlockLocalState,
  loadClientKeyRecord,
  loadKeyringCache,
  saveClientKeyRecord,
  saveKeyringCache
} from '@/lib/sessionKey'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:keyring')

/**
 * The version stamped on the stored `{ version, encryption, wrapped }`
 * client-key envelope (the record seals under its own one-epoch descriptor,
 * see `recordEnvelope.ts`), and the cipher context id its JWE is bound to
 * (distinct from the keyring record's, so the two envelopes can never be
 * swapped for each other).
 */
const CLIENT_KEYS_RECORD_VERSION = 1
const CLIENT_KEYS_CIPHER_ID = 'client-keys'

/*
 * This client's key set, as recovered from the local client-key record, is the
 * shared `ClientKeyRecord`: the random 32-byte client seed behind the client's
 * Ed25519 + X25519 pair, the locally cached user key (absent only on records
 * written for accounts minted before the user key existed), this client's
 * did:webvh update-key seeds (absent on records written before the update keys
 * became client-held), and the account controller the record was bound for
 * (absent on records written before multi-client enrollment; those were
 * necessarily written by the first client, whose own did:key IS the
 * controller). Both wallets encode and validate those contents identically;
 * only the unlock-layer wrap around them is freewallet's.
 */

/**
 * The re-wrappable members of a client-key record -- what a live session may
 * change after login (a roster-rotated user key, rolled did:webvh update-key
 * seeds, the account's did:webvh once known, and a ceremony's pending state).
 * The client seed itself is immutable for the record's lifetime. `pending` is
 * three-valued on the way in: absent leaves the stored member alone, a value
 * replaces it, and `null` clears it -- the ceremony-completion write.
 */
export interface PersistableClientKeys {
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  pointerDid?: string
  pending?: ClientKeyRecordPending | null
}

/**
 * What `fetchKeyring` returns to callers on a hit: the record contents, plus
 * the derived unlock Space id (always -- it is already computed),
 * `clientKeys` when this client holds a key set under the unlock method (an
 * enrolled client; absent on a fresh browser, which can locate the account
 * but not act), and, when `mintManageCapability` was requested and a WAS
 * server is configured, a management zcap the unlock identity delegated to
 * the recovered `controller`. The capability grants GET/DELETE on the unlock
 * Space only, so a later Settings flow can retire this method (a lost
 * passkey) with the session's root key -- no re-derivation from, or tap on,
 * the secret.
 */
export interface KeyringFetchResult extends KeyringRecordContents {
  unlockSpaceId: string
  clientKeys?: ClientKeyRecord
  manageCapability?: IZcap
  // Present beside `clientKeys`: re-wraps the client-key record with changed
  // members (see `PersistableClientKeys`) without the unlock secret -- a
  // closure over the unlock identity that produced this hit. In-memory only.
  persistClientKeys?: (changes: PersistableClientKeys) => Promise<void>
  // Re-wraps and re-PUTs the keyring record with a changed account pointer
  // (and refreshes the local cache) without the unlock secret
  // -- the login-time heal path for a signup whose did:webvh backfill never
  // ran (a KMS hiccup): once a later login's provisioning publishes the log,
  // the pointer can durably adopt the did. In-memory only.
  persistAccountPointer?: (pointer: AccountPointer) => Promise<void>
  // The standing-credential members recovered from an unlock record in the
  // standing layout (absent on a plain keyring record -- the no-WAS reduced
  // path): the pre-minted PUT-on-`did.jsonl` bridge delegation
  // and the update-key ladder seed, both credential-authenticated by the
  // record's binding MAC, plus the optional annex-Space sibling
  // delegation (`delegatedClients`, outside the MAC). What a fresh browser
  // self-enrolls with. In-memory only.
  standing?: {
    delegation: IZcap
    delegatedClients?: IZcap
    ladderSeed?: Uint8Array
  }
  // The credential's own client identity, derived beside the unlock identity
  // from the same unlock seed: the roster wrap target a self-enrollment
  // unwraps the user key with. Set on every real fetch (cheap HKDF
  // expansions); optional only so test doubles need not fabricate one.
  standingClient?: StandingUnlockClient
  // Present when `clientKeys` is absent: persists a freshly self-enrolled
  // client's key set under this unlock identity and returns the
  // `persistClientKeys` closure for the new record. The self-enrollment's
  // persist hook writes the PENDING shape through it (seeds + controller +
  // pointerDid + pending, no userKey) before the add entry publishes, and the
  // post-return completion overwrites it with the enrolled shape. In-memory
  // only.
  enrollClientKeys?: (keys: {
    clientSeed: Uint8Array
    userKey?: UserKey
    webvhUpdateKeys?: ClientWebvhUpdateKeys
    controller: string
    pointerDid?: string
    pending?: ClientKeyRecordPending
  }) => Promise<(changes: PersistableClientKeys) => Promise<void>>
  // Present beside `standing`: re-wraps and re-PUTs this unlock record with a
  // freshly minted bridge delegation (and, when supplied, a fresh
  // annex-Space sibling; an existing sibling is restated verbatim
  // otherwise), restating everything else verbatim
  // (the ladder seed included) -- the login-time expiry refresh of the
  // credential's own delegations, run when one is expired or
  // inside the renewal window. In-memory only.
  rebindStandingRecord?: (options: {
    delegation: IZcap
    delegatedClients?: IZcap
  }) => Promise<void>
  // The credential's own unlock key-agreement key, as the bind paths record
  // it in the registry entry: the key's id and its multibase, each present
  // only when the derived key carries it. In-memory only -- recomputed from
  // the derived unlock identity on every fetch, never stored in the record.
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}

/**
 * An unlock credential's full derived state: the unlock identity (Space
 * addressing, unlock KAK, record signer) and the standing client identity
 * (client seed expansion, roster wrap target, binding MAC key), both expanded
 * from ONE run of the method's KDF over the typed secret. Every unlock-layer
 * entry point derives or accepts this bundle, so the expensive passphrase
 * stretch runs once per typed secret.
 */
export interface UnlockCredential {
  unlock: UnlockIdentity
  standing: StandingUnlockClient
}

/**
 * Derives the full unlock credential for a secret under its method's KDF:
 * one stretch (`deriveUnlockSeed`), two expansions.
 *
 * @param options {object}
 * @param options.secret {string | Uint8Array}   the unlock secret
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @returns {Promise<UnlockCredential>}
 */
export async function deriveUnlockCredential({
  secret,
  kdf
}: {
  secret: string | Uint8Array
  kdf: UnlockKdf
}): Promise<UnlockCredential> {
  const unlockSeed = await deriveUnlockSeed({ secret, kdf })
  const unlock = await unlockIdentityFromSeed({ seed: unlockSeed })
  const standing = await standingClientFromUnlockSeed({ unlockSeed })
  return { unlock, standing }
}

/**
 * The DID an unlock Space's management zcap is delegated to: the account's
 * published did:webvh when the pointer names one, else the account controller
 * did:key. The did:webvh form is what makes the grant invocable by the whole
 * enrolled-client roster under the current-key-set rule -- every enrolled
 * client (including one minted by a later recovery) signs management
 * invocations with its own `<did:webvh>#<multibase>` session key, and a
 * revoked client loses the grant the moment its verification method leaves
 * the document. The did:key fallback covers the unpromoted single-client
 * account, where the account controller IS this client's own key.
 *
 * @param options {object}
 * @param [options.pointer] {AccountPointer}   the account pointer, when known
 * @param options.controller {string}   the account controller did:key
 * @returns {string}
 */
export function unlockManagementGrantee({
  pointer,
  controller
}: {
  pointer?: AccountPointer
  controller: string
}): string {
  return pointer && isWebvhDid(pointer.did) ? pointer.did : controller
}

/**
 * Delegates the long-lived management zcap on an unlock Space to the account
 * identity (see `unlockManagementGrantee`): GET/DELETE on the unlock Space
 * URL by default, expiring after `UNLOCK_MANAGE_ZCAP_TTL_MS`. Pure signing (no
 * server round trip); the chain roots at the Space's synthesized root
 * capability (the ezcap client generates it from the target). Only ever
 * called when a WAS server is configured -- the unlock Space, and thus the
 * capability, exist only then.
 *
 * A standing record's management zcap widens the actions to include PUT --
 * a recovery code's, and a standing passphrase's or passkey's alike. That is
 * what lets the revocation cascade re-PUT the record with a freshly minted
 * bridge delegation when the original's signing client is revoked. A plain
 * keyring record (a pointer with no standing members) keeps the narrow
 * GET/DELETE set. The rule holds at every mint site -- the bind, the
 * per-login mint in `buildFetchResult`, and the rebind -- because the
 * registry stores whichever capability was minted last.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the unlock identity's client (it can
 *   both invoke and delegate)
 * @param options.spaceId {string}   the unlock Space id
 * @param options.controller {string}   the account DID to delegate to (a
 *   promoted account's did:webvh, or the account did:key)
 * @param [options.allowedActions] {string[]}   default `['GET', 'DELETE']`
 * @returns {Promise<IZcap>}
 */
export async function delegateUnlockManagement({
  zcapClient,
  spaceId,
  controller,
  allowedActions = ['GET', 'DELETE']
}: {
  zcapClient: ZcapClient
  spaceId: string
  controller: string
  allowedActions?: string[]
}): Promise<IZcap> {
  // Built with was-client's path helpers rather than by hand: a sub-path
  // deployment (a server URL like `https://host/was`) keeps its base path,
  // so the target matches byte for byte what the DELETE and the GET address.
  const invocationTarget = toUrl({
    serverUrl: WAS_SERVER_URL as string,
    path: spacePath(spaceId)
  })
  return await zcapClient.delegate({
    invocationTarget,
    controller,
    allowedActions,
    expires: new Date(Date.now() + UNLOCK_MANAGE_ZCAP_TTL_MS)
  })
}

/**
 * Wraps this client's key set (+ the cached user key) into a client-key record
 * under the unlock KAK, and saves it to the `freewallet-session` IndexedDB
 * keyed by the unlock Space id.
 *
 * @param options {object}
 * @param options.unlock {UnlockIdentity}
 * @param options.clientSeed {Uint8Array}   the 32-byte client seed
 * @param [options.userKey] {UserKey}   the per-user key, cached beside the client keys
 * @param [options.webvhUpdateKeys] {ClientWebvhUpdateKeys}   this client's
 *   did:webvh update-key seeds, cached beside the client keys
 * @param [options.controller] {string}   the account controller this key set
 *   was bound for -- on an enrolled (non-first) client it differs from the
 *   client's own did:key
 * @param [options.pointerDid] {string}   the account's did:webvh -- the
 *   resume's record-to-account cross-check (routing keys on `userKey`
 *   presence alone)
 * @param [options.pending] {ClientKeyRecordPending}   a mid-flight ceremony's
 *   pending state; a record missing `userKey` classifies pending at login
 *   and routes to the resume rather than the detector
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
async function saveClientKeys({
  unlock,
  clientSeed,
  userKey,
  webvhUpdateKeys,
  controller,
  pointerDid,
  pending,
  idb
}: {
  unlock: UnlockIdentity
  clientSeed: Uint8Array
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  controller?: string
  pointerDid?: string
  pending?: ClientKeyRecordPending
  idb?: IDBFactory
}): Promise<void> {
  const contents = encodeClientKeyRecord({
    clientSeed,
    ...(userKey ? { userKey } : {}),
    ...(webvhUpdateKeys ? { webvhUpdateKeys } : {}),
    ...(controller ? { controller } : {}),
    ...(pointerDid ? { pointerDid } : {}),
    ...(pending ? { pending } : {})
  })
  const record = await wrapRecordEnvelope({
    data: { ...contents },
    version: CLIENT_KEYS_RECORD_VERSION,
    collectionId: CLIENT_KEYS_CIPHER_ID,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver
  })
  await saveClientKeyRecord({ spaceId: unlock.spaceId, record, idb })
}

/**
 * The unlock credential's key-agreement members, spread-ready: the key's id
 * and its multibase, each present only when the derived key carries it. The
 * cast is the one place the unlock identity's untyped key-agreement key is
 * read for these two members, shared by the bind paths and by the registry
 * entry a bare-entry passphrase change rebuilds.
 *
 * @param options {object}
 * @param options.unlock {UnlockIdentity}
 * @returns {{ unlockKeyAgreementKeyId?: string,
 *   unlockKeyAgreementKeyMultibase?: string }}
 */
export function unlockKeyAgreementMembers({
  unlock
}: {
  unlock: UnlockIdentity
}): {
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
} {
  const { id, publicKeyMultibase } = unlock.keyAgreementKey as unknown as {
    id?: string
    publicKeyMultibase?: string
  }
  return {
    ...(id ? { unlockKeyAgreementKeyId: id } : {}),
    ...(publicKeyMultibase
      ? { unlockKeyAgreementKeyMultibase: publicKeyMultibase }
      : {})
  }
}

/**
 * Builds the `persistClientKeys` closure over an unlock identity: loads the
 * current client-key record, merges the changed members, and re-wraps. A
 * missing or unusable record is left alone -- the closure must never
 * manufacture one. Holding the closure keeps the unlock identity's key
 * material in memory for the session; that is deliberate (it is what lets a
 * rotation persist without re-prompting for the secret) and adds no exposure
 * the in-memory client seed did not already carry.
 *
 * The ceremony-completion write is the ONE path that enrolls a pending
 * record: a `userKey` change on a record whose stored `pending` group still
 * stands is dropped unless the same change also clears `pending`
 * (`pending: null`). Without this, an incidental mid-session persist (the
 * login sweep's rotation adoption) would fill the user key on a
 * still-pending record -- it would classify enrolled with a live pending
 * group, the resume would never run again, and the pending carrier (the
 * show-once replacement code included) would be sealed away unreachable.
 *
 * @param options {object}
 * @param options.unlock {UnlockIdentity}
 * @param [options.idb] {IDBFactory}
 * @returns {(changes: PersistableClientKeys) => Promise<void>}
 */
function clientKeysPersister({
  unlock,
  idb
}: {
  unlock: UnlockIdentity
  idb?: IDBFactory
}): (changes: PersistableClientKeys) => Promise<void> {
  return async changes => {
    const clientKeys = await loadClientKeys({ unlock, idb })
    if (!clientKeys) {
      return
    }
    // The completion-only enrollment rule: a userKey fill on a pending
    // record must arrive together with the `pending: null` clear.
    let userKeyChange = changes.userKey
    if (userKeyChange && clientKeys.pending && changes.pending !== null) {
      log.debug(
        'Dropped a userKey persist on a pending client-key record; only the ceremony completion may enroll it',
        { ceremony: clientKeys.pending.ceremony }
      )
      userKeyChange = undefined
    }
    // `pending` is three-valued: absent keeps the stored member, a value
    // replaces it, `null` clears it (the ceremony-completion write).
    const pending =
      changes.pending === null
        ? undefined
        : (changes.pending ?? clientKeys.pending)
    await saveClientKeys({
      unlock,
      clientSeed: clientKeys.clientSeed,
      userKey: userKeyChange ?? clientKeys.userKey,
      webvhUpdateKeys: changes.webvhUpdateKeys ?? clientKeys.webvhUpdateKeys,
      controller: clientKeys.controller,
      pointerDid: changes.pointerDid ?? clientKeys.pointerDid,
      ...(pending ? { pending } : {}),
      idb
    })
  }
}

/**
 * Builds the `persistAccountPointer` closure a fetch result carries: re-wraps
 * the keyring record with a changed account pointer under the same unlock
 * identity, signs it with that identity's record signer, PUTs it (when a WAS
 * server is configured), and refreshes the local cache. The controller and
 * email are restated from
 * the fetched record -- only the pointer changes. This is the login-time
 * counterpart of signup's did:webvh pointer backfill, for accounts whose
 * backfill never ran (a provisioning hiccup at signup).
 *
 * @param options {object}
 * @param options.unlock {UnlockIdentity}
 * @param options.found {KeyringRecordContents}
 * @param [options.idb] {IDBFactory}
 * @returns {(pointer: AccountPointer) => Promise<void>}
 */
function accountPointerPersister({
  unlock,
  found,
  idb
}: {
  unlock: UnlockIdentity
  found: KeyringRecordContents
  idb?: IDBFactory
}): (pointer: AccountPointer) => Promise<void> {
  return async pointer => {
    // Stamped here rather than left to the codec, so the pin advances to the
    // exact timestamp the record carries without re-reading it. Advanced past
    // both the record being rewritten and this client's local pin, so a
    // client whose clock lags behind whichever client bound last still writes
    // a record that supersedes what everyone has pinned.
    const createdAt = nextRecordCreatedAt({ advancePast: [found.createdAt] })
    const record = await wrapKeyringRecord({
      controller: found.controller,
      email: found.email,
      pointer,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      createdAt
    })
    if (WAS_SERVER_URL) {
      await putUnlockKeyring({
        storageServerUrl: WAS_SERVER_URL,
        zcapClient: unlock.zcapClient,
        spaceId: unlock.spaceId,
        record
      })
    }
    await saveKeyringCache({ spaceId: unlock.spaceId, record, idb })
  }
}

/**
 * Loads and unwraps this client's key set for an unlock identity, or
 * `undefined` when this client holds none under it (a browser that has never
 * provisioned or enrolled for the account -- it can locate the account but
 * not act). A record that fails to unwrap or validate is warned about,
 * evicted, and reported as absent: corrupt ciphertext is unrecoverable
 * either way, and login then surfaces the honest "this client is not
 * enrolled" state.
 *
 * @param options {object}
 * @param options.unlock {UnlockIdentity}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<ClientKeyRecord | undefined>}
 */
async function loadClientKeys({
  unlock,
  idb
}: {
  unlock: UnlockIdentity
  idb?: IDBFactory
}): Promise<ClientKeyRecord | undefined> {
  const record = await loadClientKeyRecord({ spaceId: unlock.spaceId, idb })
  if (!record) {
    return undefined
  }
  try {
    return await unwrapClientKeys({ record, unlock })
  } catch (err) {
    log.warn('Discarding an unusable client-key record', { err })
    await deleteClientKeyRecord({ spaceId: unlock.spaceId, idb })
    return undefined
  }
}

/**
 * Unwraps and validates a stored client-key record: validates the
 * `{ version, encryption, wrapped }` frame (a record with no `encryption`
 * descriptor -- the retired direct-to-KAK form -- is refused as unusable),
 * decrypts the payload, and hands the contents to the shared record codec,
 * which throws on any malformed member.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored `{ version, encryption,
 *   wrapped }` envelope
 * @param options.unlock {UnlockIdentity}
 * @returns {Promise<ClientKeyRecord>}
 */
async function unwrapClientKeys({
  record,
  unlock
}: {
  record: unknown
  unlock: UnlockIdentity
}): Promise<ClientKeyRecord> {
  const contents = await unwrapRecordEnvelope({
    record,
    version: CLIENT_KEYS_RECORD_VERSION,
    collectionId: CLIENT_KEYS_CIPHER_ID,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver,
    label: 'client-key'
  })
  return decodeClientKeyRecord({ contents })
}

/**
 * Thrown by `fetchKeyring` when a keyring record was found under the
 * passphrase's unlock Space but could not be unwrapped or validated -- a
 * genuinely corrupt/malformed (or retired version-1) record. Distinct from
 * "no account" (a `null` return; a wrong passphrase resolves to a different
 * unlock Space and misses) and from an unreachable server (a rethrown network
 * error), so callers can surface it with its own recovery guidance.
 */
export class KeyringRecordUnusableError extends Error {
  constructor({ cause }: { cause?: unknown } = {}) {
    const detail = cause instanceof Error ? ` ${cause.message}` : ''
    super(`Unusable keyring record.${detail}`)
    this.name = 'KeyringRecordUnusableError'
    this.cause = cause
  }
}

/**
 * Thrown when a keyring record's Data Integrity proof is absent, malformed, or
 * made by a key other than the one the typed unlock secret derives -- the
 * authenticity refusal: the storage host served a record it forged or tampered
 * with. Distinct from a wrong passphrase (which resolves to a different unlock
 * Space and simply misses) and from `KeyringRecordUnusableError` (a record this
 * client's own account genuinely wrote, but cannot read).
 */
export class KeyringRecordForgedError extends Error {
  constructor({ cause }: { cause?: unknown } = {}) {
    const detail = cause instanceof Error ? ` ${cause.message}` : ''
    super(`Forged or tampered keyring record.${detail}`)
    this.name = 'KeyringRecordForgedError'
    this.cause = cause
  }
}

/**
 * Whether an error came out of wallet-core's record-proof layer. Matched on
 * `name` rather than `instanceof`: the shared package may be linked rather
 * than installed, and a duplicated class identity would silently turn the
 * forgery refusal into a generic unusable-record one.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function isRecordProofError(err: unknown): boolean {
  return (err as Error | null)?.name === 'RecordProofError'
}

/**
 * Maps an unwrap failure onto its typed refusal: a proof failure or a failed
 * credential-authenticated account binding is the host-forgery refusal,
 * anything else is a corrupt/unreadable record. Both matched on `name`
 * rather than `instanceof` (wallet-core may be linked, duplicating class
 * identity).
 *
 * @param err {unknown}
 * @returns {Error}
 */
function keyringUnwrapError(err: unknown): Error {
  return isRecordProofError(err) ||
    (err as Error | null)?.name === 'UnlockBindingError'
    ? new KeyringRecordForgedError({ cause: err })
    : new KeyringRecordUnusableError({ cause: err })
}

/**
 * What a stored record unwraps to, whichever layout it is stored in: the
 * shared pointer-record contents, the standing-credential members when the
 * record is an unlock record in the standing layout, and the record's proof
 * state (`'verified'`, or the pending marker of a cascade-re-minted record
 * whose signer must still be settled against the account document).
 */
interface UnwrappedStoredRecord {
  found: KeyringRecordContents
  standing?: {
    delegation: IZcap
    delegatedClients?: IZcap
    ladderSeed?: Uint8Array
  }
  proofState: UnlockRecordProofState
}

/**
 * Unwraps a stored record under an unlock credential, branching on the
 * record's layout: a frame carrying a `bridge` member is an unlock record in
 * the standing layout (the account core verified under the credential's
 * binding MAC before the pointer is trusted), anything else is a plain
 * keyring record (the pre-promotion or no-WAS reduced path -- a pure
 * pointer, no standing authority). Throws raw codec errors; callers map them
 * through `keyringUnwrapError`.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored record envelope
 * @param options.credential {UnlockCredential}
 * @returns {Promise<UnwrappedStoredRecord>}
 */
async function unwrapStoredKeyringRecord({
  record,
  credential
}: {
  record: unknown
  credential: UnlockCredential
}): Promise<UnwrappedStoredRecord> {
  const { unlock, standing } = credential
  if ((record as { bridge?: unknown } | null)?.bridge !== undefined) {
    const { contents, proofState } = await unwrapUnlockRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase,
      // The account binding is verified inside the unwrap, under the
      // credential-derived MAC key -- the pointer that comes back is
      // credential-authenticated, not merely what the (host-re-encryptable)
      // record claims.
      bindingMacKey: standing.bindingMacKey
    })
    return {
      found: {
        controller: contents.controller,
        email: contents.email,
        pointer: contents.pointer,
        createdAt: contents.createdAt
      },
      standing: {
        delegation: contents.delegation,
        ...(contents.delegatedClients
          ? { delegatedClients: contents.delegatedClients }
          : {}),
        ...(contents.ladderSeed ? { ladderSeed: contents.ladderSeed } : {})
      },
      proofState
    }
  }
  const found = await unwrapKeyringRecord({
    record,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver,
    expectedKeyMultibase: unlock.recordSigner.keyMultibase
  })
  return { found, proofState: 'verified' }
}

/**
 * Settles a pending record proof: a record the credential's own unlock key
 * did not sign is only acceptable when a currently enrolled client of the
 * account the credential-authenticated pointer names signed it -- the
 * revocation cascade's bridge re-mint. The binding was verified in the
 * unwrap, so the document fetched here belongs to the account the credential
 * was bound for, never to one a forging host substituted.
 *
 * Failure classification mirrors the recovery flow's: an unreachable storage
 * server rethrows unchanged (could-not-check must not read as forged), and so
 * does an account-log continuity refusal (its own surface; a `rollback` may
 * be replication lag). Everything else refuses as
 * `KeyringRecordForgedError`.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored record, proof included
 * @param options.proofState {UnlockRecordProofState}
 * @param options.found {KeyringRecordContents}   the unwrapped contents (the
 *   credential-authenticated pointer names the account to check against)
 * @param [options.accountLogPinStore] {ResourceLogPinStore}   the chain-head
 *   pin store the account-log read rides; defaults to the settlement's own
 *   in-memory one.
 * @returns {Promise<void>}
 */
async function settlePendingRecordProof({
  record,
  proofState,
  found,
  accountLogPinStore = memoryResourceLogPinStore()
}: {
  record: unknown
  proofState: UnlockRecordProofState
  found: KeyringRecordContents
  accountLogPinStore?: ResourceLogPinStore
}): Promise<void> {
  if (proofState === 'verified') {
    return
  }
  try {
    const pointer = found.pointer
    if (!pointer || !isWebvhDid(pointer.did)) {
      throw new Error(
        'The record names no did:webvh account, so no document can account ' +
          'for its signer.'
      )
    }
    // The allowlist is the record-signer set (enrolled clients plus the
    // ladder VMs), not the enrolled-client set alone: after the last-client
    // forget every other unlock method's record is re-signed by the ladder
    // VM, the one key the client-less account's document still lists.
    const signingKeys = await currentAccountRecordSigners({
      pointer: {
        did: pointer.did!,
        spaceId: pointer.spaceId,
        host: pointer.host
      },
      accountLogPinStore
    })
    await verifyRecordProof({
      record,
      allowedKeyMultibases: [...signingKeys],
      label: 'unlock'
    })
  } catch (err) {
    if (isStorageUnreachable(err)) {
      throw err
    }
    if ((err as Error | null)?.name === 'ResourceLogContinuityError') {
      throw err
    }
    throw new KeyringRecordForgedError({ cause: err })
  }
}

/**
 * The bind timestamp to stamp on a record this client is about to write: now,
 * advanced to one millisecond past the newest of the given timestamps when one
 * is already at or ahead of now. The advance-past timestamps are what the new
 * record must supersede, chiefly the record it replaces, so a client whose
 * clock lags another's still writes a record that supersedes it. Absent and
 * unparseable entries are ignored.
 *
 * @param options {object}
 * @param options.advancePast {Array<string | null | undefined>}   ISO
 *   timestamps the returned stamp must be strictly newer than
 * @returns {string}
 */
function nextRecordCreatedAt({
  advancePast
}: {
  advancePast: Array<string | null | undefined>
}): string {
  let millis = Date.now()
  for (const prior of advancePast) {
    const parsed = prior ? Date.parse(prior) : Number.NaN
    if (!Number.isNaN(parsed) && parsed >= millis) {
      millis = parsed + 1
    }
  }
  return new Date(millis).toISOString()
}

/**
 * Reads a loaded cache entry: unwraps its record and, on success, assembles
 * the fetch result. On any failure it warns and evicts the unusable cache
 * entry, then returns `null` -- each caller decides what an eviction means
 * (the no-remote path treats it as "no account" and returns null; the offline
 * fallback treats it as "could not check" and rethrows the network error that
 * sent it to the cache).
 *
 * @param options {object}
 * @param options.cached {{ record: unknown }}   the loaded cache entry
 * @param options.credential {UnlockCredential}
 * @param options.mintManageCapability {boolean}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<KeyringFetchResult | null>}
 */
async function readCachedRecord({
  cached,
  credential,
  mintManageCapability,
  idb
}: {
  cached: { record: unknown }
  credential: UnlockCredential
  mintManageCapability: boolean
  idb?: IDBFactory
}): Promise<KeyringFetchResult | null> {
  const { unlock } = credential
  try {
    // A cached record is still a signed record and this client holds the
    // verification key, so it is verified exactly as a remote one is -- the
    // cache is local state a page script could reach, not a trusted origin.
    // A pending proof (a cascade-re-minted record) is settled against the
    // account document like a remote one; offline that settlement fails, so
    // the entry reads as unusable and the caller reports could-not-check.
    const unwrapped = await unwrapStoredKeyringRecord({
      record: cached.record,
      credential
    })
    await settlePendingRecordProof({
      record: cached.record,
      proofState: unwrapped.proofState,
      found: unwrapped.found
    })
    return await buildFetchResult({
      unwrapped,
      credential,
      mintManageCapability,
      idb
    })
  } catch (err) {
    log.warn('Discarding an unusable cached keyring record', { err })
    await deleteKeyringCache({ spaceId: unlock.spaceId, idb })
    return null
  }
}

/**
 * Locates the keyring for an unlock secret. When a WAS server is configured
 * the remote copy is consulted first -- it is the source of truth, and
 * checking it before the cache is what makes a method change (e.g. a
 * passphrase change) on another client take effect here: a found record
 * refreshes the local cache, while a 404-shaped miss (a null record) drops
 * the cached copy and returns `null` (no account for this secret -- never
 * bound, or retired). The local client-key record is left
 * alone on a miss: it is the only copy of this client's keys, and a server
 * answer must never be able to destroy it. When the remote GET fails
 * (network/unreachable), the cache answers as an offline fallback, but only
 * within `KEYRING_CACHE_TTL_MS`; past that (or with no usable cache) the
 * error rethrows, so the caller sees "could not check" rather than misreading
 * it as "no account". A remote record whose proof does not verify against the
 * unlock identity's own signing key throws `KeyringRecordForgedError` (the
 * host forged or tampered with it); one that fails to unwrap or validate for
 * any other reason throws `KeyringRecordUnusableError` (corrupt record -- a
 * state distinct from both "no account" and "server unreachable"). Neither
 * refreshes the cache. With no
 * WAS server configured the cache is the keyring's only copy, so the lookup
 * is cache-only with no TTL.
 *
 * A hit carries `clientKeys` when this client holds a key set under the
 * unlock method (an enrolled client -- the session can be built), and omits
 * it on a fresh browser (the account is located; acting requires enrollment).
 * The result always carries the derived `unlockSpaceId` (cheap -- it is
 * already computed); when `mintManageCapability` is set and a WAS server is
 * configured it also carries a `manageCapability` delegated to the recovered
 * controller (pure signing, minted on both the remote-hit and cache-fallback
 * paths), so a full login can record the method's revocation authority in the
 * unlock-methods registry.
 *
 * @param options {object}
 * @param [options.secret] {string | Uint8Array}   the unlock secret
 * @param [options.passphrase] {string}   compat alias for `secret` (existing
 *   passphrase call sites); one of the two is required
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}   the unlock method's KDF parameters
 * @param [options.mintManageCapability] {boolean}   also delegate the unlock
 *   Space management zcap to the recovered controller; default false
 * @param [options.credential] {UnlockCredential}   an already-derived unlock
 *   credential for the same secret, so a flow that unlocks more than once
 *   (finishing an enrollment) runs the KDF a single time
 * @returns {Promise<KeyringFetchResult | null>}
 */
export async function fetchKeyring({
  secret,
  passphrase,
  idb,
  kdf = KEYRING_KDF,
  mintManageCapability = false,
  credential: derived
}: {
  secret?: string | Uint8Array
  passphrase?: string
  idb?: IDBFactory
  kdf?: UnlockKdf
  mintManageCapability?: boolean
  credential?: UnlockCredential
}): Promise<KeyringFetchResult | null> {
  const unlockSecret = secret ?? passphrase
  if (!derived && unlockSecret === undefined) {
    throw new TypeError('An unlock secret is required.')
  }
  const credential =
    derived ??
    (await deriveUnlockCredential({
      secret: unlockSecret as string | Uint8Array,
      kdf
    }))
  const { unlock } = credential

  if (!WAS_SERVER_URL) {
    // No remote: the cache is the keyring's only copy -- authoritative, no TTL.
    const cached = await loadKeyringCache({ spaceId: unlock.spaceId, idb })
    if (!cached) {
      return null
    }
    // An unusable cache entry (warned + evicted inside the helper) means "no
    // account" here, since the cache is the keyring's only copy.
    return await readCachedRecord({
      cached,
      credential,
      mintManageCapability,
      idb
    })
  }

  let record: unknown
  try {
    record = await getUnlockKeyring({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: unlock.zcapClient,
      spaceId: unlock.spaceId
    })
  } catch (err) {
    // Remote unreachable: fall back to the cache (offline logins), but only
    // within its TTL -- past that (or for an unstamped legacy entry) the
    // error rethrows, so the caller reports "could not check" instead of
    // honoring an unboundedly stale record.
    const cached = await loadKeyringCache({ spaceId: unlock.spaceId, idb })
    if (
      !cached ||
      cached.cachedAt === null ||
      Date.now() - cached.cachedAt > KEYRING_CACHE_TTL_MS
    ) {
      throw err
    }
    // An unusable cache entry (warned + evicted inside the helper) means
    // "could not check" here: rethrow the original network error rather than
    // misread it as "no account".
    const result = await readCachedRecord({
      cached,
      credential,
      mintManageCapability,
      idb
    })
    if (!result) {
      throw err
    }
    return result
  }

  if (!record) {
    // A 404-shaped miss: no keyring for this passphrase (never bound, or
    // retired by a passphrase change on this or another client). Drop the
    // cached copy so the retired passphrase cannot keep resolving offline.
    // The client-key record stays: it is primary state, and without a
    // session it is inert anyway.
    await deleteKeyringCache({ spaceId: unlock.spaceId, idb })
    return null
  }

  let unwrapped: UnwrappedStoredRecord
  try {
    unwrapped = await unwrapStoredKeyringRecord({ record, credential })
  } catch (err) {
    // A record exists under the correct unlock Space but does not open: a
    // forged one (its proof was not made by the key the typed secret derives,
    // or its account binding fails the credential's MAC) or a
    // corrupt/malformed one. Neither is a wrong passphrase -- that resolves
    // to a different Space and misses above -- so each surfaces as its own
    // state, and neither ever refreshes the cache.
    throw keyringUnwrapError(err)
  }
  // A pending proof (the revocation cascade re-minted this record's bridge,
  // signing with an enrolled client's account key) is settled against the
  // verified document of the account the credential-authenticated pointer
  // names, before anything trusts the shell.
  await settlePendingRecordProof({
    record,
    proofState: unwrapped.proofState,
    found: unwrapped.found
  })
  await saveKeyringCache({ spaceId: unlock.spaceId, record, idb })
  return await buildFetchResult({
    unwrapped,
    credential,
    mintManageCapability,
    idb
  })
}

/**
 * What `fetchTransientKeyring` returns on a hit: the record contents plus the
 * derived unlock Space id, the standing-credential members when the record is
 * in the standing layout, the credential's own client identity, and a freshly
 * minted management zcap on the unlock Space. Nothing browser-local rides
 * along -- no client keys and no persist or enroll closures: a transient
 * session holds none of them.
 *
 * The management zcap is the one exception to "a transient visit carries
 * nothing a remembered login carries". It is a local signature costing no
 * request, and without it no credential's management zcap would ever be
 * refreshed on an account that never remembers a browser -- every one of them
 * would lapse a year after its bind, on the default account shape. The
 * transient login writes it to the acting credential's registry entry when
 * the stored copy is stale (`refreshTransientManageCapability`).
 */
export interface TransientKeyringFetchResult extends KeyringRecordContents {
  unlockSpaceId: string
  manageCapability?: IZcap
  standing?: {
    delegation: IZcap
    delegatedClients?: IZcap
    ladderSeed?: Uint8Array
  }
  standingClient: StandingUnlockClient
  // Present beside `standing`: the record re-bind closure, in its transient
  // shape -- the remote record is re-written, nothing local is touched. What
  // the visit's client-annex heal re-seals a freshly minted sibling
  // delegation into.
  rebindStandingRecord?: (options: {
    delegation: IZcap
    delegatedClients?: IZcap
  }) => Promise<void>
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}

/**
 * The transient unlock-record fetch: `fetchKeyring`'s public-terminal
 * sibling, which writes nothing -- not on this browser, and not on the
 * server. Remote-only (the transient login presupposes a WAS server -- with
 * none configured it throws), it fetches the record, verifies its proof and,
 * for a standing record, the credential-authenticated account binding, and
 * settles a pending proof (a cascade-re-minted record) against the account
 * log under the CALLER-SUPPLIED chain-head pin store -- an in-memory one for
 * a transient login, so the account-log read leaves no trace either.
 *
 * What it deliberately does not do, per the `fetchKeyring` contract it
 * parallels: no keyring cache read or write (so no offline fallback -- a
 * network error rethrows unchanged, could-not-check), no client-key record
 * read (a transient session never holds one). It DOES mint the unlock Space's
 * management zcap, a local signature costing no request: the transient login
 * is the only refresher of that capability on an account that never remembers
 * a browser. The refusal classes are otherwise
 * `fetchKeyring`'s: a miss is `null`, a forged or tampered record is
 * `KeyringRecordForgedError`, a corrupt one `KeyringRecordUnusableError`.
 *
 * @param options {object}
 * @param [options.secret] {string | Uint8Array}   the unlock secret
 * @param [options.kdf] {UnlockKdf}   the unlock method's KDF parameters
 * @param options.accountLogPinStore {ResourceLogPinStore}   the chain-head
 *   pin store a pending-proof settlement's account-log read rides --
 *   caller-supplied, in-memory for a transient login
 * @param [options.credential] {UnlockCredential}   an already-derived unlock
 *   credential for the same secret, so a flow that unlocks more than once
 *   runs the KDF a single time
 * @returns {Promise<TransientKeyringFetchResult | null>}
 */
export async function fetchTransientKeyring({
  secret,
  kdf = KEYRING_KDF,
  accountLogPinStore,
  credential: derived
}: {
  secret?: string | Uint8Array
  kdf?: UnlockKdf
  accountLogPinStore: ResourceLogPinStore
  credential?: UnlockCredential
}): Promise<TransientKeyringFetchResult | null> {
  if (!WAS_SERVER_URL) {
    throw new TypeError(
      'The transient unlock fetch requires a configured WAS server.'
    )
  }
  if (!derived && secret === undefined) {
    throw new TypeError('An unlock secret is required.')
  }
  const credential =
    derived ??
    (await deriveUnlockCredential({
      secret: secret as string | Uint8Array,
      kdf
    }))
  const { unlock, standing: standingClient } = credential

  // No cache fallback on a network error, and no cache or pin cleanup on a
  // miss: a transient visit holds no browser-local state to fall back on or
  // clear.
  const record = await getUnlockKeyring({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: unlock.zcapClient,
    spaceId: unlock.spaceId
  })
  if (!record) {
    return null
  }

  let unwrapped: UnwrappedStoredRecord
  try {
    unwrapped = await unwrapStoredKeyringRecord({ record, credential })
  } catch (err) {
    throw keyringUnwrapError(err)
  }
  await settlePendingRecordProof({
    record,
    proofState: unwrapped.proofState,
    found: unwrapped.found,
    accountLogPinStore
  })
  // The management zcap this visit may refresh the registry entry with: the
  // same mint the remembered login makes (`buildFetchResult`), with PUT for a
  // standing record so a refresh never narrows what the bind delegated.
  const manageCapability = await delegateUnlockManagement({
    zcapClient: unlock.zcapClient,
    spaceId: unlock.spaceId,
    controller: unlockManagementGrantee({
      pointer: unwrapped.found.pointer,
      controller: unwrapped.found.controller
    }),
    ...(unwrapped.standing ? { allowedActions: ['GET', 'PUT', 'DELETE'] } : {})
  })
  return {
    ...unwrapped.found,
    unlockSpaceId: unlock.spaceId,
    manageCapability,
    standingClient,
    ...(unwrapped.standing
      ? {
          standing: unwrapped.standing,
          rebindStandingRecord: standingRecordRebinder({
            unlock,
            standingClient,
            found: unwrapped.found,
            standing: unwrapped.standing
          })
        }
      : {}),
    ...unlockKeyAgreementMembers({ unlock })
  }
}

/**
 * Builds a standing record's re-bind closure: re-wraps and re-PUTs the
 * record with a freshly minted bridge delegation (and, when supplied, a
 * fresh annex-Space sibling; an existing sibling is restated verbatim
 * otherwise), everything else -- the controller, the pointer, the email,
 * the ladder seed -- restated verbatim.
 *
 * The one difference between the remembered and the transient variant is
 * `local`: a remembered hit refreshes this browser's keyring cache
 * afterwards, while a transient visit (which holds no local state at all)
 * writes nothing locally. Both floor the fresh stamp over the served
 * record, and the remote record write is the same one either way.
 *
 * @param options {object}
 * @param options.unlock {UnlockIdentity}   the derived unlock identity
 * @param options.standingClient {StandingUnlockClient}   the credential's
 *   own client identity (its binding MAC key authenticates the account core)
 * @param options.found {KeyringRecordContents}   the served record's contents
 * @param options.standing {object}   the record's standing members
 * @param [options.local] {object}   the remembered variant's local state (the
 *   `freewallet-session` IndexedDB factory); absent for a transient visit
 * @returns {Function}   `({ delegation, delegatedClients }) => Promise<void>`
 */
function standingRecordRebinder({
  unlock,
  standingClient,
  found,
  standing,
  local
}: {
  unlock: UnlockIdentity
  standingClient: StandingUnlockClient
  found: KeyringRecordContents
  standing: NonNullable<UnwrappedStoredRecord['standing']>
  local?: { idb?: IDBFactory }
}): (options: {
  delegation: IZcap
  delegatedClients?: IZcap
}) => Promise<void> {
  return async ({ delegation, delegatedClients }) => {
    const createdAt = nextRecordCreatedAt({ advancePast: [found.createdAt] })
    // A fresh sibling replaces the stored one; absent a fresh one,
    // the record's own sibling is restated verbatim.
    const carriedDelegatedClients =
      delegatedClients ?? standing.delegatedClients
    const record = await wrapUnlockRecord({
      controller: found.controller,
      email: found.email,
      pointer: found.pointer!,
      delegation,
      ...(carriedDelegatedClients
        ? { delegatedClients: carriedDelegatedClients }
        : {}),
      ...(standing.ladderSeed ? { ladderSeed: standing.ladderSeed } : {}),
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: standingClient.bindingMacKey,
      createdAt
    })
    if (WAS_SERVER_URL) {
      await putUnlockKeyring({
        storageServerUrl: WAS_SERVER_URL,
        zcapClient: unlock.zcapClient,
        spaceId: unlock.spaceId,
        record
      })
    }
    if (local) {
      await saveKeyringCache({
        spaceId: unlock.spaceId,
        record,
        idb: local.idb
      })
    }
  }
}

/**
 * Assembles a `fetchKeyring` hit: the unwrapped record contents plus the
 * derived unlock Space id, this client's key set when one is stored under the
 * unlock method, and, when requested and a WAS server is configured, the
 * management zcap delegated to the recovered controller.
 *
 * @param options {object}
 * @param options.unwrapped {UnwrappedStoredRecord}   the unwrapped record
 * @param options.credential {UnlockCredential}
 * @param options.mintManageCapability {boolean}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<KeyringFetchResult>}
 */
async function buildFetchResult({
  unwrapped,
  credential,
  mintManageCapability,
  idb
}: {
  unwrapped: UnwrappedStoredRecord
  credential: UnlockCredential
  mintManageCapability: boolean
  idb?: IDBFactory
}): Promise<KeyringFetchResult> {
  const { unlock, standing: standingClient } = credential
  const { found, standing } = unwrapped
  const clientKeys = await loadClientKeys({ unlock, idb })
  const result: KeyringFetchResult = {
    ...found,
    unlockSpaceId: unlock.spaceId,
    standingClient,
    ...unlockKeyAgreementMembers({ unlock }),
    ...(standing
      ? {
          standing,
          rebindStandingRecord: standingRecordRebinder({
            unlock,
            standingClient,
            found,
            standing,
            local: { idb }
          })
        }
      : {}),
    ...(clientKeys
      ? {
          clientKeys,
          persistClientKeys: clientKeysPersister({ unlock, idb }),
          persistAccountPointer: accountPointerPersister({ unlock, found, idb })
        }
      : {
          enrollClientKeys: async keys => {
            await saveClientKeys({ unlock, ...keys, idb })
            return clientKeysPersister({ unlock, idb })
          }
        })
  }
  if (mintManageCapability && WAS_SERVER_URL) {
    // A standing record's capability carries PUT, exactly as its bind
    // delegated it: the login mints a fresh delegation every time and the
    // registry backfill stores it, so a narrower mint here would strip the
    // re-PUT authority the revocation cascade's record re-mint needs.
    result.manageCapability = await delegateUnlockManagement({
      zcapClient: unlock.zcapClient,
      spaceId: unlock.spaceId,
      controller: unlockManagementGrantee({
        pointer: found.pointer,
        controller: found.controller
      }),
      ...(standing ? { allowedActions: ['GET', 'PUT', 'DELETE'] } : {})
    })
  }
  return result
}

/**
 * Thrown when a bind is about to overwrite an unlock record that belongs to
 * someone else: the served record at the target unlock Space names a
 * different account, or it is a standing credential's record (its ladder
 * seed, bridge, and sibling exist nowhere else, so a plain overwrite would
 * destroy that credential forever) that this ceremony's own earlier attempt
 * did not write. The recovery spend's pre-entry bind is the one caller today:
 * a colliding new passphrase refuses before the reveal entry burns anything,
 * worded at the new-passphrase form.
 */
export class UnlockSpaceCollisionError extends Error {
  constructor({ cause }: { cause?: unknown } = {}) {
    super(
      'This passphrase already unlocks an existing wallet credential; ' +
        'choose a different one.'
    )
    this.name = 'UnlockSpaceCollisionError'
    this.cause = cause
  }
}

/**
 * The shared collision predicate over a served unlock record the bind is
 * about to overwrite: the reason the overwrite must refuse, or `null` when it
 * is safe. A record naming another account (pointer mismatch) always
 * collides; a same-account STANDING record collides unless the caller proved
 * the overwrite is this ceremony's own rewrite (`ownRewriteLicensed` -- the
 * probe's pin or document evidence, never the local pending record alone) --
 * its randomly minted standing members are exactly what the typed material
 * cannot re-derive, so an overwrite would destroy them. A same-account plain
 * pointer record carries nothing an overwrite loses.
 *
 * The account-identity test is POINTER-based (Space id, host, did): the
 * record's `controller` is an identity label that legitimately varies (an
 * enrolled bind writes the account did:key; a credential-anchored bind
 * writes a per-ceremony bootstrap did:key), so it cannot decide which
 * account a record belongs to.
 *
 * @param options {object}
 * @param options.unwrapped {UnwrappedStoredRecord}   the served record
 * @param [options.pointer] {AccountPointer}   the account pointer this bind
 *   writes
 * @param [options.ownRewriteLicensed] {boolean}   the probe's evidence that
 *   the served standing record is this ceremony's own residue (see
 *   `probeUnlockSpaceCollision`)
 * @returns {string | null}   the refusal reason, or `null`
 */
function unlockRecordCollisionReason({
  unwrapped,
  pointer,
  ownRewriteLicensed = false
}: {
  unwrapped: UnwrappedStoredRecord
  pointer?: AccountPointer
  ownRewriteLicensed?: boolean
}): string | null {
  const { found, standing } = unwrapped
  const served = found.pointer
  const sameAccount =
    !!served &&
    !!pointer &&
    served.spaceId === pointer.spaceId &&
    served.host === pointer.host &&
    (served.did ?? undefined) === (pointer.did ?? undefined)
  if (!sameAccount) {
    return 'the served record names another account'
  }
  if (standing && !ownRewriteLicensed) {
    return (
      "the served record is a standing credential's this ceremony cannot " +
      'account for'
    )
  }
  return null
}

/**
 * Whether the account document lists a verification-method id, checking both
 * the `verificationMethod` entries and the `keyAgreement` relation's string
 * references -- the membership test behind the transient probe's
 * inert-residue license.
 *
 * @param options {object}
 * @param options.doc {unknown}   the locally verified account document
 * @param options.vmId {string}
 * @returns {boolean}
 */
function documentListsVmId({
  doc,
  vmId
}: {
  doc: unknown
  vmId: string
}): boolean {
  const shaped = doc as {
    verificationMethod?: unknown
    keyAgreement?: unknown
  } | null
  const methods = Array.isArray(shaped?.verificationMethod)
    ? shaped.verificationMethod
    : []
  if (methods.some(method => (method as { id?: string })?.id === vmId)) {
    return true
  }
  const keyAgreement = Array.isArray(shaped?.keyAgreement)
    ? shaped.keyAgreement
    : []
  return keyAgreement.some(entry =>
    typeof entry === 'string'
      ? entry === vmId
      : (entry as { id?: string })?.id === vmId
  )
}

/**
 * The recovery spend's read-first probe of the new passphrase's unlock Space,
 * run BEFORE the reveal entry (and re-run inside the hook's bind): loads this
 * ceremony's own pending client-key record (a pre-entry tear's residue, whose
 * persisted replacement-code bytes the re-run reuses), GETs the served unlock
 * record, and refuses a colliding one with `UnlockSpaceCollisionError` per
 * the shared predicate. A 404-shaped miss proceeds as a fresh bind; a
 * transport error rethrows unchanged; a record that will not decrypt or parse
 * refuses too (an overwrite of a record this probe cannot account for is not
 * provably safe). Returns the served record's stamp so the bind can advance
 * its own `createdAt` past it (the fetch-and-advance obligation).
 *
 * A served STANDING record is overwritable on one proof only, never on the
 * local pending record alone (a stale pending record must not license
 * destroying a record someone else legitimately established since): the
 * document license (`accountDoc` supplied), where the credential's
 * key-agreement publication (commitment or verbatim) is NOT in the verified
 * account document, so the served record's standing members back no
 * published inventory -- the inert residue of a torn earlier attempt, not a
 * live credential. It is also what covers the remembered spend's own
 * PUT-then-persist window, where a tab death leaves a served standing record
 * with no pending record behind it.
 *
 * @param options {object}
 * @param options.credential {UnlockCredential}   the new passphrase's derived
 *   credential
 * @param options.controller {string}   the account controller the bind writes
 * @param [options.pointer] {AccountPointer}   the account pointer the bind
 *   writes
 * @param [options.accountDoc] {unknown}   the locally verified account
 *   document, enabling the transient license above
 * @param [options.readLocalRecord] {boolean}   consult the local client-key
 *   record for the own-pending residue (default true); the transient spend
 *   passes false, since even a read would create the session database on
 *   this browser
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ ownPending?: ClientKeyRecordPending,
 *   servedCreatedAt?: string }>}
 */
export async function probeUnlockSpaceCollision({
  credential,
  controller,
  pointer,
  accountDoc,
  readLocalRecord = true,
  idb
}: {
  credential: UnlockCredential
  controller: string
  pointer?: AccountPointer
  accountDoc?: unknown
  readLocalRecord?: boolean
  idb?: IDBFactory
}): Promise<{
  ownPending?: ClientKeyRecordPending
  servedCreatedAt?: string
}> {
  const { unlock } = credential
  const clientKeys = readLocalRecord
    ? await loadClientKeys({ unlock, idb })
    : undefined
  const localPending = clientKeys?.pending
  const ownPending =
    localPending?.ceremony === 'recovery-spend' &&
    (!clientKeys?.controller || clientKeys.controller === controller) &&
    (!clientKeys?.pointerDid ||
      !pointer?.did ||
      clientKeys.pointerDid === pointer.did)
      ? localPending
      : undefined
  if (!WAS_SERVER_URL) {
    return { ...(ownPending ? { ownPending } : {}) }
  }
  const record = await getUnlockKeyring({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: unlock.zcapClient,
    spaceId: unlock.spaceId
  })
  if (!record) {
    return { ...(ownPending ? { ownPending } : {}) }
  }
  let unwrapped: UnwrappedStoredRecord
  try {
    unwrapped = await unwrapStoredKeyringRecord({ record, credential })
  } catch (err) {
    throw new UnlockSpaceCollisionError({ cause: keyringUnwrapError(err) })
  }
  let ownRewriteLicensed = false
  if (unwrapped.standing) {
    if (
      !ownRewriteLicensed &&
      accountDoc !== undefined &&
      pointer &&
      isWebvhDid(pointer.did)
    ) {
      // The document license: no published inventory backs the served
      // record's standing members, so it is a torn attempt's inert residue
      // (a genuinely standing credential's commitment IS in the document).
      // The transient spend's only license (it holds no pin and reads no
      // local records), and the remembered spend's backstop for the window its
      // own bind order creates: a tab death between the remote record PUT
      // and the local persists leaves a served standing record with no
      // pending record and no pin, which the pin license alone would refuse
      // forever.
      const did = pointer.did!
      const commitment = await keyAgreementCommitment({
        keyAgreementKeyMultibase: credential.standing.keyAgreementKeyMultibase
      })
      const publishedIds = [
        unlockKeyVmId({ did, keyAgreement: { commitment } }),
        unlockKeyVmId({
          did,
          keyAgreement: {
            publicKeyMultibase: credential.standing.keyAgreementKeyMultibase
          }
        })
      ]
      ownRewriteLicensed = !publishedIds.some(vmId =>
        documentListsVmId({ doc: accountDoc, vmId })
      )
    }
  }
  const reason = unlockRecordCollisionReason({
    unwrapped,
    pointer,
    ownRewriteLicensed
  })
  if (reason) {
    log.warn('Refusing to overwrite a colliding unlock record', {
      reason,
      unlockSpaceId: unlock.spaceId
    })
    throw new UnlockSpaceCollisionError({ cause: new Error(reason) })
  }
  return {
    ...(ownPending ? { ownPending } : {}),
    servedCreatedAt: unwrapped.found.createdAt
  }
}

/**
 * Binds an unlock secret to this client's key set and the account it belongs
 * to: derives the unlock identity for the method's KDF, ensures the unlock
 * Space (when WAS is configured), wraps, signs, and PUTs the account-pointer
 * keyring
 * record, wraps the client seed + user key into the local client-key record,
 * and saves the local cache. Throws on failure (the caller
 * decides fatality -- fatal for signups). With no WAS server configured the
 * keyring is cache-only, so the account is then only recoverable in this
 * browser profile. Returns the unlock Space id so callers (the unlock-methods
 * registry) can record which Space this method resolves to. Also returns a
 * `persistClientKeys` closure over the just-derived unlock identity, so the
 * caller can later re-wrap the record (rolled update-key seeds, a rotated
 * user key) without re-prompting for the secret.
 *
 * @param options {object}
 * @param options.clientSeed {Uint8Array}   this client's 32-byte seed
 * @param options.controller {string}   the account did:key
 * @param options.secret {string | Uint8Array}   the unlock secret
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @param [options.email] {string}   the account email, carried in the wrapped
 *   record so any unlock method recovers it at login
 * @param [options.userKey] {UserKey}   the per-user key, cached in the local
 *   client-key record so any unlock method recovers it at login
 * @param [options.webvhUpdateKeys] {ClientWebvhUpdateKeys}   this client's
 *   did:webvh update-key seeds, cached in the local client-key record so any
 *   unlock method recovers update authority at login
 * @param [options.pointer] {AccountPointer}   the account pointer the record
 *   carries; absent on no-WAS deployments
 * @param [options.delegateManagementTo] {string}   an account DID (see
 *   `unlockManagementGrantee`) to delegate the unlock Space management zcap
 *   to (GET/DELETE on this unlock Space). When set and a WAS server is
 *   configured, the returned `manageCapability` is the revocation authority
 *   a later Settings flow uses to retire this method (a lost passkey)
 *   without tapping or re-deriving from the secret.
 * @param [options.delegation] {IZcap}   the pre-minted PUT-on-`did.jsonl`
 *   bridge delegation to the credential-derived signing DID. When present
 *   (with `ladderSeed`), the record is written in the standing unlock-record
 *   layout -- the credential can self-enroll a fresh browser -- instead of as
 *   a plain pointer record. Requires `pointer` (unlock records exist only on
 *   WAS deployments).
 * @param [options.delegatedClients] {IZcap}   the pre-minted annex-Space
 *   sibling delegation (GET+PUT over the auxiliary Space's items subtree),
 *   sealed into the standing record beside the bridge
 * @param [options.ladderSeed] {Uint8Array}   the credential's 32-byte
 *   update-key ladder seed, sealed into the standing record beside the bridge
 * @param [options.pending] {ClientKeyRecordPending}   a mid-flight ceremony's
 *   pending state, written into the local client-key record (the record then
 *   classifies pending at login and routes to the resume)
 * @param [options.refuseCollidingRecord] {boolean | object}   the read-first
 *   collision refusal: GET the served record first, refuse a colliding one
 *   (`UnlockSpaceCollisionError`, shared predicate with
 *   `probeUnlockSpaceCollision`), and advance the bind stamp past the served
 *   record's `createdAt` beside the local pin (the fetch-and-advance
 *   obligation). The object form carries `accountDoc` (the locally verified
 *   account document), enabling the probe's document license beside the pin
 *   license. The recovery spend's pre-entry bind passes it; the ordinary
 *   bind and re-establishment sites overwrite their own records by design
 * @param [options.idb] {IDBFactory}
 * @param [options.credential] {UnlockCredential}   an already-derived unlock
 *   credential for the same secret and KDF, so a flow that unlocks more than
 *   once runs the KDF a single time
 * @returns {Promise<{ unlockSpaceId: string, manageCapability?: IZcap }>}
 */
export async function bindUnlockSecret({
  clientSeed,
  controller,
  secret,
  kdf,
  email,
  userKey,
  webvhUpdateKeys,
  pointer,
  delegateManagementTo,
  delegation,
  delegatedClients,
  ladderSeed,
  pending,
  refuseCollidingRecord = false,
  idb,
  credential: derived
}: {
  clientSeed: Uint8Array
  controller: string
  secret: string | Uint8Array
  kdf: UnlockKdf
  email?: string
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  pointer?: AccountPointer
  delegateManagementTo?: string
  delegation?: IZcap
  delegatedClients?: IZcap
  ladderSeed?: Uint8Array
  pending?: ClientKeyRecordPending
  refuseCollidingRecord?: boolean | { accountDoc?: unknown }
  idb?: IDBFactory
  credential?: UnlockCredential
}): Promise<{
  unlockSpaceId: string
  manageCapability?: IZcap
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}> {
  const credential = derived ?? (await deriveUnlockCredential({ secret, kdf }))
  const { unlock, standing } = credential
  if (delegation && !pointer) {
    throw new TypeError('A standing unlock record requires an account pointer.')
  }
  // The read-first collision refusal and the served half of the
  // fetch-and-advance: the probe GETs the served record, refuses a colliding
  // one before anything is overwritten, and hands back its `createdAt` so a
  // bind from a browser whose clock lags the record's writer still
  // supersedes it (the cross-browser fast-clock wedge).
  let servedCreatedAt: string | undefined
  if (refuseCollidingRecord) {
    const guard =
      typeof refuseCollidingRecord === 'object' ? refuseCollidingRecord : {}
    const probed = await probeUnlockSpaceCollision({
      credential,
      controller,
      pointer,
      ...(guard.accountDoc !== undefined
        ? { accountDoc: guard.accountDoc }
        : {}),
      idb
    })
    servedCreatedAt = probed.servedCreatedAt
  }
  // The bind timestamp is stamped here rather than left to the codec, and is
  // advanced past the served record's stamp when the read-first probe fetched
  // one, so the record this bind writes supersedes the one it read even when
  // the other client's clock ran ahead of this one.
  const createdAt = nextRecordCreatedAt({ advancePast: [servedCreatedAt] })
  const record =
    delegation && pointer
      ? await wrapUnlockRecord({
          controller,
          email,
          pointer,
          delegation,
          ...(delegatedClients ? { delegatedClients } : {}),
          ...(ladderSeed ? { ladderSeed } : {}),
          keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
          signer: unlock.recordSigner,
          bindingMacKey: standing.bindingMacKey,
          createdAt
        })
      : await wrapKeyringRecord({
          controller,
          email,
          pointer,
          keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
          signer: unlock.recordSigner,
          createdAt
        })

  let manageCapability: IZcap | undefined
  if (WAS_SERVER_URL) {
    await ensureUnlockSpace({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: unlock.zcapClient,
      spaceId: unlock.spaceId,
      controller: unlock.agent.id
    })
    await putUnlockKeyring({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: unlock.zcapClient,
      spaceId: unlock.spaceId,
      record
    })
    if (delegateManagementTo) {
      // The unlock agent delegates GET/DELETE on its own Space to the account
      // identity, so a lost method stays revocable without re-deriving this
      // unlock identity from the (possibly lost) secret. Pure signing. A
      // standing bind widens the actions to include PUT, exactly as a
      // recovery code's does: that is what lets the revocation cascade
      // re-PUT this record with a freshly minted bridge delegation when the
      // original's signing client is revoked.
      manageCapability = await delegateUnlockManagement({
        zcapClient: unlock.zcapClient,
        spaceId: unlock.spaceId,
        controller: delegateManagementTo,
        ...(delegation ? { allowedActions: ['GET', 'PUT', 'DELETE'] } : {})
      })
    }
  }

  await saveKeyringCache({ spaceId: unlock.spaceId, record, idb })
  await saveClientKeys({
    unlock,
    clientSeed,
    userKey,
    webvhUpdateKeys,
    controller,
    // The account's did:webvh, when the pointer already names one. A
    // pre-promotion bind writes none; the member is backfilled by the next
    // record rewrite made with the promoted pointer in hand, and its absence
    // has no routing consequence (the pending/enrolled router keys on
    // `userKey` presence alone; `pointerDid` is the resume's cross-check).
    ...(pointer && isWebvhDid(pointer.did) ? { pointerDid: pointer.did } : {}),
    ...(pending ? { pending } : {}),
    idb
  })
  return {
    unlockSpaceId: unlock.spaceId,
    manageCapability,
    persistClientKeys: clientKeysPersister({ unlock, idb }),
    ...unlockKeyAgreementMembers({ unlock })
  }
}

/**
 * Binds a passphrase to this client's key set -- the passphrase-shaped
 * wrapper over `bindUnlockSecret`, defaulting to the app's passphrase KDF.
 *
 * @param options {object}
 * @param options.clientSeed {Uint8Array}   this client's 32-byte seed
 * @param options.controller {string}   the account did:key
 * @param options.passphrase {string}
 * @param [options.email] {string}   the account email, carried in the wrapped
 *   record
 * @param [options.userKey] {UserKey}   the per-user key, cached in the local
 *   client-key record
 * @param [options.webvhUpdateKeys] {ClientWebvhUpdateKeys}   this client's
 *   did:webvh update-key seeds, cached in the local client-key record
 * @param [options.pointer] {AccountPointer}   the account pointer the record
 *   carries
 * @param [options.delegateManagementTo] {string}   an account DID to
 *   delegate the unlock Space management zcap to (see `bindUnlockSecret`)
 * @param [options.delegation] {IZcap}   the bridge delegation for a standing
 *   bind (see `bindUnlockSecret`)
 * @param [options.delegatedClients] {IZcap}   the annex-Space sibling
 *   delegation for a standing bind
 * @param [options.ladderSeed] {Uint8Array}   the update-key ladder seed for a
 *   standing bind
 * @param [options.pending] {ClientKeyRecordPending}   a mid-flight ceremony's
 *   pending state (see `bindUnlockSecret`)
 * @param [options.refuseCollidingRecord] {boolean | object}   the read-first
 *   collision refusal and served-stamp advance (see `bindUnlockSecret`)
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}
 * @param [options.credential] {UnlockCredential}   an already-derived unlock
 *   credential for the same passphrase (see `bindUnlockSecret`)
 * @returns {Promise<{ unlockSpaceId: string, manageCapability?: IZcap,
 *   persistClientKeys: Function }>}
 */
export async function bindPassphrase({
  clientSeed,
  controller,
  passphrase,
  email,
  userKey,
  webvhUpdateKeys,
  pointer,
  delegateManagementTo,
  delegation,
  delegatedClients,
  ladderSeed,
  pending,
  refuseCollidingRecord,
  idb,
  kdf = KEYRING_KDF,
  credential
}: {
  clientSeed: Uint8Array
  controller: string
  passphrase: string
  email?: string
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  pointer?: AccountPointer
  delegateManagementTo?: string
  delegation?: IZcap
  delegatedClients?: IZcap
  ladderSeed?: Uint8Array
  pending?: ClientKeyRecordPending
  refuseCollidingRecord?: boolean | { accountDoc?: unknown }
  idb?: IDBFactory
  kdf?: UnlockKdf
  credential?: UnlockCredential
}): Promise<{
  unlockSpaceId: string
  manageCapability?: IZcap
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}> {
  return bindUnlockSecret({
    clientSeed,
    controller,
    secret: passphrase,
    kdf,
    email,
    userKey,
    webvhUpdateKeys,
    pointer,
    delegateManagementTo,
    delegation,
    delegatedClients,
    ladderSeed,
    ...(pending ? { pending } : {}),
    ...(refuseCollidingRecord !== undefined ? { refuseCollidingRecord } : {}),
    idb,
    ...(credential ? { credential } : {})
  })
}

/**
 * The CREDENTIAL-ANCHORED bind: writes a standing unlock record with NO local
 * counterpart at all -- no client-key record (such a signup mints no client
 * seed to persist) and no keyring cache. Everything it writes is remote:
 * the unlock Space, the
 * standing-layout record (bridge, optional sibling, ladder seed, binding
 * MAC), and the optional management delegation.
 *
 * The record's `controller` is the ladder VM's bare did:key -- the bootstrap
 * identity, re-derivable from the credential alone -- and the bind stamp
 * advances past the caller-supplied prior stamp (the signup's first bind), so
 * the post-genesis re-bind always supersedes it.
 *
 * @param options {object}
 * @param options.controller {string}   the ladder VM's did:key
 * @param [options.secret] {string | Uint8Array}   the unlock secret, when no
 *   derived credential is supplied
 * @param [options.kdf] {UnlockKdf}   the unlock method's KDF parameters,
 *   required beside `secret`
 * @param [options.email] {string}   carried inside the wrapped record
 * @param options.pointer {AccountPointer}   the account pointer (DID-less on
 *   the pre-genesis bind; the full pointer on the re-bind)
 * @param options.delegation {IZcap}   the bridge delegation (the interim
 *   ladder-did:key-signed one pre-genesis, the ladder-VM-signed one after)
 * @param [options.delegatedClients] {IZcap}   the annex-Space sibling
 * @param options.ladderSeed {Uint8Array}
 * @param [options.delegateManagementTo] {string}   an account DID to delegate
 *   the unlock Space management zcap to (widened with PUT, the standing
 *   standing configuration)
 * @param [options.priorCreatedAt] {string}   the previous bind's stamp; this
 *   bind's stamp advances past it
 * @param [options.refuseCollidingRecord] {object}   the read-first collision
 *   refusal (see `probeUnlockSpaceCollision`): the bind GETs the served
 *   record first, refuses a colliding one, and advances its stamp past the
 *   served record's. Carries the verified account document -- the
 *   inert-residue license, since a transient visit must not read local
 *   records (even a read would create the session database on this browser)
 * @param [options.credential] {UnlockCredential}   an already-derived
 *   credential for the same secret
 * @returns {Promise<object>}   the unlock Space id, the management zcap when
 *   one was delegated, this record's `createdAt` stamp, and the unlock KAK's
 *   id and multibase for the registry entry
 */
export async function bindCredentialAnchoredUnlockSecret({
  controller,
  secret,
  kdf,
  email,
  pointer,
  delegation,
  delegatedClients,
  ladderSeed,
  delegateManagementTo,
  priorCreatedAt,
  refuseCollidingRecord,
  credential: derived
}: {
  controller: string
  secret?: string | Uint8Array
  kdf?: UnlockKdf
  email?: string
  pointer: AccountPointer
  delegation: IZcap
  delegatedClients?: IZcap
  ladderSeed: Uint8Array
  delegateManagementTo?: string
  priorCreatedAt?: string
  refuseCollidingRecord?: { accountDoc: unknown }
  credential?: UnlockCredential
}): Promise<{
  unlockSpaceId: string
  manageCapability?: IZcap
  createdAt: string
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}> {
  if (!WAS_SERVER_URL) {
    throw new TypeError(
      'The credential-anchored bind requires a configured WAS server.'
    )
  }
  if (!derived && (secret === undefined || kdf === undefined)) {
    throw new TypeError(
      'An unlock secret and its KDF are required when no derived credential ' +
        'is supplied.'
    )
  }
  const credential =
    derived ??
    (await deriveUnlockCredential({
      secret: secret as string | Uint8Array,
      kdf: kdf as UnlockKdf
    }))
  const { unlock, standing } = credential
  // The read-first refusal and the served half of fetch-and-advance, when
  // the caller asked for it (the transient spend's re-bind of a
  // passphrase-addressed Space that may hold another credential's record).
  let servedCreatedAt: string | undefined
  if (refuseCollidingRecord) {
    const probed = await probeUnlockSpaceCollision({
      credential,
      controller,
      pointer,
      accountDoc: refuseCollidingRecord.accountDoc,
      readLocalRecord: false
    })
    servedCreatedAt = probed.servedCreatedAt
  }
  const createdAt = nextRecordCreatedAt({
    advancePast: [priorCreatedAt, servedCreatedAt]
  })
  const record = await wrapUnlockRecord({
    controller,
    email,
    pointer,
    delegation,
    ...(delegatedClients ? { delegatedClients } : {}),
    ladderSeed,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    signer: unlock.recordSigner,
    bindingMacKey: standing.bindingMacKey,
    createdAt
  })

  await ensureUnlockSpace({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: unlock.zcapClient,
    spaceId: unlock.spaceId,
    controller: unlock.agent.id
  })
  await putUnlockKeyring({
    storageServerUrl: WAS_SERVER_URL,
    zcapClient: unlock.zcapClient,
    spaceId: unlock.spaceId,
    record
  })
  let manageCapability: IZcap | undefined
  if (delegateManagementTo) {
    // The standing widening (PUT beside GET/DELETE), exactly as the
    // remembered path's standing bind delegates it: the revocation cascade
    // must be able to re-PUT this record with a re-minted bridge.
    manageCapability = await delegateUnlockManagement({
      zcapClient: unlock.zcapClient,
      spaceId: unlock.spaceId,
      controller: delegateManagementTo,
      allowedActions: ['GET', 'PUT', 'DELETE']
    })
  }

  return {
    unlockSpaceId: unlock.spaceId,
    manageCapability,
    createdAt,
    ...unlockKeyAgreementMembers({ unlock })
  }
}

/**
 * Thrown when a supplied unlock secret (the current passphrase, most
 * commonly) does not unlock a keyring for this account. Shared by every
 * unlock method's verification path.
 */
export class WrongPassphraseError extends Error {
  constructor(message = 'The current passphrase is incorrect.') {
    super(message)
    this.name = 'WrongPassphraseError'
  }
}

/**
 * Verifies an already-derived unlock identity against an account controller
 * by reading and unwrapping its keyring record. When a WAS server is
 * configured the remote copy is read -- the source of truth, so a locally
 * cached record cannot verify a passphrase already retired on another client;
 * with no WAS server the local cache is the keyring's only copy.
 *
 * A missing record, or one that fails to unwrap or whose controller does not
 * match, is a `WrongPassphraseError`. A network error while reading the remote
 * record rethrows unchanged -- being unable to verify while the remote is
 * unreachable must not read as a wrong passphrase. Shared by `changePassphrase`
 * and `verifyPassphrase`.
 *
 * @param options {object}
 * @param options.credential {UnlockCredential}
 *   the unlock credential for the passphrase being verified
 * @param options.controller {string}   the account did:key to match
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ found: KeyringRecordContents, ladderSeed?: Uint8Array }>}
 *   the verified record's unwrapped contents (so a rebind can preserve fields
 *   such as the email and pointer), plus a standing record's ladder seed --
 *   what a retirement passes on so the ladder attribution does not depend on
 *   the registry's recorded rung alone
 */
async function verifyUnlockKeyring({
  credential,
  controller,
  idb
}: {
  credential: UnlockCredential
  controller: string
  idb?: IDBFactory
}): Promise<{ found: KeyringRecordContents; ladderSeed?: Uint8Array }> {
  const { unlock } = credential
  let record: unknown
  if (WAS_SERVER_URL) {
    record = await getUnlockKeyring({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: unlock.zcapClient,
      spaceId: unlock.spaceId
    })
  } else {
    const cached = await loadKeyringCache({ spaceId: unlock.spaceId, idb })
    record = cached?.record ?? null
  }

  if (!record) {
    throw new WrongPassphraseError()
  }
  let unwrapped: UnwrappedStoredRecord | null = null
  try {
    // A pending proof (a cascade-re-minted record) is acceptable here without
    // settlement: verification asks whether the SECRET is right, and a
    // successful decrypt under the credential's unlock KAK -- with the
    // account binding verified inside the unwrap for a standing record --
    // already answers that.
    unwrapped = await unwrapStoredKeyringRecord({ record, credential })
  } catch {
    // A record that does not unwrap for this controller is a wrong passphrase.
  }
  if (!unwrapped || unwrapped.found.controller !== controller) {
    throw new WrongPassphraseError()
  }
  return {
    found: unwrapped.found,
    ...(unwrapped.standing?.ladderSeed
      ? { ladderSeed: unwrapped.standing.ladderSeed }
      : {})
  }
}

/**
 * A standing credential's ladder seed, read from its unlock record --
 * best-effort, for a retirement that holds the credential's secret (the
 * tapped-passkey removal): the seed lets the ladder attribution strike the
 * credential's whole inventory independent of the registry's recorded rung.
 * Any failure (no record, a non-standing layout, a controller mismatch)
 * resolves to `undefined`, and the retirement's log-walk attribution carries
 * on without it.
 *
 * @param options {object}
 * @param options.credential {UnlockCredential}   the credential being retired
 * @param options.controller {string}   the account did:key
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<Uint8Array | undefined>}
 */
export async function standingLadderSeed({
  credential,
  controller,
  idb
}: {
  credential: UnlockCredential
  controller: string
  idb?: IDBFactory
}): Promise<Uint8Array | undefined> {
  try {
    const { ladderSeed } = await verifyUnlockKeyring({
      credential,
      controller,
      idb
    })
    return ladderSeed
  } catch {
    return undefined
  }
}

/**
 * Verifies an unlock secret against its keyring without changing anything, so
 * destructive flows (account deletion) can confirm the secret before acting.
 * Derives the unlock identity for `secret` under the method's KDF and runs
 * the shared keyring verification against `controller` (the account did:key).
 *
 * Throws `WrongPassphraseError` when the secret does not unlock a keyring
 * bound to `controller`. A network error while reading the remote record
 * rethrows unchanged -- an unreachable remote must not read as a wrong
 * secret.
 *
 * @param options {object}
 * @param options.controller {string}   the account did:key
 * @param options.secret {string | Uint8Array}   the unlock secret
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @param [options.idb] {IDBFactory}
 * @param [options.credential] {UnlockCredential}   an already-derived
 *   credential for this secret, so a caller running several unlock-layer
 *   steps pays the KDF once
 * @returns {Promise<{ ladderSeed?: Uint8Array }>}   a standing record's
 *   ladder seed, so a ceremony that verifies before retiring holds the
 *   attribution seed without a second record fetch
 */
async function verifyUnlockSecret({
  controller,
  secret,
  kdf,
  idb,
  credential
}: {
  controller: string
  secret: string | Uint8Array
  kdf: UnlockKdf
  idb?: IDBFactory
  credential?: UnlockCredential
}): Promise<{ ladderSeed?: Uint8Array }> {
  const { ladderSeed } = await verifyUnlockKeyring({
    credential: credential ?? (await deriveUnlockCredential({ secret, kdf })),
    controller,
    idb
  })
  return ladderSeed ? { ladderSeed } : {}
}

/**
 * Verifies a passphrase against its keyring -- the passphrase-shaped wrapper
 * over `verifyUnlockSecret`, defaulting to the app's passphrase KDF.
 *
 * @param options {object}
 * @param options.controller {string}   the account did:key
 * @param options.passphrase {string}
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}
 * @param [options.credential] {UnlockCredential}   an already-derived
 *   credential for this passphrase
 * @returns {Promise<{ ladderSeed?: Uint8Array }>}   a standing record's
 *   ladder seed (see `verifyUnlockSecret`)
 */
export async function verifyPassphrase({
  controller,
  passphrase,
  idb,
  kdf = KEYRING_KDF,
  credential
}: {
  controller: string
  passphrase: string
  idb?: IDBFactory
  kdf?: UnlockKdf
  credential?: UnlockCredential
}): Promise<{ ladderSeed?: Uint8Array }> {
  return verifyUnlockSecret({
    controller,
    secret: passphrase,
    kdf,
    idb,
    credential
  })
}

/**
 * Retires one unlock identity: its unlock Space on the server (best effort)
 * and every local record filed under it (the keyring cache and the
 * client-key record). Shared by `deleteUnlockMethod` and the old-identity
 * half of `changePassphrase`.
 *
 * @param options {object}
 * @param options.unlock {UnlockIdentity}   the identity to retire
 * @param options.warning {string}   how a failed Space deletion is logged
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<boolean>}   whether the unlock Space was deleted
 */
async function retireUnlockIdentity({
  unlock,
  warning,
  idb
}: {
  unlock: UnlockIdentity
  warning: string
  idb?: IDBFactory
}): Promise<boolean> {
  let unlockSpaceDeleted = true
  if (WAS_SERVER_URL) {
    try {
      await deleteUnlockSpace({
        storageServerUrl: WAS_SERVER_URL,
        zcapClient: unlock.zcapClient,
        spaceId: unlock.spaceId
      })
    } catch (err) {
      log.warn(warning, { err })
      unlockSpaceDeleted = false
    }
  }
  await deleteUnlockLocalState({ spaceId: unlock.spaceId, idb })
  return unlockSpaceDeleted
}

/**
 * Retires an unlock method's keyring (account deletion, method removal):
 * derives the unlock identity, deletes its unlock Space (when a WAS server is
 * configured), and always clears the local records -- the cache and this
 * method's client-key record (an explicit lifecycle flow is the one place a
 * client-key record may be deleted). With no WAS server
 * configured there is no Space, so `unlockSpaceDeleted` stays `true`.
 *
 * Performs no verification -- a wrong secret derives a different unlock Space
 * id and `deleteUnlockSpace` is idempotent, so callers confirm the secret
 * first via `verifyUnlockSecret`. Once an account's last keyring is gone this
 * client's keys are unrecoverable, so callers must wipe/dispose the data
 * Space before deleting the final method.
 *
 * @param options {object}
 * @param options.secret {string | Uint8Array}   the unlock secret
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @param [options.idb] {IDBFactory}
 * @param [options.credential] {UnlockCredential}   an already-derived
 *   credential for this secret (account deletion verifies then deletes on
 *   one derivation)
 * @returns {Promise<{ unlockSpaceDeleted: boolean }>}
 */
export async function deleteUnlockMethod({
  secret,
  kdf,
  idb,
  credential
}: {
  secret: string | Uint8Array
  kdf: UnlockKdf
  idb?: IDBFactory
  credential?: UnlockCredential
}): Promise<{ unlockSpaceDeleted: boolean }> {
  const unlockSpaceDeleted = await retireUnlockIdentity({
    unlock: credential?.unlock ?? (await deriveUnlockIdentity({ secret, kdf })),
    warning: 'Could not delete the unlock Space',
    idb
  })

  return { unlockSpaceDeleted }
}

/**
 * Retires a passphrase's keyring as part of account deletion -- the
 * passphrase-shaped wrapper over `deleteUnlockMethod`, defaulting to the
 * app's passphrase KDF.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}
 * @param [options.credential] {UnlockCredential}   an already-derived
 *   credential for this passphrase
 * @returns {Promise<{ unlockSpaceDeleted: boolean }>}
 */
export async function deleteKeyring({
  passphrase,
  idb,
  kdf = KEYRING_KDF,
  credential
}: {
  passphrase: string
  idb?: IDBFactory
  kdf?: UnlockKdf
  credential?: UnlockCredential
}): Promise<{ unlockSpaceDeleted: boolean }> {
  return deleteUnlockMethod({ secret: passphrase, kdf, idb, credential })
}

/**
 * Changes the account passphrase. Verifies the old passphrase by unwrapping
 * its keyring (the remote copy when a WAS server is configured -- the source
 * of truth -- else the local cache) and matching the recovered controller
 * against the account did:key, binds the new passphrase (re-wrapping this
 * client's key set, the user key, and the did:webvh update-key seeds, and carrying
 * the verified record's email and pointer forward), then deletes the old
 * unlock Space and this method's old local records.
 *
 * A missing record, or one that fails to unwrap or whose controller does not
 * match, is a `WrongPassphraseError`. A network error while reading the remote
 * record rethrows -- being unable to verify while the remote is unreachable
 * must not read as a wrong passphrase.
 *
 * `oldPassphraseRetired` reflects whether the old unlock Space is gone: `true`
 * when its deletion succeeded or was skipped because old == new, `false` only
 * when the deletion failed. An old == new passphrase call rebinds in place and
 * never deletes the just-written Space.
 *
 * The new passphrase's `unlockSpaceId` and `manageCapability` are returned (the
 * new bind delegates the management zcap to `controller`), so Settings can
 * update the unlock-methods registry's passphrase entry to the new Space and
 * its revocation authority -- along with the new bind's `persistClientKeys`
 * closure, so the live session can re-wrap the new record (a rotated user key,
 * rolled update-key seeds) without re-prompting for the passphrase.
 *
 * @param options {object}
 * @param options.clientSeed {Uint8Array}   this client's 32-byte seed
 * @param options.controller {string}   the account did:key
 * @param options.oldPassphrase {string}
 * @param options.newPassphrase {string}
 * @param [options.userKey] {UserKey}   the per-user key to carry into the new
 *   client-key record (the session's copy; falls back to the old record's)
 * @param [options.webvhUpdateKeys] {ClientWebvhUpdateKeys}   this client's
 *   did:webvh update-key seeds to carry into the new client-key record (the
 *   session's copy; falls back to the old record's)
 * @param [options.newCredential] {UnlockCredential}   an already-derived
 *   credential for the new passphrase (the standing-configuration ceremony derives
 *   it to mint the bridge delegation, so the rebind must not re-stretch)
 * @param [options.oldCredential] {UnlockCredential}   an already-derived
 *   credential for the old passphrase (the change ceremony derives it to
 *   settle the registry's recorded inventory against the typed secret, so the
 *   verification must not re-stretch either)
 * @param [options.delegation] {IZcap}   the new passphrase's bridge
 *   delegation, for a standing rebind (see `bindUnlockSecret`)
 * @param [options.delegatedClients] {IZcap}   the new passphrase's
 *   annex-Space sibling delegation, for a standing rebind
 * @param [options.ladderSeed] {Uint8Array}   the new passphrase's update-key
 *   ladder seed, for a standing rebind
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}
 * @returns {Promise<{ oldPassphraseRetired: boolean, unlockSpaceId: string,
 *   manageCapability?: IZcap, persistClientKeys: Function }>}
 */
export async function changePassphrase({
  clientSeed,
  controller,
  oldPassphrase,
  newPassphrase,
  userKey,
  webvhUpdateKeys,
  newCredential,
  oldCredential: derivedOldCredential,
  delegation,
  delegatedClients,
  ladderSeed,
  idb,
  kdf = KEYRING_KDF
}: {
  clientSeed: Uint8Array
  controller: string
  oldPassphrase: string
  newPassphrase: string
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  newCredential?: UnlockCredential
  oldCredential?: UnlockCredential
  delegation?: IZcap
  delegatedClients?: IZcap
  ladderSeed?: Uint8Array
  idb?: IDBFactory
  kdf?: UnlockKdf
}): Promise<{
  oldPassphraseRetired: boolean
  unlockSpaceId: string
  manageCapability?: IZcap
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
  oldLadderSeed?: Uint8Array
}> {
  const oldCredential =
    derivedOldCredential ??
    (await deriveUnlockCredential({
      secret: oldPassphrase,
      kdf
    }))
  const oldUnlock = oldCredential.unlock

  // Verify the old passphrase via its keyring. With a WAS server configured
  // the remote copy is read -- the source of truth, so a locally cached record
  // cannot verify a passphrase already retired on another client. A network
  // error while reading the remote rethrows -- an unreachable remote must not
  // be misread as a wrong passphrase. With no WAS server the local cache is
  // the keyring's only copy.
  const { found: verified, ladderSeed: oldLadderSeed } =
    await verifyUnlockKeyring({
      credential: oldCredential,
      controller,
      idb
    })

  // Prefer the caller's live user key and update-key seeds; fall back to the ones
  // cached in the old client-key record, so a rebind can never silently drop
  // them.
  const oldClientKeys = await loadClientKeys({ unlock: oldUnlock, idb })

  const {
    unlockSpaceId,
    manageCapability,
    persistClientKeys,
    unlockKeyAgreementKeyId,
    unlockKeyAgreementKeyMultibase
  } = await bindPassphrase({
    clientSeed,
    controller,
    passphrase: newPassphrase,
    // Preserve the account email and pointer carried by the old record, and
    // the user key and did:webvh update-key seeds, across the rebind.
    email: verified.email,
    pointer: verified.pointer,
    userKey: userKey ?? oldClientKeys?.userKey,
    webvhUpdateKeys: webvhUpdateKeys ?? oldClientKeys?.webvhUpdateKeys,
    // Delegate the new unlock Space's management zcap to the account
    // identity, so Settings can record it in the registry (and revoke this
    // method later).
    delegateManagementTo: unlockManagementGrantee({
      pointer: verified.pointer,
      controller
    }),
    delegation,
    delegatedClients,
    ladderSeed,
    idb,
    kdf,
    ...(newCredential ? { credential: newCredential } : {})
  })

  // Retire the old unlock identity -- but only when it differs from the new
  // one (an old == new rebind must not delete the records just written). The
  // spaceId is deterministic from the passphrase, so comparing the passphrases
  // answers this without a third unlock derivation.
  let oldSpaceDeleted = true
  if (newPassphrase !== oldPassphrase) {
    oldSpaceDeleted = await retireUnlockIdentity({
      unlock: oldUnlock,
      warning: 'Could not delete the old unlock Space',
      idb
    })
  }

  // The old unlock Space is gone (deleted, or old == new so nothing to delete);
  // only a failed deletion leaves the old passphrase live.
  return {
    oldPassphraseRetired: oldSpaceDeleted,
    unlockSpaceId,
    manageCapability,
    persistClientKeys,
    ...(unlockKeyAgreementKeyId ? { unlockKeyAgreementKeyId } : {}),
    ...(unlockKeyAgreementKeyMultibase
      ? { unlockKeyAgreementKeyMultibase }
      : {}),
    ...(oldLadderSeed ? { oldLadderSeed } : {})
  }
}
