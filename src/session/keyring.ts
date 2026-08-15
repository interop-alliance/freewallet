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
 * - The **keyring record** lives in the unlock identity's own Space
 *   (`keyring/keyring.json`) -- the only placement that is locatable before
 *   the account is known. Its payload is the **account pointer**
 *   `{ did, spaceId, host }` (plus the controller and the account email),
 *   wrapped (JWE, ECDH-ES to the unlock KAK) via the same EDV cipher the
 *   wallet already ships -- discovery for a portable credential, never key
 *   material -- and SIGNED by the unlock identity's own Ed25519 key. The
 *   retired wrapped data seed is gone: a passphrase on a fresh
 *   browser locates the account but cannot act until that client is enrolled.
 *   The remote copy is the source of truth and is consulted first on every
 *   login; a **local cache** in the `freewallet-session` IndexedDB serves
 *   no-WAS deployments and, within `KEYRING_CACHE_TTL_MS`, offline logins.
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
 * record the account has since moved off is authentic forever. So each client
 * pins the newest signed `createdAt` it has accepted for the unlock method, and
 * refuses a record older than the pin (`KeyringRecordRolledBackError`). Between
 * the two, a pointer that differs from anything this client has seen is simply
 * followed: a rebind, a host migration, or a fresh account under a reused
 * passphrase all produce a newer, validly signed record, and the honest answer
 * to one is to log in.
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
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import {
  KEYRING_CACHE_TTL_MS,
  UNLOCK_MANAGE_ZCAP_TTL_MS,
  WAS_SERVER_URL
} from '@/app.config'
import {
  isWebvhDid,
  type ClientWebvhUpdateKeys
} from '@interop/wallet-core/webvh'
import {
  decodeClientKeyRecord,
  encodeClientKeyRecord,
  type ClientKeyRecord,
  type UserKey
} from '@interop/wallet-core/keys'
import {
  deleteUnlockSpace,
  deriveUnlockIdentity,
  ensureUnlockSpace,
  getUnlockKeyring,
  putUnlockKeyring,
  unwrapKeyringRecord,
  wrapKeyringRecord,
  KEYRING_KDF,
  type AccountPointer,
  type KeyringRecordContents,
  type UnlockIdentity,
  type UnlockKdf
} from '@interop/wallet-core/keyring'
import {
  unwrapRecordEnvelope,
  wrapRecordEnvelope
} from '@/session/recordEnvelope'
import {
  deleteClientKeyRecord,
  deleteKeyringCache,
  deleteKeyringFreshnessPin,
  loadClientKeyRecord,
  loadKeyringCache,
  loadKeyringFreshnessPin,
  saveClientKeyRecord,
  saveKeyringCache,
  saveKeyringFreshnessPin
} from '@/lib/sessionKey'

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
 * seeds). The client seed itself is immutable for the record's lifetime.
 */
export interface PersistableClientKeys {
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
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
  // (and refreshes the local cache + freshness pin) without the unlock secret
  // -- the login-time heal path for a signup whose did:webvh backfill never
  // ran (a KMS hiccup): once a later login's provisioning publishes the log,
  // the pointer can durably adopt the did. In-memory only.
  persistAccountPointer?: (pointer: AccountPointer) => Promise<void>
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
 * A recovery code widens the actions to include PUT: that is what lets the
 * revocation cascade re-PUT the code's record with a freshly minted
 * delegation when the original's signing client is revoked.
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
  const invocationTarget = new URL(
    `/space/${spaceId}`,
    WAS_SERVER_URL
  ).toString()
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
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
async function saveClientKeys({
  unlock,
  clientSeed,
  userKey,
  webvhUpdateKeys,
  controller,
  idb
}: {
  unlock: UnlockIdentity
  clientSeed: Uint8Array
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  controller?: string
  idb?: IDBFactory
}): Promise<void> {
  const contents = encodeClientKeyRecord({
    clientSeed,
    ...(userKey ? { userKey } : {}),
    ...(webvhUpdateKeys ? { webvhUpdateKeys } : {}),
    ...(controller ? { controller } : {})
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
 * Builds the `persistClientKeys` closure over an unlock identity: loads the
 * current client-key record, merges the changed members, and re-wraps. A
 * missing or unusable record is left alone -- the closure must never
 * manufacture one. Holding the closure keeps the unlock identity's key
 * material in memory for the session; that is deliberate (it is what lets a
 * rotation persist without re-prompting for the secret) and adds no exposure
 * the in-memory client seed did not already carry.
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
    await saveClientKeys({
      unlock,
      clientSeed: clientKeys.clientSeed,
      userKey: changes.userKey ?? clientKeys.userKey,
      webvhUpdateKeys: changes.webvhUpdateKeys ?? clientKeys.webvhUpdateKeys,
      controller: clientKeys.controller,
      idb
    })
  }
}

/**
 * Builds the `persistAccountPointer` closure a fetch result carries: re-wraps
 * the keyring record with a changed account pointer under the same unlock
 * identity, signs it with that identity's record signer, PUTs it (when a WAS
 * server is configured), and refreshes the local cache and the freshness pin.
 * The controller and email are restated from
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
    // exact timestamp the record carries without re-reading it.
    const createdAt = new Date().toISOString()
    const record = await wrapKeyringRecord({
      controller: found.controller,
      email: found.email,
      pointer,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
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
    await saveKeyringFreshnessPin({ spaceId: unlock.spaceId, createdAt, idb })
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
    console.warn('Discarding an unusable client-key record:', err)
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
 * Thrown by `fetchKeyring` when a validly signed keyring record is OLDER than
 * the newest one this client has accepted for the unlock method -- a replay.
 * The proof cannot catch this on its own: a record the account has since moved
 * off stays authentic forever, so a host withholding the current record and
 * re-serving a superseded one would silently send this client at a stale
 * account pointer. The pin is left in place so a later, current record is
 * accepted normally.
 */
export class KeyringRecordRolledBackError extends Error {
  pinnedCreatedAt: string
  servedCreatedAt: string
  constructor({
    pinnedCreatedAt,
    servedCreatedAt
  }: {
    pinnedCreatedAt: string
    servedCreatedAt: string
  }) {
    super(
      `The keyring record served (${servedCreatedAt}) is older than the ` +
        `newest one this client has accepted (${pinnedCreatedAt}).`
    )
    this.name = 'KeyringRecordRolledBackError'
    this.pinnedCreatedAt = pinnedCreatedAt
    this.servedCreatedAt = servedCreatedAt
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
 * Maps an unwrap failure onto its typed refusal: a proof failure is the
 * host-forgery refusal, anything else is a corrupt/unreadable record.
 *
 * @param err {unknown}
 * @returns {Error}
 */
function keyringUnwrapError(err: unknown): Error {
  return isRecordProofError(err)
    ? new KeyringRecordForgedError({ cause: err })
    : new KeyringRecordUnusableError({ cause: err })
}

/**
 * Enforces freshness for a verified, unwrapped record: refuses one whose
 * signed bind timestamp predates the local pin (throws
 * `KeyringRecordRolledBackError`), and otherwise advances the pin. The first
 * accepted record establishes it; it only ever moves forward, so an equal
 * timestamp (the same record, re-read) passes untouched.
 *
 * Nothing here inspects the account pointer: a record naming somewhere this
 * client has never seen is legitimate whenever it is the newest signed one --
 * a rebind, a host migration, or a fresh account bound under a reused
 * passphrase.
 *
 * @param options {object}
 * @param options.unlock {UnlockIdentity}
 * @param options.found {KeyringRecordContents}   the unwrapped remote record
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
async function enforceRecordFreshness({
  unlock,
  found,
  idb
}: {
  unlock: UnlockIdentity
  found: KeyringRecordContents
  idb?: IDBFactory
}): Promise<void> {
  const pinnedCreatedAt = await loadKeyringFreshnessPin({
    spaceId: unlock.spaceId,
    idb
  })
  if (
    pinnedCreatedAt &&
    Date.parse(found.createdAt) < Date.parse(pinnedCreatedAt)
  ) {
    throw new KeyringRecordRolledBackError({
      pinnedCreatedAt,
      servedCreatedAt: found.createdAt
    })
  }
  await saveKeyringFreshnessPin({
    spaceId: unlock.spaceId,
    createdAt: found.createdAt,
    idb
  })
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
 * @param options.unlock {UnlockIdentity}
 * @param options.mintManageCapability {boolean}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<KeyringFetchResult | null>}
 */
async function readCachedRecord({
  cached,
  unlock,
  mintManageCapability,
  idb
}: {
  cached: { record: unknown }
  unlock: UnlockIdentity
  mintManageCapability: boolean
  idb?: IDBFactory
}): Promise<KeyringFetchResult | null> {
  try {
    // A cached record is still a signed record and this client holds the
    // verification key, so it is verified exactly as a remote one is -- the
    // cache is local state a page script could reach, not a trusted origin.
    const unwrapped = await unwrapKeyringRecord({
      record: cached.record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase
    })
    return await buildFetchResult({
      found: unwrapped,
      unlock,
      mintManageCapability,
      idb
    })
  } catch (err) {
    console.warn('Discarding an unusable cached keyring record:', err)
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
 * the cached copy and the freshness pin and returns `null` (no account for this
 * secret -- never bound, or retired). The local client-key record is left
 * alone on a miss: it is the only copy of this client's keys, and a server
 * answer must never be able to destroy it. When the remote GET fails
 * (network/unreachable), the cache answers as an offline fallback, but only
 * within `KEYRING_CACHE_TTL_MS`; past that (or with no usable cache) the
 * error rethrows, so the caller sees "could not check" rather than misreading
 * it as "no account". A remote record whose proof does not verify against the
 * unlock identity's own signing key throws `KeyringRecordForgedError` (the
 * host forged or tampered with it); one that fails to unwrap or validate for
 * any other reason throws `KeyringRecordUnusableError` (corrupt record -- a
 * state distinct from both "no account" and "server unreachable"); one older
 * than the local freshness pin throws `KeyringRecordRolledBackError` (a
 * replay). None of the three refreshes the cache. With no
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
 * @param [options.unlock] {UnlockIdentity}   an already-derived unlock
 *   identity for the same secret, so a flow that unlocks more than once
 *   (finishing an enrollment) runs the KDF a single time
 * @returns {Promise<KeyringFetchResult | null>}
 */
export async function fetchKeyring({
  secret,
  passphrase,
  idb,
  kdf = KEYRING_KDF,
  mintManageCapability = false,
  unlock: derived
}: {
  secret?: string | Uint8Array
  passphrase?: string
  idb?: IDBFactory
  kdf?: UnlockKdf
  mintManageCapability?: boolean
  unlock?: UnlockIdentity
}): Promise<KeyringFetchResult | null> {
  const unlockSecret = secret ?? passphrase
  if (!derived && unlockSecret === undefined) {
    throw new TypeError('An unlock secret is required.')
  }
  const unlock =
    derived ??
    (await deriveUnlockIdentity({
      secret: unlockSecret as string | Uint8Array,
      kdf
    }))

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
      unlock,
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
      unlock,
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
    // cached copy so the retired passphrase cannot keep resolving offline,
    // and the freshness pin -- the continuity prior is stale once this client
    // has seen "no account". The client-key record stays: it is primary
    // state, and without a session it is inert anyway.
    await deleteKeyringCache({ spaceId: unlock.spaceId, idb })
    await deleteKeyringFreshnessPin({ spaceId: unlock.spaceId, idb })
    return null
  }

  let found: KeyringRecordContents
  try {
    found = await unwrapKeyringRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase
    })
  } catch (err) {
    // A record exists under the correct unlock Space but does not open: a
    // forged one (its proof was not made by the key the typed secret derives)
    // or a corrupt/malformed one. Neither is a wrong passphrase -- that
    // resolves to a different Space and misses above -- so each surfaces as
    // its own state, and neither ever refreshes the cache.
    throw keyringUnwrapError(err)
  }
  // The freshness check runs before the cache refresh, so a replayed record
  // is neither followed nor allowed to become tomorrow's offline fallback.
  await enforceRecordFreshness({ unlock, found, idb })
  await saveKeyringCache({ spaceId: unlock.spaceId, record, idb })
  return await buildFetchResult({ found, unlock, mintManageCapability, idb })
}

/**
 * Assembles a `fetchKeyring` hit: the unwrapped record contents plus the
 * derived unlock Space id, this client's key set when one is stored under the
 * unlock method, and, when requested and a WAS server is configured, the
 * management zcap delegated to the recovered controller.
 *
 * @param options {object}
 * @param options.found {KeyringRecordContents}   the unwrapped record
 * @param options.unlock {UnlockIdentity}
 * @param options.mintManageCapability {boolean}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<KeyringFetchResult>}
 */
async function buildFetchResult({
  found,
  unlock,
  mintManageCapability,
  idb
}: {
  found: KeyringRecordContents
  unlock: UnlockIdentity
  mintManageCapability: boolean
  idb?: IDBFactory
}): Promise<KeyringFetchResult> {
  const clientKeys = await loadClientKeys({ unlock, idb })
  const result: KeyringFetchResult = {
    ...found,
    unlockSpaceId: unlock.spaceId,
    ...(clientKeys
      ? {
          clientKeys,
          persistClientKeys: clientKeysPersister({ unlock, idb }),
          persistAccountPointer: accountPointerPersister({ unlock, found, idb })
        }
      : {})
  }
  if (mintManageCapability && WAS_SERVER_URL) {
    result.manageCapability = await delegateUnlockManagement({
      zcapClient: unlock.zcapClient,
      spaceId: unlock.spaceId,
      controller: unlockManagementGrantee({
        pointer: found.pointer,
        controller: found.controller
      })
    })
  }
  return result
}

/**
 * Binds an unlock secret to this client's key set and the account it belongs
 * to: derives the unlock identity for the method's KDF, ensures the unlock
 * Space (when WAS is configured), wraps, signs, and PUTs the account-pointer
 * keyring
 * record, wraps the client seed + user key into the local client-key record,
 * seeds the freshness pin with the timestamp it just signed, and saves the
 * local cache. Throws on failure (the caller
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
 * @param [options.idb] {IDBFactory}
 * @param [options.unlock] {UnlockIdentity}   an already-derived unlock
 *   identity for the same secret and KDF, so a flow that unlocks more than
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
  idb,
  unlock: derived
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
  idb?: IDBFactory
  unlock?: UnlockIdentity
}): Promise<{
  unlockSpaceId: string
  manageCapability?: IZcap
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
}> {
  const unlock = derived ?? (await deriveUnlockIdentity({ secret, kdf }))
  // The bind timestamp is stamped here rather than left to the codec, so this
  // client seeds its freshness pin with exactly what it signed.
  const createdAt = new Date().toISOString()
  const record = await wrapKeyringRecord({
    controller,
    email,
    pointer,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver,
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
      // unlock identity from the (possibly lost) secret. Pure signing.
      manageCapability = await delegateUnlockManagement({
        zcapClient: unlock.zcapClient,
        spaceId: unlock.spaceId,
        controller: delegateManagementTo
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
    idb
  })
  await saveKeyringFreshnessPin({ spaceId: unlock.spaceId, createdAt, idb })

  return {
    unlockSpaceId: unlock.spaceId,
    manageCapability,
    persistClientKeys: clientKeysPersister({ unlock, idb })
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
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}
 * @param [options.unlock] {UnlockIdentity}   an already-derived unlock
 *   identity for the same passphrase (see `bindUnlockSecret`)
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
  idb,
  kdf = KEYRING_KDF,
  unlock
}: {
  clientSeed: Uint8Array
  controller: string
  passphrase: string
  email?: string
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  pointer?: AccountPointer
  delegateManagementTo?: string
  idb?: IDBFactory
  kdf?: UnlockKdf
  unlock?: UnlockIdentity
}): Promise<{
  unlockSpaceId: string
  manageCapability?: IZcap
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
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
    idb,
    ...(unlock ? { unlock } : {})
  })
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
 * @param options.unlock {UnlockIdentity}
 *   the unlock identity for the passphrase being verified
 * @param options.controller {string}   the account did:key to match
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<KeyringRecordContents>}   the verified record's unwrapped
 *   contents (so a rebind can preserve fields such as the email and pointer)
 */
async function verifyUnlockKeyring({
  unlock,
  controller,
  idb
}: {
  unlock: UnlockIdentity
  controller: string
  idb?: IDBFactory
}): Promise<KeyringRecordContents> {
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
  let unwrapped: KeyringRecordContents | null = null
  try {
    unwrapped = await unwrapKeyringRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase
    })
  } catch {
    // A record that does not unwrap for this controller is a wrong passphrase.
  }
  if (!unwrapped || unwrapped.controller !== controller) {
    throw new WrongPassphraseError()
  }
  return unwrapped
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
 * @param [options.unlock] {UnlockIdentity}   an already-derived identity for
 *   this secret, so a caller running several unlock-layer steps pays the KDF
 *   once
 * @returns {Promise<void>}
 */
async function verifyUnlockSecret({
  controller,
  secret,
  kdf,
  idb,
  unlock
}: {
  controller: string
  secret: string | Uint8Array
  kdf: UnlockKdf
  idb?: IDBFactory
  unlock?: UnlockIdentity
}): Promise<void> {
  await verifyUnlockKeyring({
    unlock: unlock ?? (await deriveUnlockIdentity({ secret, kdf })),
    controller,
    idb
  })
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
 * @param [options.unlock] {UnlockIdentity}   an already-derived identity for
 *   this passphrase
 * @returns {Promise<void>}
 */
export async function verifyPassphrase({
  controller,
  passphrase,
  idb,
  kdf = KEYRING_KDF,
  unlock
}: {
  controller: string
  passphrase: string
  idb?: IDBFactory
  kdf?: UnlockKdf
  unlock?: UnlockIdentity
}): Promise<void> {
  return verifyUnlockSecret({
    controller,
    secret: passphrase,
    kdf,
    idb,
    unlock
  })
}

/**
 * Retires one unlock identity: its unlock Space on the server (best effort)
 * and every local record filed under it (the keyring cache, the client-key
 * record, the keyring-freshness pin). Shared by `deleteUnlockMethod` and the
 * old-identity half of `changePassphrase`.
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
      console.warn(warning, err)
      unlockSpaceDeleted = false
    }
  }
  await deleteKeyringCache({ spaceId: unlock.spaceId, idb })
  await deleteClientKeyRecord({ spaceId: unlock.spaceId, idb })
  await deleteKeyringFreshnessPin({ spaceId: unlock.spaceId, idb })
  return unlockSpaceDeleted
}

/**
 * Retires an unlock method's keyring (account deletion, method removal):
 * derives the unlock identity, deletes its unlock Space (when a WAS server is
 * configured), and always clears the local records -- the cache, the
 * freshness pin, and this method's client-key record (an explicit lifecycle
 * flow is the one place a client-key record may be deleted). With no WAS server
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
 * @param [options.unlock] {UnlockIdentity}   an already-derived identity for
 *   this secret (account deletion verifies then deletes on one derivation)
 * @returns {Promise<{ unlockSpaceDeleted: boolean }>}
 */
export async function deleteUnlockMethod({
  secret,
  kdf,
  idb,
  unlock
}: {
  secret: string | Uint8Array
  kdf: UnlockKdf
  idb?: IDBFactory
  unlock?: UnlockIdentity
}): Promise<{ unlockSpaceDeleted: boolean }> {
  const unlockSpaceDeleted = await retireUnlockIdentity({
    unlock: unlock ?? (await deriveUnlockIdentity({ secret, kdf })),
    warning: 'Could not delete the unlock Space:',
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
 * @param [options.unlock] {UnlockIdentity}   an already-derived identity for
 *   this passphrase
 * @returns {Promise<{ unlockSpaceDeleted: boolean }>}
 */
export async function deleteKeyring({
  passphrase,
  idb,
  kdf = KEYRING_KDF,
  unlock
}: {
  passphrase: string
  idb?: IDBFactory
  kdf?: UnlockKdf
  unlock?: UnlockIdentity
}): Promise<{ unlockSpaceDeleted: boolean }> {
  return deleteUnlockMethod({ secret: passphrase, kdf, idb, unlock })
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
  idb,
  kdf = KEYRING_KDF
}: {
  clientSeed: Uint8Array
  controller: string
  oldPassphrase: string
  newPassphrase: string
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  idb?: IDBFactory
  kdf?: UnlockKdf
}): Promise<{
  oldPassphraseRetired: boolean
  unlockSpaceId: string
  manageCapability?: IZcap
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
}> {
  const oldUnlock = await deriveUnlockIdentity({
    secret: oldPassphrase,
    kdf
  })

  // Verify the old passphrase via its keyring. With a WAS server configured
  // the remote copy is read -- the source of truth, so a locally cached record
  // cannot verify a passphrase already retired on another client. A network
  // error while reading the remote rethrows -- an unreachable remote must not
  // be misread as a wrong passphrase. With no WAS server the local cache is
  // the keyring's only copy.
  const verified = await verifyUnlockKeyring({
    unlock: oldUnlock,
    controller,
    idb
  })

  // Prefer the caller's live user key and update-key seeds; fall back to the ones
  // cached in the old client-key record, so a rebind can never silently drop
  // them.
  const oldClientKeys = await loadClientKeys({ unlock: oldUnlock, idb })

  const { unlockSpaceId, manageCapability, persistClientKeys } =
    await bindPassphrase({
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
      idb,
      kdf
    })

  // Retire the old unlock identity -- but only when it differs from the new
  // one (an old == new rebind must not delete the records just written). The
  // spaceId is deterministic from the passphrase, so comparing the passphrases
  // answers this without a third unlock derivation.
  let oldSpaceDeleted = true
  if (newPassphrase !== oldPassphrase) {
    oldSpaceDeleted = await retireUnlockIdentity({
      unlock: oldUnlock,
      warning: 'Could not delete the old unlock Space:',
      idb
    })
  }

  // The old unlock Space is gone (deleted, or old == new so nothing to delete);
  // only a failed deletion leaves the old passphrase live.
  return {
    oldPassphraseRetired: oldSpaceDeleted,
    unlockSpaceId,
    manageCapability,
    persistClientKeys
  }
}
