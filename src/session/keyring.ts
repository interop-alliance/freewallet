/**
 * Keyring v2 -- decouples the wallet identity from the passphrase.
 *
 * A freewallet account has two identities:
 *
 * - The **data identity** is the wallet's real root: the Ed25519 key pair
 *   behind the did:key, the spaceId, the KMS keystore controller, and the
 *   vault KAK. It is a random 32-byte seed, never derivable from any
 *   passphrase.
 * - The **unlock identity** is derived from an unlock secret at login -- the
 *   passphrase today; a passkey PRF output or a recovery code are further
 *   methods on the same seam (`unlockSeed = KDF(secret)` per the method's
 *   `UnlockKdf`, then `CapabilityAgent.fromSeed` with a distinct `'unlock'`
 *   handle so it can never collide with the data identity's `'bootstrap'`
 *   derivation). It controls nothing but its own minimal Space. One unlock
 *   method = one unlock identity = one unlock Space; each method's KDF salt
 *   differs, so two methods can never derive the same Space.
 *
 * The **keyring record** lives in the unlock identity's own Space
 * (`keyring/keyring.json`) -- the only placement that is locatable before the
 * data identity is known. Its payload is the data seed wrapped (JWE, ECDH-ES to
 * the unlock KAK) via the same EDV cipher the wallet already ships, so the
 * unlock Space never publicly links the two identities. The remote copy is the
 * source of truth and is consulted first on every login; a **local cache** of
 * the record in the `freewallet-session` IndexedDB database serves no-WAS
 * deployments and, within a bounded TTL (`KEYRING_CACHE_TTL_MS`), offline
 * logins when the remote is unreachable.
 *
 * A passphrase change re-wraps the data seed under a new unlock identity, PUTs
 * it to the new unlock Space, then deletes the old unlock Space -- which is
 * what retires the old passphrase (the random data seed is never derivable from
 * a passphrase, so once its unlock Space is gone the old passphrase resolves to
 * nothing). Because login checks the remote first, other devices see the
 * retirement on their next online login (their stale caches are dropped);
 * offline, a stale cache stops answering once its TTL lapses.
 *
 * Account deletion retires the keyring the same way -- it deletes the unlock
 * Space and its cache outright, after the caller has wiped the data Space
 * (once the keyring is gone the data seed is unrecoverable).
 */
import { CapabilityAgent } from '@interop/webkms-client'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { ZcapClient } from '@interop/ezcap'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IZcap
} from '@interop/data-integrity-core'
import {
  KEYRING_CACHE_TTL_MS,
  KEYRING_COLLECTION,
  KEYRING_KDF,
  UNLOCK_MANAGE_ZCAP_TTL_MS,
  WAS_SERVER_URL
} from '@/app.config'
import { bufferToBase64Url, digestHash } from '@/lib/cidFrom'
import { singleKeyResolver } from '@/lib/keyResolver'
import { createEdvDocCipher } from '@/stores/edvDocCipher'
import {
  deleteKeyringCache,
  loadKeyringCache,
  saveKeyringCache
} from '@/lib/sessionKey'
import {
  deleteUnlockSpace,
  ensureUnlockSpace,
  getUnlockKeyring,
  putUnlockKeyring
} from '@/stores/wasRemoteStore'

/**
 * Unlock-derivation parameters, one variant per KDF family: PBKDF2 stretches
 * a low-entropy passphrase; HKDF expands already-uniform key material (e.g. a
 * passkey PRF output). Each unlock method pins its own parameter set -- and
 * its own salt, so two methods can never derive the same unlock identity.
 * The `version` records which parameter set produced a derivation; the
 * keyring record's own `version` is stamped separately.
 */
export type UnlockKdf =
  | {
      version: number
      algorithm: 'PBKDF2'
      iterations: number
      hash: string
      salt: string
    }
  | {
      version: number
      algorithm: 'HKDF'
      hash: string
      salt: string
      info: string
    }

/**
 * The recovered data identity: the 32-byte data seed plus the controller
 * (data did:key) the keyring record carries alongside it. `email` is the
 * account email captured at bind time (when one was given) -- carried in the
 * record so any unlock method recovers it (a passkey login has no login form
 * to ask on).
 */
export interface KeyringSeed {
  seed: Uint8Array
  controller: string
  email?: string
}

/**
 * What `fetchKeyringSeed` returns to callers on a hit: the recovered data
 * identity (`KeyringSeed`), plus the derived unlock Space id (always -- it is
 * already computed) and, when `mintManageCapability` was requested and a WAS
 * server is configured, a management zcap the unlock identity delegated to the
 * recovered `controller`. The capability grants GET/DELETE on the unlock Space
 * only, so a later Settings flow can retire this method (a lost passkey) with
 * the session's root key -- no re-derivation from, or tap on, the secret.
 */
export interface KeyringFetchResult extends KeyringSeed {
  unlockSpaceId: string
  manageCapability?: IZcap
}

/**
 * Delegates the long-lived management zcap on an unlock Space to the data
 * identity: GET/DELETE on the unlock Space URL, controlled by the data did:key,
 * expiring after `UNLOCK_MANAGE_ZCAP_TTL_MS`. Pure signing (no server round
 * trip); the chain roots at the Space's synthesized root capability (the ezcap
 * client generates it from the target). Only ever called when a WAS server is
 * configured -- the unlock Space, and thus the capability, exist only then.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the unlock identity's client (it can
 *   both invoke and delegate)
 * @param options.spaceId {string}   the unlock Space id
 * @param options.controller {string}   the data did:key to delegate to
 * @returns {Promise<IZcap>}
 */
async function delegateUnlockManagement({
  zcapClient,
  spaceId,
  controller
}: {
  zcapClient: ZcapClient
  spaceId: string
  controller: string
}): Promise<IZcap> {
  const invocationTarget = new URL(
    `/space/${spaceId}`,
    WAS_SERVER_URL
  ).toString()
  return await zcapClient.delegate({
    invocationTarget,
    controller,
    allowedActions: ['GET', 'DELETE'],
    expires: new Date(Date.now() + UNLOCK_MANAGE_ZCAP_TTL_MS)
  })
}

/**
 * Decodes an (optionally unpadded) base64url string back to raw bytes. The
 * repo's encoder (`bufferToBase64Url`) strips padding, so re-pad before atob.
 *
 * @param value {string}
 * @returns {Uint8Array}
 */
function base64UrlToBytes(value: string): Uint8Array {
  let normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  while (normalized.length % 4 !== 0) {
    normalized += '='
  }
  const binary = atob(normalized)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

/**
 * Derives the 32-byte unlock seed from an unlock secret (WebCrypto),
 * branching on the KDF family: PBKDF2 stretches a passphrase, HKDF expands
 * already-uniform key material such as a passkey PRF output.
 *
 * @param options {object}
 * @param options.secret {string | Uint8Array}
 * @param options.kdf {UnlockKdf}
 * @returns {Promise<Uint8Array>}
 */
async function deriveUnlockSeed({
  secret,
  kdf
}: {
  secret: string | Uint8Array
  kdf: UnlockKdf
}): Promise<Uint8Array> {
  // Copy a bytes secret into a fresh buffer: WebCrypto's BufferSource wants a
  // plain ArrayBuffer-backed view, which a caller's slice may not be.
  const secretBytes =
    typeof secret === 'string'
      ? new TextEncoder().encode(secret)
      : new Uint8Array(secret)
  if (kdf.algorithm === 'PBKDF2') {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      secretBytes,
      'PBKDF2',
      false,
      ['deriveBits']
    )
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: new TextEncoder().encode(kdf.salt),
        iterations: kdf.iterations,
        hash: kdf.hash
      },
      baseKey,
      256
    )
    return new Uint8Array(bits)
  }
  const baseKey = await crypto.subtle.importKey(
    'raw',
    secretBytes,
    'HKDF',
    false,
    ['deriveBits']
  )
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: kdf.hash,
      salt: new TextEncoder().encode(kdf.salt),
      info: new TextEncoder().encode(kdf.info)
    },
    baseKey,
    256
  )
  return new Uint8Array(bits)
}

/**
 * Derives the full unlock identity from an unlock secret: the unlock
 * CapabilityAgent, a ZcapClient that can both invoke and delegate (the
 * unlock agent delegates a management zcap on its own Space to the data
 * identity at bind time), the unlock KAK + resolver for wrap/unwrap, and the
 * unlock Space id. Performs no I/O -- exported as the derivation seam for
 * tests and future unlock methods.
 *
 * @param options {object}
 * @param options.secret {string | Uint8Array}
 * @param options.kdf {UnlockKdf}
 * @returns {Promise<object>}
 */
export async function deriveUnlockIdentity({
  secret,
  kdf
}: {
  secret: string | Uint8Array
  kdf: UnlockKdf
}) {
  const seed = await deriveUnlockSeed({ secret, kdf })
  const agent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'unlock',
    keyName: 'unlock-key'
  })
  const signer = agent.getSigner()
  const zcapClient = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: signer,
    delegationSigner: signer
  })

  // The unlock KAK is the Montgomery form of the unlock signing key -- the same
  // derivation the data side uses (`agentsFromSeed`), so a returning user
  // reconstitutes the exact key that wrapped the keyring record.
  const keyAgreementKey =
    X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
      keyPair: agent.getVerificationKeyPair()
    })
  const keyResolver: IKeyResolver = singleKeyResolver({ keyAgreementKey })

  const spaceId = bufferToBase64Url(await digestHash(agent.id))
  return { agent, zcapClient, keyAgreementKey, keyResolver, spaceId }
}

/**
 * Wraps a data seed into a keyring record: the seed (+ controller / timestamp)
 * encrypted under the unlock KAK via the EDV cipher.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}
 * @param options.controller {string}   the data did:key
 * @param [options.email] {string}   the account email, when known
 * @param options.keyAgreementKey {IKeyAgreementKey}   the unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<{ version: number, wrapped: unknown }>}
 */
async function wrapSeed({
  seed,
  controller,
  email,
  keyAgreementKey,
  keyResolver
}: {
  seed: Uint8Array
  controller: string
  email?: string
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<{ version: number; wrapped: unknown }> {
  const cipher = await createEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId: KEYRING_COLLECTION.id
  })
  const { envelope } = await cipher.encrypt({
    data: {
      seed: bufferToBase64Url(seed),
      controller,
      ...(email ? { email } : {}),
      createdAt: new Date().toISOString()
    }
  })
  return { version: 1, wrapped: envelope }
}

/**
 * Unwraps and validates a keyring record. Rejects a record whose `version` is
 * not 1, and sanity-checks the decrypted plaintext (32-byte seed, non-empty
 * controller). An extra `seedOrigin` field (written by records from earlier in
 * this session) is tolerated and ignored.
 *
 * @param options {object}
 * @param options.record {unknown}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<KeyringSeed>}
 */
async function unwrapSeed({
  record,
  keyAgreementKey,
  keyResolver
}: {
  record: unknown
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<KeyringSeed> {
  if (record === null || typeof record !== 'object') {
    throw new Error('Malformed keyring record.')
  }
  const { version, wrapped } = record as {
    version?: unknown
    wrapped?: unknown
  }
  if (version !== 1) {
    throw new Error(`Unsupported keyring record version "${String(version)}".`)
  }
  const cipher = await createEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId: KEYRING_COLLECTION.id
  })
  const plaintext = (await cipher.decrypt({
    envelope: wrapped as never
  })) as {
    seed?: unknown
    controller?: unknown
    email?: unknown
  }

  if (typeof plaintext.controller !== 'string' || !plaintext.controller) {
    throw new Error('Keyring record is missing a controller.')
  }
  if (typeof plaintext.seed !== 'string') {
    throw new Error('Keyring record is missing a seed.')
  }
  const seed = base64UrlToBytes(plaintext.seed)
  if (seed.length !== 32) {
    throw new Error('Keyring record seed is not 32 bytes.')
  }

  return {
    seed,
    controller: plaintext.controller,
    // A record written before emails were carried (or bound without one)
    // simply has no email; anything non-string is ignored, not fatal.
    ...(typeof plaintext.email === 'string' && plaintext.email
      ? { email: plaintext.email }
      : {})
  }
}

/**
 * Thrown by `fetchKeyringSeed` when a keyring record was found under the
 * passphrase's unlock Space but could not be unwrapped or validated -- a
 * genuinely corrupt/malformed record. Distinct from "no account" (a `null`
 * return; a wrong passphrase resolves to a different unlock Space and misses)
 * and from an unreachable server (a rethrown network error), so callers can
 * surface it with its own recovery guidance.
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
 * Locates and unwraps the keyring for an unlock secret. When a WAS server is
 * configured the remote copy is consulted first -- it is the source of truth,
 * and checking it before the cache is what makes a method change (e.g. a
 * passphrase change) on another device take effect here: a found record
 * refreshes the local cache, while a 404-shaped miss (a null record) drops
 * any cached copy and returns `null` (no account for this secret -- never
 * bound, or retired). When the remote GET fails (network/unreachable), the
 * cache answers as an offline fallback, but only within
 * `KEYRING_CACHE_TTL_MS`; past that (or with no usable cache) the error
 * rethrows, so the caller sees "could not check" rather than misreading it as
 * "no account". A remote record that fails to unwrap or validate throws
 * `KeyringRecordUnusableError` (corrupt record -- a state distinct from both
 * "no account" and "server unreachable") and never refreshes the cache. With
 * no WAS server configured the cache is the keyring's only copy, so the
 * lookup is cache-only with no TTL.
 *
 * The result on a hit always carries the derived `unlockSpaceId` (cheap -- it
 * is already computed); when `mintManageCapability` is set and a WAS server is
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
 * @returns {Promise<KeyringFetchResult | null>}
 */
export async function fetchKeyringSeed({
  secret,
  passphrase,
  idb,
  kdf = KEYRING_KDF,
  mintManageCapability = false
}: {
  secret?: string | Uint8Array
  passphrase?: string
  idb?: IDBFactory
  kdf?: UnlockKdf
  mintManageCapability?: boolean
}): Promise<KeyringFetchResult | null> {
  const unlockSecret = secret ?? passphrase
  if (unlockSecret === undefined) {
    throw new TypeError('An unlock secret is required.')
  }
  const unlock = await deriveUnlockIdentity({ secret: unlockSecret, kdf })

  if (!WAS_SERVER_URL) {
    // No remote: the cache is the keyring's only copy -- authoritative, no TTL.
    const cached = await loadKeyringCache({ spaceId: unlock.spaceId, idb })
    if (!cached) {
      return null
    }
    try {
      const unwrapped = await unwrapSeed({
        record: cached.record,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver
      })
      return await buildFetchResult({
        found: unwrapped,
        unlock,
        mintManageCapability
      })
    } catch (err) {
      console.warn('Discarding an unusable cached keyring record:', err)
      await deleteKeyringCache({ spaceId: unlock.spaceId, idb })
      return null
    }
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
    try {
      const unwrapped = await unwrapSeed({
        record: cached.record,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver
      })
      return await buildFetchResult({
        found: unwrapped,
        unlock,
        mintManageCapability
      })
    } catch (unwrapErr) {
      console.warn('Discarding an unusable cached keyring record:', unwrapErr)
      await deleteKeyringCache({ spaceId: unlock.spaceId, idb })
      throw err
    }
  }

  if (!record) {
    // A 404-shaped miss: no keyring for this passphrase (never bound, or
    // retired by a passphrase change on this or another device). Drop any
    // cached copy so the retired passphrase cannot keep resolving offline.
    await deleteKeyringCache({ spaceId: unlock.spaceId, idb })
    return null
  }

  let found: KeyringSeed
  try {
    found = await unwrapSeed({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver
    })
  } catch (err) {
    // A record exists under the correct unlock Space but does not unwrap:
    // a corrupt/malformed record, not a wrong passphrase (that resolves to
    // a different Space and misses above). Surface it as its own state --
    // and never refresh the cache from an unusable record.
    throw new KeyringRecordUnusableError({ cause: err })
  }
  await saveKeyringCache({ spaceId: unlock.spaceId, record, idb })
  return await buildFetchResult({ found, unlock, mintManageCapability })
}

/**
 * Assembles a `fetchKeyringSeed` hit: the unwrapped `KeyringSeed` plus the
 * derived unlock Space id and, when requested and a WAS server is configured,
 * the management zcap delegated to the recovered controller.
 *
 * @param options {object}
 * @param options.found {KeyringSeed}   the unwrapped record
 * @param options.unlock {Awaited<ReturnType<typeof deriveUnlockIdentity>>}
 * @param options.mintManageCapability {boolean}
 * @returns {Promise<KeyringFetchResult>}
 */
async function buildFetchResult({
  found,
  unlock,
  mintManageCapability
}: {
  found: KeyringSeed
  unlock: Awaited<ReturnType<typeof deriveUnlockIdentity>>
  mintManageCapability: boolean
}): Promise<KeyringFetchResult> {
  const result: KeyringFetchResult = {
    ...found,
    unlockSpaceId: unlock.spaceId
  }
  if (mintManageCapability && WAS_SERVER_URL) {
    result.manageCapability = await delegateUnlockManagement({
      zcapClient: unlock.zcapClient,
      spaceId: unlock.spaceId,
      controller: found.controller
    })
  }
  return result
}

/**
 * Binds an unlock secret to a data seed: derives the unlock identity for the
 * method's KDF, ensures the unlock Space (when WAS is configured), wraps and
 * PUTs the keyring record, and saves the local cache. Throws on failure (the
 * caller decides fatality -- fatal for signups). With no WAS server configured
 * the keyring is cache-only, so the account is then only recoverable in this
 * browser profile. Returns the unlock Space id so callers (the unlock-methods
 * registry) can record which Space this method resolves to.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the data seed
 * @param options.controller {string}   the data did:key
 * @param options.secret {string | Uint8Array}   the unlock secret
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @param [options.email] {string}   the account email, carried in the wrapped
 *   record so any unlock method recovers it at login
 * @param [options.delegateManagementTo] {string}   a data did:key to delegate
 *   the unlock Space management zcap to (GET/DELETE on this unlock Space). When
 *   set and a WAS server is configured, the returned `manageCapability` is the
 *   revocation authority a later Settings flow uses to retire this method (a
 *   lost passkey) without tapping or re-deriving from the secret.
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ unlockSpaceId: string, manageCapability?: IZcap }>}
 */
export async function bindUnlockSecret({
  seed,
  controller,
  secret,
  kdf,
  email,
  delegateManagementTo,
  idb
}: {
  seed: Uint8Array
  controller: string
  secret: string | Uint8Array
  kdf: UnlockKdf
  email?: string
  delegateManagementTo?: string
  idb?: IDBFactory
}): Promise<{ unlockSpaceId: string; manageCapability?: IZcap }> {
  const unlock = await deriveUnlockIdentity({ secret, kdf })
  const record = await wrapSeed({
    seed,
    controller,
    email,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver
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
      // The unlock agent delegates GET/DELETE on its own Space to the data
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

  return { unlockSpaceId: unlock.spaceId, manageCapability }
}

/**
 * Binds a passphrase to a data seed -- the passphrase-shaped wrapper over
 * `bindUnlockSecret`, defaulting to the app's passphrase KDF.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the data seed
 * @param options.controller {string}   the data did:key
 * @param options.passphrase {string}
 * @param [options.email] {string}   the account email, carried in the wrapped
 *   record
 * @param [options.delegateManagementTo] {string}   a data did:key to delegate
 *   the unlock Space management zcap to (see `bindUnlockSecret`)
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}
 * @returns {Promise<{ unlockSpaceId: string, manageCapability?: IZcap }>}
 */
export async function bindPassphrase({
  seed,
  controller,
  passphrase,
  email,
  delegateManagementTo,
  idb,
  kdf = KEYRING_KDF
}: {
  seed: Uint8Array
  controller: string
  passphrase: string
  email?: string
  delegateManagementTo?: string
  idb?: IDBFactory
  kdf?: UnlockKdf
}): Promise<{ unlockSpaceId: string; manageCapability?: IZcap }> {
  return bindUnlockSecret({
    seed,
    controller,
    secret: passphrase,
    kdf,
    email,
    delegateManagementTo,
    idb
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
 * Verifies an already-derived unlock identity against a data controller by
 * reading and unwrapping its keyring record. When a WAS server is configured
 * the remote copy is read -- the source of truth, so a locally cached record
 * cannot verify a passphrase already retired on another device; with no WAS
 * server the local cache is the keyring's only copy.
 *
 * A missing record, or one that fails to unwrap or whose controller does not
 * match, is a `WrongPassphraseError`. A network error while reading the remote
 * record rethrows unchanged -- being unable to verify while the remote is
 * unreachable must not read as a wrong passphrase. Shared by `changePassphrase`
 * and `verifyPassphrase`.
 *
 * @param options {object}
 * @param options.unlock {Awaited<ReturnType<typeof deriveUnlockIdentity>>}
 *   the unlock identity for the passphrase being verified
 * @param options.controller {string}   the data did:key to match
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<KeyringSeed>}   the verified record's unwrapped contents
 *   (so a rebind can preserve fields such as the email)
 */
async function verifyUnlockKeyring({
  unlock,
  controller,
  idb
}: {
  unlock: Awaited<ReturnType<typeof deriveUnlockIdentity>>
  controller: string
  idb?: IDBFactory
}): Promise<KeyringSeed> {
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
  let unwrapped: KeyringSeed | null = null
  try {
    unwrapped = await unwrapSeed({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver
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
 * the shared keyring verification against `controller` (the data did:key).
 *
 * Throws `WrongPassphraseError` when the secret does not unlock a keyring
 * bound to `controller`. A network error while reading the remote record
 * rethrows unchanged -- an unreachable remote must not read as a wrong
 * secret.
 *
 * @param options {object}
 * @param options.controller {string}   the data did:key
 * @param options.secret {string | Uint8Array}   the unlock secret
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function verifyUnlockSecret({
  controller,
  secret,
  kdf,
  idb
}: {
  controller: string
  secret: string | Uint8Array
  kdf: UnlockKdf
  idb?: IDBFactory
}): Promise<void> {
  const unlock = await deriveUnlockIdentity({ secret, kdf })
  await verifyUnlockKeyring({ unlock, controller, idb })
}

/**
 * Verifies a passphrase against its keyring -- the passphrase-shaped wrapper
 * over `verifyUnlockSecret`, defaulting to the app's passphrase KDF.
 *
 * @param options {object}
 * @param options.controller {string}   the data did:key
 * @param options.passphrase {string}
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}
 * @returns {Promise<void>}
 */
export async function verifyPassphrase({
  controller,
  passphrase,
  idb,
  kdf = KEYRING_KDF
}: {
  controller: string
  passphrase: string
  idb?: IDBFactory
  kdf?: UnlockKdf
}): Promise<void> {
  return verifyUnlockSecret({ controller, secret: passphrase, kdf, idb })
}

/**
 * Retires an unlock method's keyring (account deletion, method removal):
 * derives the unlock identity, deletes its unlock Space (when a WAS server is
 * configured), and always clears the local cache. With no WAS server
 * configured there is no Space, so `unlockSpaceDeleted` stays `true`.
 *
 * Performs no verification -- a wrong secret derives a different unlock Space
 * id and `deleteUnlockSpace` is idempotent, so callers confirm the secret
 * first via `verifyUnlockSecret`. Once an account's last keyring is gone the
 * data seed is unrecoverable (the random data seed is never derivable from an
 * unlock secret), so callers must wipe/dispose the data Space before deleting
 * the final method.
 *
 * @param options {object}
 * @param options.secret {string | Uint8Array}   the unlock secret
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<{ unlockSpaceDeleted: boolean }>}
 */
export async function deleteUnlockMethod({
  secret,
  kdf,
  idb
}: {
  secret: string | Uint8Array
  kdf: UnlockKdf
  idb?: IDBFactory
}): Promise<{ unlockSpaceDeleted: boolean }> {
  const unlock = await deriveUnlockIdentity({ secret, kdf })

  let unlockSpaceDeleted = true
  if (WAS_SERVER_URL) {
    try {
      await deleteUnlockSpace({
        storageServerUrl: WAS_SERVER_URL,
        zcapClient: unlock.zcapClient,
        spaceId: unlock.spaceId
      })
    } catch (err) {
      console.warn('Could not delete the unlock Space:', err)
      unlockSpaceDeleted = false
    }
  }
  await deleteKeyringCache({ spaceId: unlock.spaceId, idb })

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
 * @returns {Promise<{ unlockSpaceDeleted: boolean }>}
 */
export async function deleteKeyring({
  passphrase,
  idb,
  kdf = KEYRING_KDF
}: {
  passphrase: string
  idb?: IDBFactory
  kdf?: UnlockKdf
}): Promise<{ unlockSpaceDeleted: boolean }> {
  return deleteUnlockMethod({ secret: passphrase, kdf, idb })
}

/**
 * Changes the account passphrase. Verifies the old passphrase by unwrapping its
 * keyring (the remote copy when a WAS server is configured -- the source of
 * truth -- else the local cache) and matching the recovered controller against
 * the data did:key, binds the new passphrase, then deletes the old unlock Space
 * and its cache entry.
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
 * its revocation authority.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the data seed
 * @param options.controller {string}   the data did:key
 * @param options.oldPassphrase {string}
 * @param options.newPassphrase {string}
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}
 * @returns {Promise<{ oldPassphraseRetired: boolean, unlockSpaceId: string, manageCapability?: IZcap }>}
 */
export async function changePassphrase({
  seed,
  controller,
  oldPassphrase,
  newPassphrase,
  idb,
  kdf = KEYRING_KDF
}: {
  seed: Uint8Array
  controller: string
  oldPassphrase: string
  newPassphrase: string
  idb?: IDBFactory
  kdf?: UnlockKdf
}): Promise<{
  oldPassphraseRetired: boolean
  unlockSpaceId: string
  manageCapability?: IZcap
}> {
  const oldUnlock = await deriveUnlockIdentity({
    secret: oldPassphrase,
    kdf
  })

  // Verify the old passphrase via its keyring. With a WAS server configured
  // the remote copy is read -- the source of truth, so a locally cached record
  // cannot verify a passphrase already retired on another device. A network
  // error while reading the remote rethrows -- an unreachable remote must not
  // be misread as a wrong passphrase. With no WAS server the local cache is
  // the keyring's only copy.
  const verified = await verifyUnlockKeyring({
    unlock: oldUnlock,
    controller,
    idb
  })

  const { unlockSpaceId, manageCapability } = await bindPassphrase({
    seed,
    controller,
    passphrase: newPassphrase,
    // Preserve the account email carried by the old record across the rebind.
    email: verified.email,
    // Delegate the new unlock Space's management zcap to the data identity, so
    // Settings can record it in the registry (and revoke this method later).
    delegateManagementTo: controller,
    idb,
    kdf
  })

  // Retire the old unlock identity -- but only when it differs from the new
  // one (an old == new rebind must not delete the Space just written). The
  // spaceId is deterministic from the passphrase, so comparing the passphrases
  // answers this without a third unlock derivation.
  let oldSpaceDeleted = true
  if (newPassphrase !== oldPassphrase) {
    if (WAS_SERVER_URL) {
      try {
        await deleteUnlockSpace({
          storageServerUrl: WAS_SERVER_URL,
          zcapClient: oldUnlock.zcapClient,
          spaceId: oldUnlock.spaceId
        })
      } catch (err) {
        console.warn('Could not delete the old unlock Space:', err)
        oldSpaceDeleted = false
      }
    }
    await deleteKeyringCache({ spaceId: oldUnlock.spaceId, idb })
  }

  // The old unlock Space is gone (deleted, or old == new so nothing to delete);
  // only a failed deletion leaves the old passphrase live.
  return {
    oldPassphraseRetired: oldSpaceDeleted,
    unlockSpaceId,
    manageCapability
  }
}
