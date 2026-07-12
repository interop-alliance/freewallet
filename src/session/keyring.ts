/**
 * Keyring v2 -- decouples the wallet identity from the passphrase.
 *
 * A freewallet account has two identities:
 *
 * - The **data identity** is the wallet's real root: the Ed25519 key pair
 *   behind the did:key, the spaceId, the KMS keystore controller, and the
 *   vault KAK. It is a random 32-byte seed, never derivable from any
 *   passphrase.
 * - The **unlock identity** is derived from the passphrase at login
 *   (`unlockSeed = PBKDF2(passphrase)`, then `CapabilityAgent.fromSeed` with a
 *   distinct `'unlock'` handle so it can never collide with the data identity's
 *   `'bootstrap'` derivation). It controls nothing but its own minimal Space.
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
 */
import { CapabilityAgent } from '@interop/webkms-client'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { ZcapClient } from '@interop/ezcap'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import {
  KEYRING_CACHE_TTL_MS,
  KEYRING_COLLECTION,
  KEYRING_KDF,
  WAS_SERVER_URL
} from '@/app.config'
import { bufferToBase64Url, digestHash } from '@/lib/cidFrom'
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
 * PBKDF2 parameters for the unlock derivation. Defaults to `KEYRING_KDF`;
 * overridable so tests can dial the iteration count down to stay fast. The
 * `version` from `KEYRING_KDF` is stamped onto the record, not consumed here.
 */
type UnlockKdf = {
  iterations: number
  hash: string
  salt: string
}

/**
 * The recovered data identity: the 32-byte data seed plus the controller
 * (data did:key) the keyring record carries alongside it.
 */
export interface KeyringSeed {
  seed: Uint8Array
  controller: string
}

/**
 * Encodes raw bytes as an unpadded base64url string.
 *
 * @param bytes {Uint8Array}
 * @returns {string}
 */
function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
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
 * Stretches the passphrase into a 32-byte unlock seed via PBKDF2 (WebCrypto).
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param options.kdf {UnlockKdf}
 * @returns {Promise<Uint8Array>}
 */
async function deriveUnlockSeed({
  passphrase,
  kdf
}: {
  passphrase: string
  kdf: UnlockKdf
}): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
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

/**
 * Derives the full unlock identity from a passphrase: the unlock
 * CapabilityAgent, an invocation-only ZcapClient (the unlock agent never
 * delegates), the unlock KAK + resolver for wrap/unwrap, and the unlock
 * Space id.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param options.kdf {UnlockKdf}
 * @returns {Promise<object>}
 */
async function deriveUnlockIdentity({
  passphrase,
  kdf
}: {
  passphrase: string
  kdf: UnlockKdf
}) {
  const seed = await deriveUnlockSeed({ passphrase, kdf })
  const agent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'unlock',
    keyName: 'unlock-key'
  })
  const zcapClient = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: agent.getSigner()
  })

  // The unlock KAK is the Montgomery form of the unlock signing key -- the same
  // derivation the data side uses (`agentsFromSeed`), so a returning user
  // reconstitutes the exact key that wrapped the keyring record.
  const keyAgreementKey =
    X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
      keyPair: agent.getVerificationKeyPair()
    })
  const keyResolver: IKeyResolver = async ({ id }: { id?: string }) => {
    if (id !== keyAgreementKey.id) {
      throw new Error(`Unknown key id "${id}".`)
    }
    return {
      id: keyAgreementKey.id,
      type: keyAgreementKey.type,
      publicKeyMultibase: keyAgreementKey.publicKeyMultibase
    }
  }

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
 * @param options.keyAgreementKey {IKeyAgreementKey}   the unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<{ version: number, wrapped: unknown }>}
 */
async function wrapSeed({
  seed,
  controller,
  keyAgreementKey,
  keyResolver
}: {
  seed: Uint8Array
  controller: string
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
      seed: bytesToBase64Url(seed),
      controller,
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
    controller: plaintext.controller
  }
}

/**
 * Locates and unwraps the keyring for a passphrase. When a WAS server is
 * configured the remote copy is consulted first -- it is the source of truth,
 * and checking it before the cache is what makes a passphrase change on
 * another device take effect here: a found record refreshes the local cache,
 * while a 404-shaped miss (a null record) drops any cached copy and returns
 * `null` (no account for this passphrase -- never bound, or retired by a
 * passphrase change). When the remote GET fails (network/unreachable), the
 * cache answers as an offline fallback, but only within
 * `KEYRING_CACHE_TTL_MS`; past that (or with no usable cache) the error
 * rethrows, so the caller sees "could not check" rather than misreading it as
 * "no account". With no WAS server configured the cache is the keyring's only
 * copy, so the lookup is cache-only with no TTL.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}
 * @returns {Promise<KeyringSeed | null>}
 */
export async function fetchKeyringSeed({
  passphrase,
  idb,
  kdf = KEYRING_KDF
}: {
  passphrase: string
  idb?: IDBFactory
  kdf?: UnlockKdf
}): Promise<KeyringSeed | null> {
  const unlock = await deriveUnlockIdentity({ passphrase, kdf })

  if (!WAS_SERVER_URL) {
    // No remote: the cache is the keyring's only copy -- authoritative, no TTL.
    const cached = await loadKeyringCache({ spaceId: unlock.spaceId, idb })
    if (!cached) {
      return null
    }
    try {
      return await unwrapSeed({
        record: cached.record,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver
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
      return await unwrapSeed({
        record: cached.record,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver
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

  const found = await unwrapSeed({
    record,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver
  })
  await saveKeyringCache({ spaceId: unlock.spaceId, record, idb })
  return found
}

/**
 * Binds a passphrase to a data seed: derives the unlock identity, ensures the
 * unlock Space (when WAS is configured), wraps and PUTs the keyring record,
 * and saves the local cache. Throws on failure (the caller decides fatality --
 * fatal for signups). With no WAS server configured the keyring is cache-only,
 * so the account is then only recoverable in this browser profile.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the data seed
 * @param options.controller {string}   the data did:key
 * @param options.passphrase {string}
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}
 * @returns {Promise<void>}
 */
export async function bindPassphrase({
  seed,
  controller,
  passphrase,
  idb,
  kdf = KEYRING_KDF
}: {
  seed: Uint8Array
  controller: string
  passphrase: string
  idb?: IDBFactory
  kdf?: UnlockKdf
}): Promise<void> {
  const unlock = await deriveUnlockIdentity({ passphrase, kdf })
  const record = await wrapSeed({
    seed,
    controller,
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver
  })

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
  }

  await saveKeyringCache({ spaceId: unlock.spaceId, record, idb })
}

/**
 * Thrown by `changePassphrase` when the supplied current passphrase does not
 * unlock a keyring for this account.
 */
export class WrongPassphraseError extends Error {
  constructor(message = 'The current passphrase is incorrect.') {
    super(message)
    this.name = 'WrongPassphraseError'
  }
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
 * @param options {object}
 * @param options.seed {Uint8Array}   the data seed
 * @param options.controller {string}   the data did:key
 * @param options.oldPassphrase {string}
 * @param options.newPassphrase {string}
 * @param [options.idb] {IDBFactory}
 * @param [options.kdf] {UnlockKdf}
 * @returns {Promise<{ oldPassphraseRetired: boolean }>}
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
}): Promise<{ oldPassphraseRetired: boolean }> {
  const oldUnlock = await deriveUnlockIdentity({
    passphrase: oldPassphrase,
    kdf
  })

  // Verify the old passphrase via its keyring. With a WAS server configured
  // the remote copy is read -- the source of truth, so a locally cached record
  // cannot verify a passphrase already retired on another device. A network
  // error while reading the remote rethrows -- an unreachable remote must not
  // be misread as a wrong passphrase. With no WAS server the local cache is
  // the keyring's only copy.
  let oldRecord: unknown
  if (WAS_SERVER_URL) {
    oldRecord = await getUnlockKeyring({
      storageServerUrl: WAS_SERVER_URL,
      zcapClient: oldUnlock.zcapClient,
      spaceId: oldUnlock.spaceId
    })
  } else {
    const cached = await loadKeyringCache({ spaceId: oldUnlock.spaceId, idb })
    oldRecord = cached?.record ?? null
  }

  if (!oldRecord) {
    throw new WrongPassphraseError()
  }
  let verified = false
  try {
    const unwrapped = await unwrapSeed({
      record: oldRecord,
      keyAgreementKey: oldUnlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: oldUnlock.keyResolver
    })
    verified = unwrapped.controller === controller
  } catch {
    // A record that does not unwrap for this controller is a wrong passphrase.
  }
  if (!verified) {
    throw new WrongPassphraseError()
  }

  await bindPassphrase({
    seed,
    controller,
    passphrase: newPassphrase,
    idb,
    kdf
  })

  // Retire the old unlock identity -- but only when it differs from the new
  // one (an old == new rebind must not delete the Space just written).
  const newUnlock = await deriveUnlockIdentity({
    passphrase: newPassphrase,
    kdf
  })
  let oldSpaceDeleted = true
  if (newUnlock.spaceId !== oldUnlock.spaceId) {
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
  return { oldPassphraseRetired: oldSpaceDeleted }
}
