// @vitest-environment node
/**
 * Unit tests for the keyring v2 module (`src/session/keyring.ts`): the unlock
 * derivation (deterministic, secret-sensitive), the record wrap/unwrap
 * round-trip and its validation, the local client-key record (this client's
 * key set + cached user key under the unlock layer), record authenticity
 * (the frame proof and its refusal), and the `fetchKeyring` / `bindPassphrase`
 * / `changePassphrase` public contract across the WAS-configured and
 * cache-only branches. The module is method-agnostic -- unlock derivation
 * runs off a generic `{ secret, kdf }` pair (a string passphrase under
 * PBKDF2, or uniform byte material such as a passkey PRF output under HKDF)
 * via the exported `deriveUnlockIdentity` / `bindUnlockSecret` seam, and the
 * passphrase functions are thin wrappers over it; the frozen-vector block
 * pins the production salts. The unlock-Space WAS helpers are replaced by an
 * in-memory fake keyed by unlock Space id; the `freewallet-session`
 * IndexedDB is backed by a minimal in-memory `IDBFactory` (node has no
 * IndexedDB). Tiny PBKDF2 iteration counts keep the derivation fast; the
 * real EDV cipher and CapabilityAgent / X25519 derivations run unmocked.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IDelegatedZcap,
  IKeyAgreementKey
} from '@interop/data-integrity-core'
import { WasError, type CollectionEncryption } from '@interop/was-client'
import { deriveSpaceId } from '@interop/was-client/sync'
import { createEdvDocCipher } from '@interop/was-client/edv'
import { loadClientKeyRecord, loadKeyringCache } from '@/lib/sessionKey'
import {
  KEYRING_CACHE_TTL_MS,
  PASSKEY_KDF,
  UNLOCK_MANAGE_ZCAP_TTL_MS
} from '@/app.config'

/**
 * Shared mutable state for the two mocks: the configured WAS url (mutable so a
 * test can drop it to exercise the cache-only branch), the in-memory unlock
 * Spaces (spaceId to keyring record), and an optional error the remote GET
 * should throw.
 */
const wasState = vi.hoisted(() => ({
  url: 'https://was.example.test' as string | undefined,
  spaces: new Map<string, unknown>(),
  getError: undefined as unknown
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return wasState.url
  }
}))

/**
 * The enrolled-client signing keys the mocked `currentAccountRecordSigners`
 * answers with, for the pending-proof settlement paths (a cascade-re-minted
 * record signed by an account key rather than the unlock key).
 */
const clientsState = vi.hoisted(() => ({
  signingKeys: [] as string[]
}))

vi.mock('@interop/wallet-core/clients', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/clients')>()),
  currentAccountRecordSigners: vi.fn(
    async () => new Set(clientsState.signingKeys)
  )
}))

vi.mock('@interop/wallet-core/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keyring')>()),
  ensureUnlockSpace: vi.fn(async () => {}),
  putUnlockKeyring: vi.fn(
    async ({ spaceId, record }: { spaceId: string; record: unknown }) => {
      wasState.spaces.set(spaceId, record)
    }
  ),
  getUnlockKeyring: vi.fn(async ({ spaceId }: { spaceId: string }) => {
    if (wasState.getError) {
      throw wasState.getError
    }
    return wasState.spaces.has(spaceId) ? wasState.spaces.get(spaceId) : null
  }),
  deleteUnlockSpace: vi.fn(async ({ spaceId }: { spaceId: string }) => {
    wasState.spaces.delete(spaceId)
  })
}))

import {
  bindPassphrase,
  bindUnlockSecret,
  changePassphrase,
  deleteKeyring,
  fetchKeyring,
  fetchTransientKeyring,
  KeyringRecordForgedError,
  KeyringRecordUnusableError,
  verifyPassphrase,
  WrongPassphraseError
} from '@/session/keyring'
import {
  deleteUnlockSpace,
  deriveUnlockIdentity,
  ensureUnlockSpace,
  getUnlockKeyring,
  KEYRING_KDF,
  KEYRING_RECORD_VERSION,
  mintRecordEncryption,
  recordSignerFromAgent,
  signRecordFrame,
  type AccountPointer
} from '@interop/wallet-core/keyring'
import {
  isEnrolledClientKeyRecord,
  mintUserKey
} from '@interop/wallet-core/keys'
import {
  standingClientFromUnlockSeed,
  wrapUnlockRecord
} from '@interop/wallet-core/unlock'
import { currentAccountRecordSigners } from '@interop/wallet-core/clients'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'

const KDF = {
  version: 1,
  algorithm: 'PBKDF2',
  iterations: 2,
  hash: 'SHA-256',
  salt: 'freewallet/test/unlock'
} as const
const DATA_CONTROLLER = 'did:key:z6MkDataControllerForTests'
const POINTER: AccountPointer = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

/**
 * A minimal in-memory `IDBFactory` sufficient for the session-store helpers in
 * `src/lib/sessionKey.ts` (a single object store, get/put/delete by key). Each
 * test gets a fresh one so local records start empty.
 *
 * @returns {IDBFactory}
 */
function createFakeIdb(): IDBFactory {
  const stores = new Map<string, Map<IDBValidKey, unknown>>()
  let initialized = false
  type Request = {
    onsuccess?: () => void
    onupgradeneeded?: () => void
    onerror?: () => void
    result?: unknown
  }
  function run(fn: () => unknown): Request {
    const request: Request = {}
    queueMicrotask(() => {
      request.result = fn()
      request.onsuccess?.()
    })
    return request
  }
  function storeApi(store: Map<IDBValidKey, unknown>) {
    return {
      get: (key: IDBValidKey) => run(() => store.get(key)),
      put: (value: unknown, key: IDBValidKey) =>
        run(() => {
          store.set(key, value)
          return key
        }),
      delete: (key: IDBValidKey) =>
        run(() => {
          store.delete(key)
          return undefined
        })
    }
  }
  function makeDb() {
    return {
      createObjectStore(name: string) {
        if (!stores.has(name)) {
          stores.set(name, new Map())
        }
        return {}
      },
      transaction(name: string) {
        let store = stores.get(name)
        if (!store) {
          store = new Map()
          stores.set(name, store)
        }
        return {
          objectStore: () => storeApi(store as Map<IDBValidKey, unknown>)
        }
      },
      close() {}
    }
  }
  return {
    open() {
      const request: Request = {}
      queueMicrotask(() => {
        request.result = makeDb()
        if (!initialized) {
          initialized = true
          request.onupgradeneeded?.()
        }
        request.onsuccess?.()
      })
      return request
    }
  } as unknown as IDBFactory
}

/**
 * Writes a raw value directly into the fake session store at an arbitrary
 * key (bypassing the typed helpers), to craft legacy or malformed local
 * entries.
 */
async function putRawSessionEntry({
  idb,
  key,
  value
}: {
  idb: IDBFactory
  key: string
  value: unknown
}): Promise<void> {
  const db = await new Promise<IDBDatabase>(resolve => {
    const request = idb.open('freewallet-session', 1)
    request.onsuccess = () => resolve(request.result)
  })
  await new Promise<void>(resolve => {
    const request = db
      .transaction('session', 'readwrite')
      .objectStore('session')
      .put(value, key)
    request.onsuccess = () => resolve()
  })
}

/**
 * Independently derives the unlock identity (KAK + resolver + Space id) for a
 * passphrase, using the exact steps `src/session/keyring.ts` uses. Lets a test
 * craft records at the right unlock Space and assert derivation determinism.
 */
async function unlockFor(passphrase: string) {
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
      salt: new TextEncoder().encode(KDF.salt),
      iterations: KDF.iterations,
      hash: KDF.hash
    },
    baseKey,
    256
  )
  const agent = await CapabilityAgent.fromSeed({
    seed: new Uint8Array(bits),
    handle: 'unlock',
    keyName: 'unlock-key'
  })
  const keyAgreementKey =
    X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
      keyPair: agent.getVerificationKeyPair()
    })
  const keyResolver = async () => ({
    id: keyAgreementKey.id,
    type: keyAgreementKey.type,
    publicKeyMultibase: keyAgreementKey.publicKeyMultibase
  })
  const spaceId = deriveSpaceId(agent.id)
  return {
    agent,
    keyAgreementKey,
    keyResolver,
    spaceId,
    seed: new Uint8Array(bits)
  }
}

/**
 * The passphrase whose unlock key stands in for a signing key nobody typed --
 * a storage host's own, in the forgery cases.
 */
const STRANGER_PASSPHRASE = 'a key nobody ever typed'

/**
 * Builds a keyring record whose ciphertext decrypts (under the given
 * passphrase's unlock KAK) to an arbitrary plaintext, so the negative
 * validation and host-substitution paths can be exercised. `signAs` picks the
 * frame's proof: the passphrase's own unlock key (an authentic record), a
 * stranger's key (the host forging one), or no proof at all.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param options.plaintext {Record<string, unknown>}
 * @param [options.version] {number}   the frame version to stamp
 * @param [options.signAs] {'unlock' | 'stranger' | 'none'}
 * @param [options.wrapped] {unknown}   an envelope to seal into the frame in
 *   place of the encrypted one, so the proof covers the substitute
 * @returns {Promise<{ record: unknown, spaceId: string }>}
 */
async function craftRecord({
  passphrase,
  plaintext,
  version = KEYRING_RECORD_VERSION,
  signAs = 'unlock',
  wrapped: wrappedOverride
}: {
  passphrase: string
  plaintext: Record<string, unknown>
  version?: number
  signAs?: 'unlock' | 'stranger' | 'none'
  wrapped?: unknown
}) {
  const { agent, keyAgreementKey, keyResolver, spaceId } =
    await unlockFor(passphrase)
  const encryption = await mintRecordEncryption({
    keyAgreementKey: keyAgreementKey as unknown as IKeyAgreementKey
  })
  const cipher = await createEdvDocCipher({
    keyAgreementKey: keyAgreementKey as unknown as IKeyAgreementKey,
    keyResolver,
    collectionId: 'keyring',
    encryption
  })
  const { envelope } = await cipher.encrypt({
    data: plaintext as Parameters<typeof cipher.encrypt>[0]['data']
  })
  const wrapped = wrappedOverride ?? envelope
  if (signAs === 'none') {
    return { record: { version, encryption, wrapped }, spaceId }
  }
  const signingAgent =
    signAs === 'unlock' ? agent : (await unlockFor(STRANGER_PASSPHRASE)).agent
  const record = await signRecordFrame({
    version,
    encryption,
    wrapped,
    signer: recordSignerFromAgent({ keyAgent: signingAgent })
  })
  return { record, spaceId }
}

/**
 * Decrypts a stored keyring record's plaintext under the given passphrase's
 * unlock KAK and the record's own carried descriptor, so a test can assert
 * what the record does (and does not) carry.
 */
async function decryptRecord({
  passphrase,
  record
}: {
  passphrase: string
  record: unknown
}): Promise<Record<string, unknown>> {
  const { keyAgreementKey, keyResolver } = await unlockFor(passphrase)
  const { encryption, wrapped } = record as {
    encryption: CollectionEncryption
    wrapped: unknown
  }
  const cipher = await createEdvDocCipher({
    keyAgreementKey: keyAgreementKey as unknown as IKeyAgreementKey,
    keyResolver,
    collectionId: 'keyring',
    encryption
  })
  return (await cipher.decrypt({
    envelope: wrapped as never
  })) as Record<string, unknown>
}

function randomSeed(): Uint8Array {
  const seed = new Uint8Array(32)
  crypto.getRandomValues(seed)
  return seed
}

/**
 * Encodes raw bytes as an unpadded base64url string (matching the module's
 * internal encoder), for building crafted plaintexts.
 */
function seedToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

beforeEach(() => {
  wasState.url = 'https://was.example.test'
  wasState.spaces.clear()
  wasState.getError = undefined
  clientsState.signingKeys = []
  vi.clearAllMocks()
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('unlock derivation', () => {
  it('is deterministic and matches bindPassphrase (same passphrase -> same Space)', async () => {
    const idb = createFakeIdb()
    const expected = await unlockFor('correct horse battery staple')

    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'correct horse battery staple',
      idb,
      kdf: KDF
    })

    const ensureArgs = vi.mocked(ensureUnlockSpace).mock.calls[0][0]
    expect(ensureArgs.spaceId).toBe(expected.spaceId)
    expect(ensureArgs.controller).toBe(expected.agent.id)
  })

  it('is passphrase-sensitive (different passphrase -> different Space)', async () => {
    const first = await unlockFor('passphrase one')
    const second = await unlockFor('passphrase two')
    expect(second.spaceId).not.toBe(first.spaceId)
  })
})

describe('wrap / unwrap', () => {
  it('round-trips controller, email, and pointer through bind + fetch', async () => {
    const idb = createFakeIdb()

    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'round-trip passphrase',
      email: 'holder@example.com',
      pointer: POINTER,
      idb,
      kdf: KDF
    })

    const found = await fetchKeyring({
      passphrase: 'round-trip passphrase',
      idb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(found!.controller).toBe(DATA_CONTROLLER)
    expect(found!.email).toBe('holder@example.com')
    expect(found!.pointer).toEqual(POINTER)
  })

  it('writes a record that carries no key material of any kind', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    const userKey = await mintUserKey()

    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'no key material passphrase',
      userKey,
      pointer: POINTER,
      idb,
      kdf: KDF
    })

    const { spaceId } = await unlockFor('no key material passphrase')
    const plaintext = await decryptRecord({
      passphrase: 'no key material passphrase',
      record: wasState.spaces.get(spaceId)
    })
    expect(Object.keys(plaintext).sort()).toEqual([
      'controller',
      'createdAt',
      'pointer'
    ])
  })

  it('rejects a retired unsigned version-1 record', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'legacy v1 passphrase',
      version: 1,
      signAs: 'none',
      plaintext: {
        seed: seedToBase64Url(randomSeed()),
        controller: DATA_CONTROLLER,
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      fetchKeyring({ passphrase: 'legacy v1 passphrase', idb, kdf: KDF })
    ).rejects.toThrow(KeyringRecordUnusableError)
  })

  it('rejects a record with no encryption descriptor (the retired pre-epoch frame)', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'no descriptor passphrase',
      plaintext: {
        controller: DATA_CONTROLLER,
        createdAt: new Date().toISOString()
      }
    })
    const { encryption: _encryption, ...frameWithoutDescriptor } =
      record as unknown as Record<string, unknown>
    wasState.spaces.set(spaceId, frameWithoutDescriptor)

    await expect(
      fetchKeyring({ passphrase: 'no descriptor passphrase', idb, kdf: KDF })
    ).rejects.toThrow(KeyringRecordUnusableError)
  })

  it('rejects a record with an empty controller', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'empty controller passphrase',
      plaintext: {
        controller: '',
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      fetchKeyring({
        passphrase: 'empty controller passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toThrow(/controller/)
  })

  it('rejects a record whose pointer is malformed (missing host)', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'malformed pointer passphrase',
      plaintext: {
        controller: DATA_CONTROLLER,
        pointer: { spaceId: 'space-123' },
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      fetchKeyring({
        passphrase: 'malformed pointer passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toThrow(KeyringRecordUnusableError)
  })

  it('maps a corrupt remote record to KeyringRecordUnusableError and never caches it', async () => {
    const idb = createFakeIdb()
    // A record with the right frame but an undecryptable payload -- the
    // "genuinely corrupt record under the correct unlock Space" case.
    const { record, spaceId } = await craftRecord({
      passphrase: 'corrupt record passphrase',
      plaintext: { controller: DATA_CONTROLLER },
      // Signed over the garbage, so this is a corrupt record and not a
      // tampered one -- the two refusals must not be confusable.
      wrapped: { garbage: true }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      fetchKeyring({
        passphrase: 'corrupt record passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toThrow(KeyringRecordUnusableError)

    // The unusable record must not have refreshed the local cache.
    expect(await loadKeyringCache({ spaceId, idb })).toBeNull()
  })
})

describe('the client key set under the unlock layer', () => {
  it('round-trips the client seed and the cached user key through bind + fetch', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    const userKey = await mintUserKey()

    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'client keys round-trip passphrase',
      userKey,
      idb,
      kdf: KDF
    })

    const found = await fetchKeyring({
      passphrase: 'client keys round-trip passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.clientKeys).toBeDefined()
    expect(Array.from(found!.clientKeys!.clientSeed)).toEqual(
      Array.from(clientSeed)
    )
    expect(found!.clientKeys!.userKey!.id).toBe(userKey.id)
    expect(Array.from(found!.clientKeys!.userKey!.secret)).toEqual(
      Array.from(userKey.secret)
    )
    expect(Array.from(found!.clientKeys!.userKey!.signingSeed!)).toEqual(
      Array.from(userKey.signingSeed)
    )
  })

  it('round-trips the did:webvh update-key seeds and re-wraps via persistClientKeys', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    const userKey = await mintUserKey()
    const webvhUpdateKeys = {
      updateSeed: randomSeed(),
      stagedSeed: randomSeed()
    }

    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'webvh keys round-trip passphrase',
      userKey,
      webvhUpdateKeys,
      idb,
      kdf: KDF
    })

    const found = await fetchKeyring({
      passphrase: 'webvh keys round-trip passphrase',
      idb,
      kdf: KDF
    })
    const recovered = found!.clientKeys!.webvhUpdateKeys!
    expect(Array.from(recovered.updateSeed)).toEqual(
      Array.from(webvhUpdateKeys.updateSeed)
    )
    expect(Array.from(recovered.stagedSeed)).toEqual(
      Array.from(webvhUpdateKeys.stagedSeed)
    )
    expect(recovered.pendingStagedSeed).toBeUndefined()

    // Re-wrap rolled seeds (a rotation) without the secret: the changed
    // member lands, the untouched members survive.
    const rolled = {
      updateSeed: webvhUpdateKeys.stagedSeed,
      stagedSeed: randomSeed(),
      pendingStagedSeed: randomSeed()
    }
    await found!.persistClientKeys!({ webvhUpdateKeys: rolled })

    const after = await fetchKeyring({
      passphrase: 'webvh keys round-trip passphrase',
      idb,
      kdf: KDF
    })
    const persisted = after!.clientKeys!.webvhUpdateKeys!
    expect(Array.from(persisted.updateSeed)).toEqual(
      Array.from(rolled.updateSeed)
    )
    expect(Array.from(persisted.stagedSeed)).toEqual(
      Array.from(rolled.stagedSeed)
    )
    expect(Array.from(persisted.pendingStagedSeed!)).toEqual(
      Array.from(rolled.pendingStagedSeed)
    )
    expect(after!.clientKeys!.userKey!.id).toBe(userKey.id)
    expect(Array.from(after!.clientKeys!.clientSeed)).toEqual(
      Array.from(clientSeed)
    )
  })

  it('writes pointerDid at bind, and the record satisfies the full enrolled guard (FW-280 shape regression)', async () => {
    // Routing keys on `userKey` presence alone (question 2 as amended), but
    // the bind must still produce a record the four-member guard accepts:
    // `pointerDid` is the resume's record-to-account cross-check, and dcw's
    // counterpart asserts the same full shape.
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'enrolled shape passphrase',
      userKey: await mintUserKey(),
      webvhUpdateKeys: { updateSeed: randomSeed(), stagedSeed: randomSeed() },
      pointer: POINTER,
      idb,
      kdf: KDF
    })
    const found = await fetchKeyring({
      passphrase: 'enrolled shape passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.clientKeys!.pointerDid).toBe(POINTER.did)
    expect(isEnrolledClientKeyRecord(found!.clientKeys!)).toBe(true)
  })

  it('classifies a userKey-less record pending, and round-trips + clears the pending group', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'pending shape passphrase',
      webvhUpdateKeys: { updateSeed: randomSeed(), stagedSeed: randomSeed() },
      pointer: POINTER,
      idb,
      kdf: KDF
    })
    let found = await fetchKeyring({
      passphrase: 'pending shape passphrase',
      idb,
      kdf: KDF
    })
    expect(isEnrolledClientKeyRecord(found!.clientKeys!)).toBe(false)

    // The persist hook's write: the pending group survives the persister's
    // merge and reads back decoded.
    const builtOnHead = { scid: 'QmScidForTests', versionId: '3-abc' }
    await found!.persistClientKeys!({
      pointerDid: POINTER.did,
      pending: { ceremony: 'self-enrollment', builtOnHead }
    })
    found = await fetchKeyring({
      passphrase: 'pending shape passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.clientKeys!.pending).toEqual({
      ceremony: 'self-enrollment',
      builtOnHead
    })
    expect(found!.clientKeys!.pointerDid).toBe(POINTER.did)
    expect(isEnrolledClientKeyRecord(found!.clientKeys!)).toBe(false)

    // The completion write: the user key in, `pending: null` clears the
    // group, and the record classifies enrolled from then on.
    await found!.persistClientKeys!({
      userKey: await mintUserKey(),
      pending: null
    })
    found = await fetchKeyring({
      passphrase: 'pending shape passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.clientKeys!.pending).toBeUndefined()
    expect(found!.clientKeys!.pointerDid).toBe(POINTER.did)
    expect(isEnrolledClientKeyRecord(found!.clientKeys!)).toBe(true)
  })

  it('drops a userKey persist on a pending record unless the same change clears the pending group', async () => {
    // The completion-only enrollment rule: an incidental mid-session persist
    // (the login sweep's rotation adoption) must not fill the user key on a
    // still-pending record -- it would classify enrolled with a live pending
    // group and the resume would never run again.
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'pending drop passphrase',
      webvhUpdateKeys: { updateSeed: randomSeed(), stagedSeed: randomSeed() },
      pointer: POINTER,
      idb,
      kdf: KDF
    })
    let found = await fetchKeyring({
      passphrase: 'pending drop passphrase',
      idb,
      kdf: KDF
    })
    const builtOnHead = { scid: 'QmScidForTests', versionId: '4-def' }
    await found!.persistClientKeys!({
      pending: { ceremony: 'self-enrollment', builtOnHead }
    })

    // A userKey-only change against the pending record is dropped whole for
    // the userKey member; the record stays pending and unenrolled.
    await found!.persistClientKeys!({ userKey: await mintUserKey() })
    found = await fetchKeyring({
      passphrase: 'pending drop passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.clientKeys!.userKey).toBeUndefined()
    expect(found!.clientKeys!.pending).toEqual({
      ceremony: 'self-enrollment',
      builtOnHead
    })
    expect(isEnrolledClientKeyRecord(found!.clientKeys!)).toBe(false)

    // The completion write (userKey together with `pending: null`) remains
    // the one enrolling path.
    await found!.persistClientKeys!({
      userKey: await mintUserKey(),
      pending: null
    })
    found = await fetchKeyring({
      passphrase: 'pending drop passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.clientKeys!.pending).toBeUndefined()
    expect(isEnrolledClientKeyRecord(found!.clientKeys!)).toBe(true)
  })

  it('locates the account but reports no client keys on a fresh profile (not enrolled)', async () => {
    // Bind through one browser profile, then fetch on a second profile whose
    // session store is empty: the passphrase can no longer reconstruct the
    // account -- it finds the pointer but not the keys.
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'fresh profile passphrase',
      pointer: POINTER,
      idb: createFakeIdb(),
      kdf: KDF
    })

    const found = await fetchKeyring({
      passphrase: 'fresh profile passphrase',
      idb: createFakeIdb(),
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(found!.pointer).toEqual(POINTER)
    expect(found!.clientKeys).toBeUndefined()
  })

  it('mints unrelated client key sets in two profiles under the same passphrase', async () => {
    // Two browser profiles bound under one passphrase: each holds its own
    // locally minted key set; neither derives from the shared secret.
    const profileA = createFakeIdb()
    const profileB = createFakeIdb()
    const seedA = randomSeed()
    const seedB = randomSeed()
    await bindPassphrase({
      clientSeed: seedA,
      controller: DATA_CONTROLLER,
      passphrase: 'shared passphrase',
      idb: profileA,
      kdf: KDF
    })
    await bindPassphrase({
      clientSeed: seedB,
      controller: DATA_CONTROLLER,
      passphrase: 'shared passphrase',
      idb: profileB,
      kdf: KDF
    })

    const foundA = await fetchKeyring({
      passphrase: 'shared passphrase',
      idb: profileA,
      kdf: KDF
    })
    const foundB = await fetchKeyring({
      passphrase: 'shared passphrase',
      idb: profileB,
      kdf: KDF
    })
    expect(Array.from(foundA!.clientKeys!.clientSeed)).toEqual(
      Array.from(seedA)
    )
    expect(Array.from(foundB!.clientKeys!.clientSeed)).toEqual(
      Array.from(seedB)
    )
    expect(Array.from(foundA!.clientKeys!.clientSeed)).not.toEqual(
      Array.from(foundB!.clientKeys!.clientSeed)
    )
  })

  it('discards a malformed client-key record and reports not enrolled', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'garbled client keys passphrase',
      idb,
      kdf: KDF
    })
    const { spaceId } = await unlockFor('garbled client keys passphrase')
    await putRawSessionEntry({
      idb,
      key: `client-keys/${spaceId}`,
      value: { version: 1, wrapped: { garbage: true } }
    })

    const found = await fetchKeyring({
      passphrase: 'garbled client keys passphrase',
      idb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(found!.clientKeys).toBeUndefined()
    // The unusable record was evicted, not left to warn on every login.
    await expect(loadClientKeyRecord({ spaceId, idb })).resolves.toBeNull()
  })
})

describe('record authenticity (the proof)', () => {
  it('round-trips a signed record through bind + fetch', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'signed round trip passphrase',
      pointer: POINTER,
      idb,
      kdf: KDF
    })
    const stored = wasState.spaces.get(
      (await unlockFor('signed round trip passphrase')).spaceId
    ) as { version: number; proof?: { verificationMethod?: string } }
    expect(stored.version).toBe(KEYRING_RECORD_VERSION)
    expect(stored.proof?.verificationMethod).toContain('did:key:')

    const found = await fetchKeyring({
      passphrase: 'signed round trip passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.pointer).toEqual(POINTER)
    expect(Number.isNaN(Date.parse(found!.createdAt))).toBe(false)
  })

  it('refuses a host-crafted record signed by a key the secret does not derive', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'forged record passphrase',
      signAs: 'stranger',
      plaintext: {
        controller: DATA_CONTROLLER,
        pointer: { ...POINTER, spaceId: 'attacker-space' },
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      fetchKeyring({ passphrase: 'forged record passphrase', idb, kdf: KDF })
    ).rejects.toThrow(KeyringRecordForgedError)
    // A refused record never becomes tomorrow's offline fallback.
    expect(await loadKeyringCache({ spaceId, idb })).toBeNull()
  })

  it('refuses a record with the proof stripped', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'unsigned record passphrase',
      signAs: 'none',
      plaintext: {
        controller: DATA_CONTROLLER,
        pointer: POINTER,
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      fetchKeyring({ passphrase: 'unsigned record passphrase', idb, kdf: KDF })
    ).rejects.toThrow(KeyringRecordForgedError)
  })

  it('refuses a record whose frame was tampered with after signing', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'tampered record passphrase',
      plaintext: {
        controller: DATA_CONTROLLER,
        pointer: POINTER,
        createdAt: new Date().toISOString()
      }
    })
    const { record: other } = await craftRecord({
      passphrase: 'tampered record passphrase',
      plaintext: {
        controller: DATA_CONTROLLER,
        pointer: { ...POINTER, spaceId: 'attacker-space' },
        createdAt: new Date().toISOString()
      }
    })
    // The host keeps the authentic proof and swaps the ciphertext under it.
    wasState.spaces.set(spaceId, {
      ...(record as Record<string, unknown>),
      encryption: (other as Record<string, unknown>).encryption,
      wrapped: (other as Record<string, unknown>).wrapped
    })

    await expect(
      fetchKeyring({ passphrase: 'tampered record passphrase', idb, kdf: KDF })
    ).rejects.toThrow(KeyringRecordForgedError)
  })
})

describe('fetchKeyring', () => {
  it('consults the remote even on a cache hit (the remote is the source of truth)', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'cache hit passphrase',
      idb,
      kdf: KDF
    })
    vi.clearAllMocks()

    const found = await fetchKeyring({
      passphrase: 'cache hit passphrase',
      idb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(getUnlockKeyring).toHaveBeenCalledOnce()
  })

  it('drops the cache and returns null when the remote keyring is gone (passphrase retired elsewhere)', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'retired passphrase',
      idb,
      kdf: KDF
    })
    // Simulate a passphrase change made on another client: the old unlock
    // Space is deleted remotely while this client's cache still holds the
    // record.
    wasState.spaces.clear()

    const found = await fetchKeyring({
      passphrase: 'retired passphrase',
      idb,
      kdf: KDF
    })
    expect(found).toBeNull()

    const { spaceId } = await unlockFor('retired passphrase')
    await expect(loadKeyringCache({ spaceId, idb })).resolves.toBeNull()
  })

  it('leaves the client-key record intact on a remote miss (a server answer must not destroy keys)', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'survives miss passphrase',
      idb,
      kdf: KDF
    })
    const { spaceId } = await unlockFor('survives miss passphrase')
    const record = wasState.spaces.get(spaceId)

    // A (possibly lying) 404: the fetch reports no account...
    wasState.spaces.clear()
    await expect(
      fetchKeyring({ passphrase: 'survives miss passphrase', idb, kdf: KDF })
    ).resolves.toBeNull()

    // ...but once the record is back, this client still holds its keys.
    wasState.spaces.set(spaceId, record)
    const found = await fetchKeyring({
      passphrase: 'survives miss passphrase',
      idb,
      kdf: KDF
    })
    expect(Array.from(found!.clientKeys!.clientSeed)).toEqual(
      Array.from(clientSeed)
    )
  })

  it('falls back to a fresh cache when the remote is unreachable', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'offline fallback passphrase',
      idb,
      kdf: KDF
    })
    wasState.getError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })

    const found = await fetchKeyring({
      passphrase: 'offline fallback passphrase',
      idb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(Array.from(found!.clientKeys!.clientSeed)).toEqual(
      Array.from(clientSeed)
    )
  })

  it('rethrows when the remote is unreachable and the cache has expired', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'expired cache passphrase',
      idb,
      kdf: KDF
    })
    vi.setSystemTime(Date.now() + KEYRING_CACHE_TTL_MS + 60_000)
    const networkError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })
    wasState.getError = networkError

    await expect(
      fetchKeyring({
        passphrase: 'expired cache passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBe(networkError)
  })

  it('rethrows when the remote is unreachable and the cached record predates timestamps', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'legacy cache passphrase',
      plaintext: {
        controller: DATA_CONTROLLER,
        createdAt: new Date().toISOString()
      }
    })
    // A bare record at the cache key, as written before write-time stamps.
    await putRawSessionEntry({ idb, key: `keyring/${spaceId}`, value: record })
    const networkError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })
    wasState.getError = networkError

    await expect(
      fetchKeyring({ passphrase: 'legacy cache passphrase', idb, kdf: KDF })
    ).rejects.toBe(networkError)
  })

  it('reads remote on a cache miss and refreshes the cache', async () => {
    // Bind through one profile (populates remote + its cache), then fetch on a
    // fresh profile whose cache is empty.
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'cache miss passphrase',
      idb: createFakeIdb(),
      kdf: KDF
    })
    vi.clearAllMocks()

    const freshIdb = createFakeIdb()
    const found = await fetchKeyring({
      passphrase: 'cache miss passphrase',
      idb: freshIdb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(getUnlockKeyring).toHaveBeenCalledOnce()

    const { spaceId } = await unlockFor('cache miss passphrase')
    await expect(
      loadKeyringCache({ spaceId, idb: freshIdb })
    ).resolves.not.toBeNull()
  })

  it('returns null when no keyring exists anywhere', async () => {
    const found = await fetchKeyring({
      passphrase: 'unknown account passphrase',
      idb: createFakeIdb(),
      kdf: KDF
    })
    expect(found).toBeNull()
  })

  it('rethrows a network error rather than reporting no account', async () => {
    const networkError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })
    wasState.getError = networkError
    await expect(
      fetchKeyring({
        passphrase: 'offline passphrase',
        idb: createFakeIdb(),
        kdf: KDF
      })
    ).rejects.toBe(networkError)
  })

  it('is cache-only (no remote call) when no WAS server is configured', async () => {
    wasState.url = undefined
    const found = await fetchKeyring({
      passphrase: 'no was passphrase',
      idb: createFakeIdb(),
      kdf: KDF
    })
    expect(found).toBeNull()
    expect(getUnlockKeyring).not.toHaveBeenCalled()
  })

  it('serves the cache with no TTL when no WAS server is configured', async () => {
    wasState.url = undefined
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'no was warm cache passphrase',
      idb,
      kdf: KDF
    })
    // Far past the WAS-mode TTL: with no remote copy the cache is the
    // keyring's only copy and stays authoritative regardless of age.
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(Date.now() + KEYRING_CACHE_TTL_MS * 10)

    const found = await fetchKeyring({
      passphrase: 'no was warm cache passphrase',
      idb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(Array.from(found!.clientKeys!.clientSeed)).toEqual(
      Array.from(clientSeed)
    )
    expect(getUnlockKeyring).not.toHaveBeenCalled()
  })
})

describe('bindPassphrase', () => {
  it('writes the remote record, the cache, and the client-key record when WAS is configured', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'bind remote passphrase',
      idb,
      kdf: KDF
    })

    const { spaceId } = await unlockFor('bind remote passphrase')
    expect(ensureUnlockSpace).toHaveBeenCalledOnce()
    expect(wasState.spaces.has(spaceId)).toBe(true)
    await expect(loadKeyringCache({ spaceId, idb })).resolves.not.toBeNull()
    await expect(loadClientKeyRecord({ spaceId, idb })).resolves.not.toBeNull()
  })

  it('is cache-only when no WAS server is configured', async () => {
    wasState.url = undefined
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'bind cache only passphrase',
      idb,
      kdf: KDF
    })

    const { spaceId } = await unlockFor('bind cache only passphrase')
    expect(ensureUnlockSpace).not.toHaveBeenCalled()
    expect(wasState.spaces.size).toBe(0)
    await expect(loadKeyringCache({ spaceId, idb })).resolves.not.toBeNull()
    await expect(loadClientKeyRecord({ spaceId, idb })).resolves.not.toBeNull()
  })

  it('is idempotent (a second identical bind succeeds)', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    const args = {
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'idempotent passphrase',
      idb,
      kdf: KDF
    }
    const { spaceId } = await unlockFor('idempotent passphrase')
    await bindPassphrase(args)
    await expect(bindPassphrase(args)).resolves.toMatchObject({
      unlockSpaceId: spaceId
    })
    expect(wasState.spaces.has(spaceId)).toBe(true)
  })

  it('returns the unlock Space id it bound', async () => {
    const idb = createFakeIdb()
    const { unlockSpaceId } = await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'space id return passphrase',
      idb,
      kdf: KDF
    })
    const { spaceId } = await unlockFor('space id return passphrase')
    expect(unlockSpaceId).toBe(spaceId)
  })

  it('carries the email through the wrapped record to fetchKeyring', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'email carrying passphrase',
      email: 'holder@example.com',
      idb,
      kdf: KDF
    })

    const found = await fetchKeyring({
      passphrase: 'email carrying passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.email).toBe('holder@example.com')
  })

  it('omits the email when none was bound', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'no email passphrase',
      idb,
      kdf: KDF
    })

    const found = await fetchKeyring({
      passphrase: 'no email passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.email).toBeUndefined()
  })
})

describe('changePassphrase', () => {
  it('retires the old method (Space, cache, and client-key record deleted)', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'old passphrase',
      pointer: POINTER,
      idb,
      kdf: KDF
    })
    const oldSpace = (await unlockFor('old passphrase')).spaceId
    const newSpace = (await unlockFor('new passphrase')).spaceId

    const { oldPassphraseRetired } = await changePassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'old passphrase',
      newPassphrase: 'new passphrase',
      idb,
      kdf: KDF
    })

    expect(oldPassphraseRetired).toBe(true)
    expect(deleteUnlockSpace).toHaveBeenCalledOnce()
    expect(wasState.spaces.has(oldSpace)).toBe(false)
    expect(wasState.spaces.has(newSpace)).toBe(true)
    await expect(
      loadKeyringCache({ spaceId: oldSpace, idb })
    ).resolves.toBeNull()
    await expect(
      loadClientKeyRecord({ spaceId: oldSpace, idb })
    ).resolves.toBeNull()
    await expect(
      loadKeyringCache({ spaceId: newSpace, idb })
    ).resolves.not.toBeNull()
    await expect(
      loadClientKeyRecord({ spaceId: newSpace, idb })
    ).resolves.not.toBeNull()
  })

  it('preserves the client seed, user key, email, and pointer across the rebind', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    const userKey = await mintUserKey()
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'carry rebind old passphrase',
      email: 'holder@example.com',
      userKey,
      pointer: POINTER,
      idb,
      kdf: KDF
    })

    await changePassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'carry rebind old passphrase',
      newPassphrase: 'carry rebind new passphrase',
      userKey,
      idb,
      kdf: KDF
    })

    const found = await fetchKeyring({
      passphrase: 'carry rebind new passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.email).toBe('holder@example.com')
    expect(found!.pointer).toEqual(POINTER)
    expect(Array.from(found!.clientKeys!.clientSeed)).toEqual(
      Array.from(clientSeed)
    )
    expect(found!.clientKeys!.userKey!.id).toBe(userKey.id)
  })

  it("falls back to the old record's user key when the caller passes none", async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    const userKey = await mintUserKey()
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'userKey fallback old passphrase',
      userKey,
      idb,
      kdf: KDF
    })

    await changePassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'userKey fallback old passphrase',
      newPassphrase: 'userKey fallback new passphrase',
      idb,
      kdf: KDF
    })

    const found = await fetchKeyring({
      passphrase: 'userKey fallback new passphrase',
      idb,
      kdf: KDF
    })
    expect(found!.clientKeys!.userKey!.id).toBe(userKey.id)
  })

  it("falls back to the old record's did:webvh update keys when the caller passes none", async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    const webvhUpdateKeys = {
      updateSeed: randomSeed(),
      stagedSeed: randomSeed()
    }
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'webvh fallback old passphrase',
      webvhUpdateKeys,
      idb,
      kdf: KDF
    })

    await changePassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'webvh fallback old passphrase',
      newPassphrase: 'webvh fallback new passphrase',
      idb,
      kdf: KDF
    })

    // The rebind deletes the old client-key record, which held this client's
    // only copy of its update-key seeds: dropping them here would strand the
    // client's did:webvh update authority for good.
    const found = await fetchKeyring({
      passphrase: 'webvh fallback new passphrase',
      idb,
      kdf: KDF
    })
    const recovered = found!.clientKeys!.webvhUpdateKeys!
    expect(Array.from(recovered.updateSeed)).toEqual(
      Array.from(webvhUpdateKeys.updateSeed)
    )
    expect(Array.from(recovered.stagedSeed)).toEqual(
      Array.from(webvhUpdateKeys.stagedSeed)
    )
  })

  it("prefers the caller's did:webvh update keys over the old record's", async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    const boundKeys = {
      updateSeed: randomSeed(),
      stagedSeed: randomSeed()
    }
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'webvh precedence old passphrase',
      webvhUpdateKeys: boundKeys,
      idb,
      kdf: KDF
    })

    // The session's live copy has moved on since the bind (a rotation), just
    // as the live user key can have.
    const liveKeys = {
      updateSeed: boundKeys.stagedSeed,
      stagedSeed: randomSeed(),
      pendingStagedSeed: randomSeed()
    }
    await changePassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'webvh precedence old passphrase',
      newPassphrase: 'webvh precedence new passphrase',
      webvhUpdateKeys: liveKeys,
      idb,
      kdf: KDF
    })

    const found = await fetchKeyring({
      passphrase: 'webvh precedence new passphrase',
      idb,
      kdf: KDF
    })
    const recovered = found!.clientKeys!.webvhUpdateKeys!
    expect(Array.from(recovered.updateSeed)).toEqual(
      Array.from(liveKeys.updateSeed)
    )
    expect(Array.from(recovered.stagedSeed)).toEqual(
      Array.from(liveKeys.stagedSeed)
    )
    expect(Array.from(recovered.pendingStagedSeed!)).toEqual(
      Array.from(liveKeys.pendingStagedSeed)
    )
  })

  it('returns a persistClientKeys closure over the new client-key record', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    const userKey = await mintUserKey()
    const webvhUpdateKeys = {
      updateSeed: randomSeed(),
      stagedSeed: randomSeed()
    }
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'persist closure old passphrase',
      userKey,
      webvhUpdateKeys,
      idb,
      kdf: KDF
    })
    const oldSpace = (await unlockFor('persist closure old passphrase')).spaceId

    const { persistClientKeys } = await changePassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'persist closure old passphrase',
      newPassphrase: 'persist closure new passphrase',
      userKey,
      webvhUpdateKeys,
      idb,
      kdf: KDF
    })
    expect(typeof persistClientKeys).toBe('function')

    // The old client-key record is gone, so the pre-change closure would have
    // had nothing to update: a later re-wrap has to run over the new record.
    await expect(
      loadClientKeyRecord({ spaceId: oldSpace, idb })
    ).resolves.toBeNull()

    const rolled = {
      updateSeed: webvhUpdateKeys.stagedSeed,
      stagedSeed: randomSeed()
    }
    await persistClientKeys({ webvhUpdateKeys: rolled })

    const found = await fetchKeyring({
      passphrase: 'persist closure new passphrase',
      idb,
      kdf: KDF
    })
    const persisted = found!.clientKeys!.webvhUpdateKeys!
    expect(Array.from(persisted.updateSeed)).toEqual(
      Array.from(rolled.updateSeed)
    )
    expect(Array.from(persisted.stagedSeed)).toEqual(
      Array.from(rolled.stagedSeed)
    )
    expect(found!.clientKeys!.userKey!.id).toBe(userKey.id)
    expect(Array.from(found!.clientKeys!.clientSeed)).toEqual(
      Array.from(clientSeed)
    )
  })

  it('throws WrongPassphraseError when no keyring exists for the old passphrase', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'the real old passphrase',
      idb,
      kdf: KDF
    })

    await expect(
      changePassphrase({
        clientSeed: randomSeed(),
        controller: DATA_CONTROLLER,
        oldPassphrase: 'a wrong old passphrase',
        newPassphrase: 'brand new passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('rejects an old passphrase already retired on another client despite a cached record', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'stale old passphrase',
      idb,
      kdf: KDF
    })
    // Retired elsewhere: the unlock Space is gone remotely, the local cache
    // still holds the record. Verification must consult the remote and fail.
    wasState.spaces.clear()

    await expect(
      changePassphrase({
        clientSeed,
        controller: DATA_CONTROLLER,
        oldPassphrase: 'stale old passphrase',
        newPassphrase: 'brand new passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('throws WrongPassphraseError when the record controller does not match', async () => {
    const idb = createFakeIdb()
    // A record exists at the old passphrase's unlock Space, but it belongs to
    // a different account than the one being changed.
    const { record, spaceId } = await craftRecord({
      passphrase: 'mismatch old passphrase',
      plaintext: {
        controller: 'did:key:z6MkSomeOtherDataController',
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      changePassphrase({
        clientSeed: randomSeed(),
        controller: DATA_CONTROLLER,
        oldPassphrase: 'mismatch old passphrase',
        newPassphrase: 'brand new passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('verifies against the account controller, not an enrolled client did:key', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    // Every keyring record carries the ACCOUNT controller (the first client's
    // did:key). On an enrolled second client the session's own did:key is a
    // different value, and passing it would fail the correct passphrase.
    const secondClientDid = 'did:key:z6MkSecondClientDidKeyForTests'
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'second client old passphrase',
      idb,
      kdf: KDF
    })

    await expect(
      changePassphrase({
        clientSeed,
        controller: secondClientDid,
        oldPassphrase: 'second client old passphrase',
        newPassphrase: 'second client new passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)

    await expect(
      changePassphrase({
        clientSeed,
        controller: DATA_CONTROLLER,
        oldPassphrase: 'second client old passphrase',
        newPassphrase: 'second client new passphrase',
        idb,
        kdf: KDF
      })
    ).resolves.toMatchObject({ oldPassphraseRetired: true })
  })

  it('rethrows an unreachable remote during verify (not a wrong passphrase)', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    // Bind through a separate profile so the verify cache is empty and the
    // verify must hit the remote, which is then made unreachable.
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'unreachable verify passphrase',
      idb: createFakeIdb(),
      kdf: KDF
    })
    const networkError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })
    wasState.getError = networkError

    await expect(
      changePassphrase({
        clientSeed,
        controller: DATA_CONTROLLER,
        oldPassphrase: 'unreachable verify passphrase',
        newPassphrase: 'brand new passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBe(networkError)
  })

  it('reports oldPassphraseRetired: false when the old Space deletion fails', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'delete-fails old passphrase',
      idb,
      kdf: KDF
    })
    vi.mocked(deleteUnlockSpace).mockRejectedValueOnce(
      new Error('delete failed')
    )

    const { oldPassphraseRetired } = await changePassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'delete-fails old passphrase',
      newPassphrase: 'delete-fails new passphrase',
      idb,
      kdf: KDF
    })

    expect(oldPassphraseRetired).toBe(false)
  })

  it('does not delete the just-written records when old and new passphrases are equal', async () => {
    const idb = createFakeIdb()
    const clientSeed = randomSeed()
    await bindPassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      passphrase: 'same passphrase',
      idb,
      kdf: KDF
    })
    const spaceId = (await unlockFor('same passphrase')).spaceId

    await changePassphrase({
      clientSeed,
      controller: DATA_CONTROLLER,
      oldPassphrase: 'same passphrase',
      newPassphrase: 'same passphrase',
      idb,
      kdf: KDF
    })

    expect(deleteUnlockSpace).not.toHaveBeenCalled()
    expect(wasState.spaces.has(spaceId)).toBe(true)
    await expect(loadClientKeyRecord({ spaceId, idb })).resolves.not.toBeNull()
  })
})

describe('verifyPassphrase', () => {
  it('resolves for the bound passphrase and correct controller', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'verify correct passphrase',
      idb,
      kdf: KDF
    })

    await expect(
      verifyPassphrase({
        controller: DATA_CONTROLLER,
        passphrase: 'verify correct passphrase',
        idb,
        kdf: KDF
      })
    ).resolves.toEqual({})
  })

  it('throws WrongPassphraseError for a wrong passphrase', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'the correct passphrase',
      idb,
      kdf: KDF
    })

    await expect(
      verifyPassphrase({
        controller: DATA_CONTROLLER,
        passphrase: 'a wrong passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('throws WrongPassphraseError when the controller does not match', async () => {
    const idb = createFakeIdb()
    const { record, spaceId } = await craftRecord({
      passphrase: 'verify mismatch passphrase',
      plaintext: {
        controller: 'did:key:z6MkSomeOtherDataController',
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      verifyPassphrase({
        controller: DATA_CONTROLLER,
        passphrase: 'verify mismatch passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('accepts the account controller, not an enrolled client did:key', async () => {
    const idb = createFakeIdb()
    // The enrolled-second-client case: the record's controller is the account
    // controller, so a session passing its own did:key would be told its
    // correct passphrase is wrong.
    const secondClientDid = 'did:key:z6MkSecondClientDidKeyForTests'
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'second client verify passphrase',
      idb,
      kdf: KDF
    })

    await expect(
      verifyPassphrase({
        controller: DATA_CONTROLLER,
        passphrase: 'second client verify passphrase',
        idb,
        kdf: KDF
      })
    ).resolves.toEqual({})

    await expect(
      verifyPassphrase({
        controller: secondClientDid,
        passphrase: 'second client verify passphrase',
        idb,
        kdf: KDF
      })
    ).rejects.toBeInstanceOf(WrongPassphraseError)
  })

  it('rethrows an unreachable remote (not a wrong passphrase)', async () => {
    // Bind through a separate profile so the verify cache is empty and the
    // verify must hit the remote, which is then made unreachable.
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'verify unreachable passphrase',
      idb: createFakeIdb(),
      kdf: KDF
    })
    const networkError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })
    wasState.getError = networkError

    await expect(
      verifyPassphrase({
        controller: DATA_CONTROLLER,
        passphrase: 'verify unreachable passphrase',
        idb: createFakeIdb(),
        kdf: KDF
      })
    ).rejects.toBe(networkError)
  })
})

describe('deleteKeyring', () => {
  it('deletes the unlock Space and every local record for the method', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'delete keyring passphrase',
      pointer: POINTER,
      idb,
      kdf: KDF
    })
    const { spaceId } = await unlockFor('delete keyring passphrase')

    const { unlockSpaceDeleted } = await deleteKeyring({
      passphrase: 'delete keyring passphrase',
      idb,
      kdf: KDF
    })

    expect(unlockSpaceDeleted).toBe(true)
    expect(deleteUnlockSpace).toHaveBeenCalledOnce()
    expect(wasState.spaces.has(spaceId)).toBe(false)
    // Both unlock-Space-keyed records go together.
    await expect(loadKeyringCache({ spaceId, idb })).resolves.toBeNull()
    await expect(loadClientKeyRecord({ spaceId, idb })).resolves.toBeNull()
    // The keyring is gone: nothing resolves for this passphrase any more.
    await expect(
      fetchKeyring({
        passphrase: 'delete keyring passphrase',
        idb,
        kdf: KDF
      })
    ).resolves.toBeNull()
  })

  it('clears the local records and reports unlockSpaceDeleted: false when the remote delete fails', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'delete-fails keyring passphrase',
      idb,
      kdf: KDF
    })
    const { spaceId } = await unlockFor('delete-fails keyring passphrase')
    vi.mocked(deleteUnlockSpace).mockRejectedValueOnce(
      new Error('delete failed')
    )

    const { unlockSpaceDeleted } = await deleteKeyring({
      passphrase: 'delete-fails keyring passphrase',
      idb,
      kdf: KDF
    })

    expect(unlockSpaceDeleted).toBe(false)
    await expect(loadKeyringCache({ spaceId, idb })).resolves.toBeNull()
    await expect(loadClientKeyRecord({ spaceId, idb })).resolves.toBeNull()
  })

  it('clears the local records with no remote call when no WAS server is configured', async () => {
    wasState.url = undefined
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'delete no-was passphrase',
      idb,
      kdf: KDF
    })
    const { spaceId } = await unlockFor('delete no-was passphrase')

    const { unlockSpaceDeleted } = await deleteKeyring({
      passphrase: 'delete no-was passphrase',
      idb,
      kdf: KDF
    })

    expect(unlockSpaceDeleted).toBe(true)
    expect(deleteUnlockSpace).not.toHaveBeenCalled()
    await expect(loadKeyringCache({ spaceId, idb })).resolves.toBeNull()
    await expect(loadClientKeyRecord({ spaceId, idb })).resolves.toBeNull()
  })
})

describe('deriveUnlockIdentity (method-agnostic derivation)', () => {
  /**
   * Frozen derivation vectors: these pin the production KDF salts (and the
   * whole derivation pipeline, down to the did:key encoding and the spaceId
   * hash) forever. If any of these values changes, existing users can no
   * longer locate their keyring -- so a failure here is a red flag, not a
   * value to blindly update.
   */
  describe('frozen derivation vectors', () => {
    it('pins the passphrase (PBKDF2) unlock Space under the real KEYRING_KDF', async () => {
      const { agent, spaceId } = await deriveUnlockIdentity({
        secret: 'freewallet test vector passphrase',
        kdf: KEYRING_KDF
      })
      expect(agent.id).toBe(
        'did:key:z6Mku4aGYK4PLysHqrpUNzoNbiu4ixzAEUEkefqamgFwY6vD'
      )
      expect(spaceId).toBe('PVkVUyJ24oyQh2BebkeUOygDfR5opfhJhG4KkMYTlzU')
    })

    it('pins the passkey (HKDF) unlock Space under the real PASSKEY_KDF', async () => {
      const secret = new Uint8Array(32)
      for (let index = 0; index < 32; index++) {
        secret[index] = index
      }
      const { agent, spaceId } = await deriveUnlockIdentity({
        secret,
        kdf: PASSKEY_KDF
      })
      expect(agent.id).toBe(
        'did:key:z6MkrWQ669H4SiPPYSHKhcx1QnWS5oP1gbD45GkQLVU6ecPU'
      )
      expect(spaceId).toBe('aAW83Cs-iZk6xEx8eYqF8WcKo6v5PE8CwEeYToOELkM')
    })
  })

  describe('KDF-family and salt separation', () => {
    // A fixed 32-byte input reused across the separation cases, so any
    // difference in derived Space is attributable to the KDF alone.
    const fixedSecret = new Uint8Array(32)
    for (let index = 0; index < 32; index++) {
      fixedSecret[index] = (index * 7 + 3) & 0xff
    }

    it('derives different Spaces under PBKDF2 vs HKDF for the same input (equal salts)', async () => {
      const sharedSalt = 'freewallet/test/shared-salt'
      const pbkdf2 = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'PBKDF2',
          iterations: 2,
          hash: 'SHA-256',
          salt: sharedSalt
        }
      })
      const hkdf = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'HKDF',
          hash: 'SHA-256',
          salt: sharedSalt,
          info: 'freewallet/test/info'
        }
      })
      expect(hkdf.spaceId).not.toBe(pbkdf2.spaceId)
    })

    it('derives different Spaces under two HKDF kdfs differing only in salt', async () => {
      const info = 'freewallet/test/info'
      const saltA = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'HKDF',
          hash: 'SHA-256',
          salt: 'freewallet/test/salt-a',
          info
        }
      })
      const saltB = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'HKDF',
          hash: 'SHA-256',
          salt: 'freewallet/test/salt-b',
          info
        }
      })
      expect(saltB.spaceId).not.toBe(saltA.spaceId)
    })

    it('derives different Spaces under two HKDF kdfs differing only in info', async () => {
      const salt = 'freewallet/test/shared-salt'
      const infoA = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'HKDF',
          hash: 'SHA-256',
          salt,
          info: 'freewallet/test/info-a'
        }
      })
      const infoB = await deriveUnlockIdentity({
        secret: fixedSecret,
        kdf: {
          version: 1,
          algorithm: 'HKDF',
          hash: 'SHA-256',
          salt,
          info: 'freewallet/test/info-b'
        }
      })
      expect(infoB.spaceId).not.toBe(infoA.spaceId)
    })
  })

  describe('bindUnlockSecret with an injected PRF output', () => {
    it('binds and recovers the client key set under a 32-byte passkey-PRF secret', async () => {
      const idb = createFakeIdb()
      const prfOutput = new Uint8Array(32)
      crypto.getRandomValues(prfOutput)
      const clientSeed = randomSeed()

      await bindUnlockSecret({
        clientSeed,
        controller: DATA_CONTROLLER,
        secret: prfOutput,
        kdf: PASSKEY_KDF,
        idb
      })

      const found = await fetchKeyring({
        secret: prfOutput,
        kdf: PASSKEY_KDF,
        idb
      })
      expect(found).not.toBeNull()
      expect(Array.from(found!.clientKeys!.clientSeed)).toEqual(
        Array.from(clientSeed)
      )
      expect(found!.controller).toBe(DATA_CONTROLLER)
    })

    it('misses (returns null) for a different 32-byte secret', async () => {
      const idb = createFakeIdb()
      const prfOutput = new Uint8Array(32)
      crypto.getRandomValues(prfOutput)

      await bindUnlockSecret({
        clientSeed: randomSeed(),
        controller: DATA_CONTROLLER,
        secret: prfOutput,
        kdf: PASSKEY_KDF,
        idb
      })

      const otherOutput = new Uint8Array(32)
      crypto.getRandomValues(otherOutput)
      const miss = await fetchKeyring({
        secret: otherOutput,
        kdf: PASSKEY_KDF,
        idb
      })
      expect(miss).toBeNull()
    })
  })
})

describe('management zcap delegation', () => {
  /**
   * The unlock Space URL a management zcap targets, built exactly as the module
   * builds it from the mocked WAS url.
   */
  function unlockSpaceUrl(spaceId: string): string {
    return new URL(`/space/${spaceId}`, wasState.url).toString()
  }

  describe('bindUnlockSecret with delegateManagementTo', () => {
    it('delegates a GET/DELETE zcap on the unlock Space to the account identity', async () => {
      const idb = createFakeIdb()
      const { manageCapability, unlockSpaceId } = await bindUnlockSecret({
        clientSeed: randomSeed(),
        controller: DATA_CONTROLLER,
        secret: 'manage delegate passphrase',
        kdf: KDF,
        delegateManagementTo: DATA_CONTROLLER,
        idb
      })

      expect(manageCapability).toBeDefined()
      const cap = manageCapability as IDelegatedZcap
      expect(cap.controller).toBe(DATA_CONTROLLER)
      expect(cap.allowedAction).toEqual(['GET', 'DELETE'])
      expect(cap.invocationTarget).toBe(unlockSpaceUrl(unlockSpaceId))

      // ~10 years out, within a generous minute of the expected instant.
      const expiresMs = Date.parse(cap.expires)
      const expectedMs = Date.now() + UNLOCK_MANAGE_ZCAP_TTL_MS
      expect(Math.abs(expiresMs - expectedMs)).toBeLessThan(60_000)
    })

    it('returns no capability without delegateManagementTo', async () => {
      const idb = createFakeIdb()
      const { manageCapability } = await bindUnlockSecret({
        clientSeed: randomSeed(),
        controller: DATA_CONTROLLER,
        secret: 'no delegate passphrase',
        kdf: KDF,
        idb
      })
      expect(manageCapability).toBeUndefined()
    })

    it('returns no capability when no WAS server is configured', async () => {
      wasState.url = undefined
      const idb = createFakeIdb()
      const { manageCapability } = await bindUnlockSecret({
        clientSeed: randomSeed(),
        controller: DATA_CONTROLLER,
        secret: 'no was delegate passphrase',
        kdf: KDF,
        delegateManagementTo: DATA_CONTROLLER,
        idb
      })
      expect(manageCapability).toBeUndefined()
    })
  })

  describe('fetchKeyring with mintManageCapability', () => {
    it('returns the unlock Space id and a capability delegated to the recovered controller', async () => {
      const idb = createFakeIdb()
      const { spaceId } = await unlockFor('mint on fetch passphrase')
      await bindPassphrase({
        clientSeed: randomSeed(),
        controller: DATA_CONTROLLER,
        passphrase: 'mint on fetch passphrase',
        idb,
        kdf: KDF
      })

      const found = await fetchKeyring({
        passphrase: 'mint on fetch passphrase',
        idb,
        kdf: KDF,
        mintManageCapability: true
      })

      expect(found).not.toBeNull()
      expect(found!.unlockSpaceId).toBe(spaceId)
      const cap = found!.manageCapability as IDelegatedZcap
      expect(cap.controller).toBe(DATA_CONTROLLER)
      expect(cap.allowedAction).toEqual(['GET', 'DELETE'])
      expect(cap.invocationTarget).toBe(unlockSpaceUrl(spaceId))
    })

    it('returns the unlock Space id but no capability without mintManageCapability', async () => {
      const idb = createFakeIdb()
      const { spaceId } = await unlockFor('no mint passphrase')
      await bindPassphrase({
        clientSeed: randomSeed(),
        controller: DATA_CONTROLLER,
        passphrase: 'no mint passphrase',
        idb,
        kdf: KDF
      })

      const found = await fetchKeyring({
        passphrase: 'no mint passphrase',
        idb,
        kdf: KDF
      })
      expect(found!.unlockSpaceId).toBe(spaceId)
      expect(found!.manageCapability).toBeUndefined()
    })
  })

  describe('changePassphrase return value', () => {
    it("returns the new passphrase's unlock Space id and management capability", async () => {
      const idb = createFakeIdb()
      const clientSeed = randomSeed()
      await bindPassphrase({
        clientSeed,
        controller: DATA_CONTROLLER,
        passphrase: 'change return old passphrase',
        idb,
        kdf: KDF
      })
      const newSpace = (await unlockFor('change return new passphrase')).spaceId

      const { unlockSpaceId, manageCapability } = await changePassphrase({
        clientSeed,
        controller: DATA_CONTROLLER,
        oldPassphrase: 'change return old passphrase',
        newPassphrase: 'change return new passphrase',
        idb,
        kdf: KDF
      })

      expect(unlockSpaceId).toBe(newSpace)
      const cap = manageCapability as IDelegatedZcap
      expect(cap.controller).toBe(DATA_CONTROLLER)
      expect(cap.allowedAction).toEqual(['GET', 'DELETE'])
      expect(cap.invocationTarget).toBe(unlockSpaceUrl(newSpace))
    })
  })
})

describe('standing unlock records (FW-154)', () => {
  const DELEGATION = {
    '@context': 'https://w3id.org/zcap/v1',
    id: 'urn:uuid:standing-bridge-delegation',
    controller: 'did:key:z6MkStandingClientForTests',
    invocationTarget: 'https://was.example.test/space/space-123/id/did.jsonl',
    allowedAction: ['PUT'],
    expires: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
    parentCapability: 'urn:zcap:root:x',
    proof: { verificationMethod: 'did:key:z6MkSignerForTests#z6MkSigner' }
  } as unknown as IDelegatedZcap

  const DELEGATED_CLIENTS = {
    '@context': 'https://w3id.org/zcap/v1',
    id: 'urn:uuid:standing-clientAnnex-delegation',
    controller: 'did:key:z6MkStandingClientForTests',
    invocationTarget: 'https://was.example.test/space/clientAnnex-123/',
    allowedAction: ['GET', 'PUT'],
    expires: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
    parentCapability: 'urn:zcap:root:y',
    proof: { verificationMethod: 'did:key:z6MkSignerForTests#z6MkSigner' }
  } as unknown as IDelegatedZcap

  function ladderSeed(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32))
  }

  it('round-trips the bridge delegation and ladder seed through bind + fetch', async () => {
    const idb = createFakeIdb()
    const seed = ladderSeed()

    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'standing round trip',
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: seed,
      idb,
      kdf: KDF
    })

    const found = await fetchKeyring({
      passphrase: 'standing round trip',
      idb,
      kdf: KDF
    })
    expect(found).not.toBeNull()
    expect(found!.controller).toBe(DATA_CONTROLLER)
    expect(found!.pointer).toEqual(POINTER)
    expect(found!.standing).toBeDefined()
    expect(found!.standing!.delegation).toEqual(DELEGATION)
    // A sibling-less bind stays sibling-less (tolerant absence).
    expect(found!.standing!.delegatedClients).toBeUndefined()
    expect(found!.standing!.ladderSeed).toEqual(seed)
    expect(found!.standingClient).toBeDefined()
    expect(found!.clientKeys).toBeDefined()
    expect(found!.enrollClientKeys).toBeUndefined()
    expect(found!.rebindStandingRecord).toBeDefined()
  })

  it('round-trips the annex-Space sibling delegation (FW-194)', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'standing sibling round trip',
      pointer: POINTER,
      delegation: DELEGATION,
      delegatedClients: DELEGATED_CLIENTS,
      ladderSeed: ladderSeed(),
      idb,
      kdf: KDF
    })
    const found = await fetchKeyring({
      passphrase: 'standing sibling round trip',
      idb,
      kdf: KDF
    })
    expect(found!.standing!.delegation).toEqual(DELEGATION)
    expect(found!.standing!.delegatedClients).toEqual(DELEGATED_CLIENTS)
  })

  it('exposes enrollClientKeys on a fresh browser, and persists through it', async () => {
    const boundIdb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'standing fresh browser',
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: ladderSeed(),
      idb: boundIdb,
      kdf: KDF
    })

    // A different browser profile: same remote record, empty local records.
    const freshIdb = createFakeIdb()
    const found = await fetchKeyring({
      passphrase: 'standing fresh browser',
      idb: freshIdb,
      kdf: KDF
    })
    expect(found!.clientKeys).toBeUndefined()
    expect(found!.standing).toBeDefined()
    expect(found!.enrollClientKeys).toBeDefined()

    const newSeed = randomSeed()
    await found!.enrollClientKeys!({
      clientSeed: newSeed,
      controller: DATA_CONTROLLER
    })
    const after = await fetchKeyring({
      passphrase: 'standing fresh browser',
      idb: freshIdb,
      kdf: KDF
    })
    expect(after!.clientKeys).toBeDefined()
    expect(after!.clientKeys!.clientSeed).toEqual(newSeed)
    expect(after!.clientKeys!.controller).toBe(DATA_CONTROLLER)
  })

  it('refuses a record whose account binding fails the credential MAC', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'standing tampered binding',
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: ladderSeed(),
      idb,
      kdf: KDF
    })

    const { spaceId } = await unlockFor('standing tampered binding')
    const record = wasState.spaces.get(spaceId) as { binding: string }
    // A host swapping the credential-authenticated core cannot recompute the
    // binding tag; simulate it by corrupting the stored tag.
    wasState.spaces.set(spaceId, {
      ...record,
      binding: `${record.binding.slice(0, -2)}xx`
    })

    await expect(
      fetchKeyring({ passphrase: 'standing tampered binding', idb, kdf: KDF })
    ).rejects.toBeInstanceOf(KeyringRecordForgedError)
  })

  it('widens the management zcap to include PUT on a standing bind', async () => {
    const idb = createFakeIdb()
    const { manageCapability } = await bindUnlockSecret({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      secret: 'standing management actions',
      kdf: KDF,
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: ladderSeed(),
      delegateManagementTo: DATA_CONTROLLER,
      idb
    })
    const cap = manageCapability as unknown as { allowedAction: string[] }
    expect(cap.allowedAction).toEqual(['GET', 'PUT', 'DELETE'])
  })

  it('mints the widened management zcap on every standing login too', async () => {
    const idb = createFakeIdb()
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'standing login management actions',
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: ladderSeed(),
      idb,
      kdf: KDF
    })

    const found = await fetchKeyring({
      passphrase: 'standing login management actions',
      idb,
      kdf: KDF,
      mintManageCapability: true
    })

    // The registry backfill stores whichever capability the login minted, so
    // a narrow mint here would strip the standing record's re-PUT authority.
    const cap = found!.manageCapability as IDelegatedZcap
    expect(cap.allowedAction).toEqual(['GET', 'PUT', 'DELETE'])
  })
})

describe('fetchTransientKeyring (FW-215)', () => {
  const DELEGATION = {
    '@context': 'https://w3id.org/zcap/v1',
    id: 'urn:uuid:transient-bridge-delegation',
    controller: 'did:key:z6MkStandingClientForTests',
    invocationTarget: 'https://was.example.test/space/space-123/id/did.jsonl',
    allowedAction: ['PUT'],
    expires: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
    parentCapability: 'urn:zcap:root:x',
    proof: { verificationMethod: 'did:key:z6MkSignerForTests#z6MkSigner' }
  } as unknown as IDelegatedZcap

  /**
   * A global `indexedDB` stand-in that records every database name opened, so
   * a test can assert (via `databases()`, before and after) that the
   * transient fetch never creates the `freewallet-session` database. Backed
   * by the ordinary fake factory, so a slipped browser-local read would
   * succeed -- and be caught by the assertion -- rather than crash.
   */
  function trackingIdb(): IDBFactory & {
    databases(): Promise<Array<{ name?: string; version?: number }>>
  } {
    const inner = createFakeIdb()
    const names = new Set<string>()
    return {
      open(name: string, version?: number) {
        names.add(name)
        return inner.open(name, version)
      },
      async databases() {
        return Array.from(names).map(name => ({ name, version: 1 }))
      }
    } as unknown as IDBFactory & {
      databases(): Promise<Array<{ name?: string; version?: number }>>
    }
  }

  it('resolves a standing record without creating the session database', async () => {
    // Bind through another browser profile, so this one starts with nothing
    // local -- the public-terminal case.
    await bindPassphrase({
      clientSeed: randomSeed(),
      controller: DATA_CONTROLLER,
      passphrase: 'transient standing fetch',
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: crypto.getRandomValues(new Uint8Array(32)),
      idb: createFakeIdb(),
      kdf: KDF
    })

    const idb = trackingIdb()
    vi.stubGlobal('indexedDB', idb)
    expect(await idb.databases()).toEqual([])

    const found = await fetchTransientKeyring({
      secret: 'transient standing fetch',
      kdf: KDF,
      accountLogPinStore: memoryResourceLogPinStore()
    })

    expect(found).not.toBeNull()
    expect(found!.controller).toBe(DATA_CONTROLLER)
    expect(found!.pointer).toEqual(POINTER)
    expect(found!.standing).toBeDefined()
    expect(found!.standing!.delegation).toEqual(DELEGATION)
    expect(found!.standingClient).toBeDefined()
    // Nothing browser-local rides the result: no client keys, no persist
    // or enroll closures, no management zcap. The record re-bind closure
    // DOES ride along (the visit's annex mend re-seals a fresh sibling
    // delegation through it), in its transient shape -- a remote record
    // write that touches no local cache or freshness pin, as the database
    // check below confirms.
    expect(found).not.toHaveProperty('clientKeys')
    expect(found).not.toHaveProperty('persistClientKeys')
    expect(found).not.toHaveProperty('enrollClientKeys')
    expect(found).not.toHaveProperty('manageCapability')
    expect(typeof found!.rebindStandingRecord).toBe('function')
    // And no IndexedDB database was created at any point.
    expect(await idb.databases()).toEqual([])
  })

  it('returns null on a remote miss, still touching no database', async () => {
    const idb = trackingIdb()
    vi.stubGlobal('indexedDB', idb)

    const found = await fetchTransientKeyring({
      secret: 'transient unknown account',
      kdf: KDF,
      accountLogPinStore: memoryResourceLogPinStore()
    })

    expect(found).toBeNull()
    expect(await idb.databases()).toEqual([])
  })

  it('requires a configured WAS server (remote-only, no cache to serve)', async () => {
    wasState.url = undefined
    await expect(
      fetchTransientKeyring({
        secret: 'transient no was',
        kdf: KDF,
        accountLogPinStore: memoryResourceLogPinStore()
      })
    ).rejects.toThrow(TypeError)
  })

  it('rethrows a network error unchanged (no offline cache fallback)', async () => {
    const networkError = new WasError('NetworkError when attempting to fetch', {
      cause: new TypeError('NetworkError when attempting to fetch')
    })
    wasState.getError = networkError
    await expect(
      fetchTransientKeyring({
        secret: 'transient offline',
        kdf: KDF,
        accountLogPinStore: memoryResourceLogPinStore()
      })
    ).rejects.toBe(networkError)
  })

  it('refuses a host-crafted record signed by a key the secret does not derive', async () => {
    const { record, spaceId } = await craftRecord({
      passphrase: 'transient forged record',
      signAs: 'stranger',
      plaintext: {
        controller: DATA_CONTROLLER,
        pointer: { ...POINTER, spaceId: 'attacker-space' },
        createdAt: new Date().toISOString()
      }
    })
    wasState.spaces.set(spaceId, record)

    await expect(
      fetchTransientKeyring({
        secret: 'transient forged record',
        kdf: KDF,
        accountLogPinStore: memoryResourceLogPinStore()
      })
    ).rejects.toThrow(KeyringRecordForgedError)
  })

  it('settles a cascade-re-minted record under the caller-supplied pin store', async () => {
    // A record signed by an enrolled client's account key rather than the
    // unlock key (the revocation cascade's bridge re-mint): the pending proof
    // must settle against the account document, with the account-log read
    // riding exactly the pin store the caller supplied.
    const passphrase = 'transient pending proof'
    const { keyAgreementKey, spaceId, seed } = await unlockFor(passphrase)
    const standing = await standingClientFromUnlockSeed({ unlockSeed: seed })
    const strangerSigner = recordSignerFromAgent({
      keyAgent: (await unlockFor(STRANGER_PASSPHRASE)).agent
    })
    const record = await wrapUnlockRecord({
      controller: DATA_CONTROLLER,
      pointer: POINTER,
      delegation: DELEGATION,
      keyAgreementKey: keyAgreementKey as unknown as IKeyAgreementKey,
      signer: strangerSigner,
      bindingMacKey: standing.bindingMacKey
    })
    wasState.spaces.set(spaceId, record)
    clientsState.signingKeys = [strangerSigner.keyMultibase]

    const accountLogPinStore = memoryResourceLogPinStore()
    const found = await fetchTransientKeyring({
      secret: passphrase,
      kdf: KDF,
      accountLogPinStore
    })

    expect(found!.pointer).toEqual(POINTER)
    const settleArgs = vi.mocked(currentAccountRecordSigners).mock
      .calls[0][0] as unknown as {
      pointer: { did: string }
      accountLogPinStore: unknown
    }
    expect(settleArgs.accountLogPinStore).toBe(accountLogPinStore)
    expect(settleArgs.pointer.did).toBe(POINTER.did)
  })

  it('refuses a re-minted record no enrolled client accounts for', async () => {
    const passphrase = 'transient unsettled proof'
    const { keyAgreementKey, spaceId, seed } = await unlockFor(passphrase)
    const standing = await standingClientFromUnlockSeed({ unlockSeed: seed })
    const record = await wrapUnlockRecord({
      controller: DATA_CONTROLLER,
      pointer: POINTER,
      delegation: DELEGATION,
      keyAgreementKey: keyAgreementKey as unknown as IKeyAgreementKey,
      signer: recordSignerFromAgent({
        keyAgent: (await unlockFor(STRANGER_PASSPHRASE)).agent
      }),
      bindingMacKey: standing.bindingMacKey
    })
    wasState.spaces.set(spaceId, record)
    clientsState.signingKeys = []

    await expect(
      fetchTransientKeyring({
        secret: passphrase,
        kdf: KDF,
        accountLogPinStore: memoryResourceLogPinStore()
      })
    ).rejects.toThrow(KeyringRecordForgedError)
  })
})
