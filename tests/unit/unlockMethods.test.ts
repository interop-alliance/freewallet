// @vitest-environment node
/**
 * Unit tests for the unlock-methods registry (`src/session/unlockMethods.ts`):
 * the wrap/unwrap round-trip (a record survives JWE encryption under the vault
 * KAK and its outer/inner version validation), the no-WAS cache-only path, and
 * the remote-first read that refreshes the local cache on a hit. The
 * `wasRemoteStore` data-Space helpers are replaced by an in-memory fake keyed
 * by data Space id; the `freewallet-session` IndexedDB cache runs unmocked
 * against a minimal in-memory `IDBFactory` (node has no IndexedDB). The real
 * EDV cipher and CapabilityAgent / X25519 derivations run unmocked.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IZcap
} from '@interop/data-integrity-core'
import type { Session } from '@/types/auth'
import {
  loadKeyringCache,
  loadUnlockMethodsCache,
  saveKeyringCache
} from '@/lib/sessionKey'

/**
 * Shared mutable state for the two mocks: the configured WAS url (mutable so a
 * test can drop it to exercise the cache-only branch), the in-memory data
 * Spaces (spaceId to stored record), and an optional error the remote GET
 * should throw.
 */
const wasState = vi.hoisted(() => ({
  url: 'https://was.example.test' as string | undefined,
  records: new Map<string, unknown>(),
  getError: undefined as unknown,
  calls: [] as string[]
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return wasState.url
  }
}))

vi.mock('@/stores/wasRemoteStore', () => ({
  ensureUnlockMethodsCollection: vi.fn(async () => {}),
  putUnlockMethodsRecord: vi.fn(
    async ({ spaceId, record }: { spaceId: string; record: unknown }) => {
      wasState.records.set(spaceId, record)
    }
  ),
  getUnlockMethodsRecord: vi.fn(async ({ spaceId }: { spaceId: string }) => {
    if (wasState.getError) {
      throw wasState.getError
    }
    return wasState.records.has(spaceId) ? wasState.records.get(spaceId) : null
  })
}))

vi.mock('@interop/wallet-core/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keyring')>()),
  deleteUnlockSpaceWithCapability: vi.fn(async () => {
    wasState.calls.push('deleteUnlockSpace')
  })
}))

vi.mock('@/session/credentialRotation', () => ({
  rotateOffUnlockCredential: vi.fn(async () => {
    wasState.calls.push('rotateOffUnlockCredential')
    return { rotated: true, collections: { outcomes: {}, failed: [] } }
  })
}))

vi.mock('@/lib/passkey', () => ({
  assertPasskeyPrf: vi.fn(async () => {
    wasState.calls.push('assertPasskeyPrf')
    return { prfOutput: new Uint8Array(32) }
  }),
  registerPasskey: vi.fn()
}))

vi.mock('@/session/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/keyring')>()),
  deleteUnlockMethod: vi.fn(async () => {
    wasState.calls.push('deleteUnlockMethod')
  })
}))

import {
  adoptPassphraseRebind,
  backfillPassphraseUnlockMethod,
  getUnlockMethods,
  managementZcapClient,
  putUnlockMethods,
  revokeUnlockMethod,
  revokeUnlockMethodByCeremony,
  rewrapUnlockMethodsRecord,
  type PasskeyUnlockMethod,
  type PassphraseUnlockMethod,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import { deleteUnlockSpaceWithCapability } from '@interop/wallet-core/keyring'
import { rotateOffUnlockCredential } from '@/session/credentialRotation'
import {
  ensureUnlockMethodsCollection,
  getUnlockMethodsRecord,
  putUnlockMethodsRecord
} from '@/stores/wasRemoteStore'

const DATA_CONTROLLER = 'did:key:z6MkDataControllerForUnlockMethods'
const DATA_SPACE_ID = 'PVkVUyJ24oyQh2BebkeUOygDfR5opfhJhG4KkMYTlzU'

/**
 * A minimal in-memory `IDBFactory` sufficient for the session-store cache
 * helpers in `src/lib/sessionKey.ts` (a single object store, get/put/delete by
 * key). Each test gets a fresh one so caches start empty.
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
 * Builds a `Session` stand-in carrying a real (deterministic) vault
 * KAK + resolver -- so the EDV cipher can genuinely wrap and unwrap -- plus the
 * data controller / Space id the registry addresses. The `zcapClient` is inert:
 * every remote helper is mocked, so its value is never dereferenced.
 *
 * @returns {Promise<Session>}
 */
async function makeSession(): Promise<Session> {
  const seed = new Uint8Array(32)
  seed.fill(7)
  const agent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'test-data',
    keyName: 'test-data-key'
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
  return {
    user: { id: DATA_CONTROLLER },
    profile: { keyAgreementKey, keyResolver, zcapClient: {} },
    storage: { spaceId: DATA_SPACE_ID },
    isGuest: false
  } as unknown as Session
}

function sampleRecord(): UnlockMethodsRecord {
  return {
    version: 1,
    userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
    methods: [
      {
        type: 'passkey',
        label: 'Passkey created 2026-07-19',
        createdAt: '2026-07-19T00:00:00.000Z',
        credentialId: 'Y3JlZC1pZA',
        transports: ['internal'],
        backupEligibility: true,
        backupState: true,
        unlockSpaceId: 'unlock-space-abc'
      }
    ]
  }
}

/**
 * A stand-in management zcap. `deleteUnlockSpaceWithCapability` is mocked, so
 * the value is only ever passed through and compared by reference -- its shape
 * is never validated.
 */
const FAKE_CAP = {
  id: 'urn:zcap:test-management',
  invocationTarget: 'https://was.example.test/space/unlock-space-abc'
} as unknown as IZcap

/**
 * A stand-in management zcap expiring the given interval from now, for the
 * backfill's expiry-refresh cases.
 *
 * @param options {object}
 * @param options.msFromNow {number}
 * @returns {IZcap}
 */
function capExpiringIn({ msFromNow }: { msFromNow: number }): IZcap {
  return {
    id: `urn:zcap:test-management-${msFromNow}`,
    invocationTarget: 'https://was.example.test/space/unlock-space-abc',
    expires: new Date(Date.now() + msFromNow).toISOString()
  } as unknown as IZcap
}

const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000

/**
 * A passkey registry entry, optionally carrying a management capability.
 *
 * @param [options] {object}
 * @param [options.manageCapability] {IZcap}
 * @returns {PasskeyUnlockMethod}
 */
function passkeyEntry({
  manageCapability
}: { manageCapability?: IZcap } = {}): PasskeyUnlockMethod {
  return {
    type: 'passkey',
    label: 'Passkey created 2026-07-19',
    createdAt: '2026-07-19T00:00:00.000Z',
    credentialId: 'Y3JlZC1pZA',
    transports: ['internal'],
    backupEligibility: true,
    backupState: true,
    unlockSpaceId: 'unlock-space-abc',
    ...(manageCapability ? { manageCapability } : {})
  }
}

/**
 * A session whose profile names a passphrase unlock method (so
 * `backfillPassphraseUnlockMethod` acts on it).
 *
 * @param options {object}
 * @param options.unlockSpaceId {string}
 * @param [options.manageCapability] {IZcap}
 * @returns {Promise<Session>}
 */
async function makePassphraseSession({
  unlockSpaceId,
  manageCapability
}: {
  unlockSpaceId: string
  manageCapability?: IZcap
}): Promise<Session> {
  const session = await makeSession()
  session.profile.unlockMethod = {
    type: 'passphrase',
    unlockSpaceId,
    manageCapability
  }
  return session
}

beforeEach(() => {
  wasState.url = 'https://was.example.test'
  wasState.records.clear()
  wasState.getError = undefined
  wasState.calls = []
  vi.clearAllMocks()
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('put / get round-trip', () => {
  it('survives wrap/unwrap and stores an encrypted (versioned) envelope remotely', async () => {
    const idb = createFakeIdb()
    const session = await makeSession()
    const record = sampleRecord()

    await putUnlockMethods({ session, record, idb })
    expect(ensureUnlockMethodsCollection).toHaveBeenCalledOnce()

    // The remote body is the JWE-wrapped envelope, not the plaintext record.
    const stored = wasState.records.get(DATA_SPACE_ID) as {
      version: number
      wrapped: { jwe?: unknown }
    }
    expect(stored.version).toBe(1)
    expect(stored.wrapped.jwe).toBeDefined()
    expect(JSON.stringify(stored)).not.toContain('unlock-space-abc')

    const found = await getUnlockMethods({ session, idb })
    expect(found).toEqual(record)
    expect(getUnlockMethodsRecord).toHaveBeenCalledOnce()
  })

  it('returns null when no registry exists anywhere', async () => {
    const session = await makeSession()
    const found = await getUnlockMethods({ session, idb: createFakeIdb() })
    expect(found).toBeNull()
  })

  it('rejects a stored record whose outer version is not 1', async () => {
    const session = await makeSession()
    wasState.records.set(DATA_SPACE_ID, { version: 2, wrapped: {} })

    await expect(
      getUnlockMethods({ session, idb: createFakeIdb() })
    ).rejects.toThrow(/version/)
  })
})

describe('no-WAS cache-only path', () => {
  it('writes and reads the registry from the cache with no remote call', async () => {
    wasState.url = undefined
    const idb = createFakeIdb()
    const session = await makeSession()
    const record = sampleRecord()

    await putUnlockMethods({ session, record, idb })
    expect(ensureUnlockMethodsCollection).not.toHaveBeenCalled()
    expect(wasState.records.size).toBe(0)

    const found = await getUnlockMethods({ session, idb })
    expect(found).toEqual(record)
    expect(getUnlockMethodsRecord).not.toHaveBeenCalled()
  })
})

describe('remote-first read', () => {
  it('reads remote on a cache miss and refreshes the local cache', async () => {
    const session = await makeSession()
    const record = sampleRecord()
    // Populate the remote (and a throwaway profile's cache) via one idb, then
    // read on a fresh idb whose cache starts empty.
    await putUnlockMethods({ session, record, idb: createFakeIdb() })
    vi.clearAllMocks()

    const freshIdb = createFakeIdb()
    expect(
      await loadUnlockMethodsCache({
        controller: DATA_CONTROLLER,
        idb: freshIdb
      })
    ).toBeNull()

    const found = await getUnlockMethods({ session, idb: freshIdb })
    expect(found).toEqual(record)
    expect(getUnlockMethodsRecord).toHaveBeenCalledOnce()

    // The remote hit refreshed the fresh profile's cache.
    expect(
      await loadUnlockMethodsCache({
        controller: DATA_CONTROLLER,
        idb: freshIdb
      })
    ).not.toBeNull()
  })

  it('drops the cache and returns null when the remote registry is gone', async () => {
    const idb = createFakeIdb()
    const session = await makeSession()
    await putUnlockMethods({ session, record: sampleRecord(), idb })
    // The registry was deleted remotely while this profile's cache still holds
    // a copy.
    wasState.records.clear()

    const found = await getUnlockMethods({ session, idb })
    expect(found).toBeNull()
    expect(
      await loadUnlockMethodsCache({ controller: DATA_CONTROLLER, idb })
    ).toBeNull()
  })

  it('rethrows a remote read failure', async () => {
    const session = await makeSession()
    const networkError = new Error('NetworkError when attempting to fetch')
    wasState.getError = networkError

    await expect(
      getUnlockMethods({ session, idb: createFakeIdb() })
    ).rejects.toBe(networkError)
  })
})

describe('revokeUnlockMethod', () => {
  it('deletes the unlock Space, drops the keyring cache, and removes the registry entry', async () => {
    const idb = createFakeIdb()
    const session = await makeSession()
    const entry = passkeyEntry({ manageCapability: FAKE_CAP })
    await putUnlockMethods({
      session,
      record: {
        version: 1,
        userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      },
      idb
    })
    // Seed a keyring cache for the unlock Space so its removal is observable.
    await saveKeyringCache({
      spaceId: entry.unlockSpaceId,
      record: { version: 1, wrapped: {} },
      idb
    })
    vi.clearAllMocks()

    await revokeUnlockMethod({ session, entry, idb })

    // The Space delete was invoked with the entry's capability + spaceId.
    expect(deleteUnlockSpaceWithCapability).toHaveBeenCalledOnce()
    const args = vi.mocked(deleteUnlockSpaceWithCapability).mock.calls[0][0]
    expect(args.spaceId).toBe(entry.unlockSpaceId)
    expect(args.capability).toBe(FAKE_CAP)

    // The keyring cache for the unlock Space is gone.
    await expect(
      loadKeyringCache({ spaceId: entry.unlockSpaceId, idb })
    ).resolves.toBeNull()

    // The registry no longer lists the entry.
    const after = await getUnlockMethods({ session, idb })
    expect(after!.methods).toHaveLength(0)
  })

  it('throws when a WAS server is configured and the entry has no capability', async () => {
    const idb = createFakeIdb()
    const session = await makeSession()
    const entry = passkeyEntry()

    await expect(revokeUnlockMethod({ session, entry, idb })).rejects.toThrow()
    expect(deleteUnlockSpaceWithCapability).not.toHaveBeenCalled()
  })

  it('skips the Space delete but still cleans up with no WAS server', async () => {
    wasState.url = undefined
    const idb = createFakeIdb()
    const session = await makeSession()
    const entry = passkeyEntry()
    await putUnlockMethods({
      session,
      record: {
        version: 1,
        userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      },
      idb
    })
    await saveKeyringCache({
      spaceId: entry.unlockSpaceId,
      record: { version: 1, wrapped: {} },
      idb
    })

    await revokeUnlockMethod({ session, entry, idb })

    expect(deleteUnlockSpaceWithCapability).not.toHaveBeenCalled()
    await expect(
      loadKeyringCache({ spaceId: entry.unlockSpaceId, idb })
    ).resolves.toBeNull()
    const after = await getUnlockMethods({ session, idb })
    expect(after!.methods).toHaveLength(0)
  })
})

describe('the credential rotation inside a revocation', () => {
  /**
   * A passkey entry carrying a standing posture, so the rotation ceremony has
   * something to retire.
   *
   * @returns {PasskeyUnlockMethod}
   */
  function standingEntry(): PasskeyUnlockMethod {
    return {
      ...passkeyEntry({ manageCapability: FAKE_CAP }),
      keyAgreementKeyMultibase: 'z6LSStandingPasskeyKak',
      updateKeyMultibase: 'z6MkStandingPasskeyRung'
    }
  }

  it('rotates before the Space delete and hands the outcome back', async () => {
    const idb = createFakeIdb()
    const session = await makeSession()
    const entry = standingEntry()
    await putUnlockMethods({
      session,
      record: {
        version: 1,
        userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      },
      idb
    })
    wasState.calls = []

    const outcome = await revokeUnlockMethod({
      session,
      entry,
      idb,
      verb: 'removing a passkey'
    })

    // The rotation runs while the registry is still sealed to the old vault
    // keys, so the teardown below can still read and write it.
    expect(wasState.calls).toEqual([
      'rotateOffUnlockCredential',
      'deleteUnlockSpace'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).toHaveBeenCalledWith(
      expect.objectContaining({ method: entry, verb: 'removing a passkey' })
    )
    expect(outcome).toEqual({
      rotated: true,
      collections: { outcomes: {}, failed: [] }
    })
  })

  it('leaves a recovery-code entry alone (it rotated in its own ceremony)', async () => {
    const idb = createFakeIdb()
    const session = await makeSession()
    const entry = {
      type: 'recovery-code',
      label: 'Recovery code',
      createdAt: '2026-08-01T00:00:00.000Z',
      unlockSpaceId: 'unlock-space-code',
      manageCapability: FAKE_CAP,
      recoveryKid: 'did:key:z6LSCode#kak',
      keyAgreementKeyMultibase: 'z6LSCodeKak',
      updateKeyMultibase: 'z6MkCodeUpdate'
    } as const
    await putUnlockMethods({
      session,
      record: {
        version: 1,
        userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      },
      idb
    })

    const outcome = await revokeUnlockMethod({ session, entry, idb })
    expect(outcome).toBeNull()
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
  })

  it('taps the passkey before rotating, on the ceremony path', async () => {
    const idb = createFakeIdb()
    const session = await makeSession()
    const entry = standingEntry()
    await putUnlockMethods({
      session,
      record: {
        version: 1,
        userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      },
      idb
    })
    wasState.calls = []

    const outcome = await revokeUnlockMethodByCeremony({ session, entry, idb })

    expect(wasState.calls).toEqual([
      'assertPasskeyPrf',
      'rotateOffUnlockCredential',
      'deleteUnlockMethod'
    ])
    expect(outcome?.rotated).toBe(true)
    const after = await getUnlockMethods({ session, idb })
    expect(after!.methods).toHaveLength(0)
  })
})

describe('managementZcapClient', () => {
  it('signs under the did:key for a grant delegated to this client', async () => {
    const session = await makeSession()
    const keyAgent = await CapabilityAgent.fromSeed({
      seed: new Uint8Array(32).fill(9),
      handle: 'test-client',
      keyName: 'test-client-key'
    })
    session.profile.keyAgent = keyAgent as never
    const capability = {
      ...FAKE_CAP,
      controller: keyAgent.id
    } as unknown as IZcap

    const client = managementZcapClient({ session, capability })
    expect(client).not.toBe(session.profile.zcapClient)
    const { invocationSigner } = client as unknown as {
      invocationSigner: { id: string }
    }
    expect(invocationSigner.id.startsWith(keyAgent.id)).toBe(true)
  })

  it('signs with the session root client for an account-DID grant', async () => {
    // A promoted account's grant names the did:webvh; the session's root
    // zcapClient is what signs under the promoted verification method.
    const session = await makeSession()
    const keyAgent = await CapabilityAgent.fromSeed({
      seed: new Uint8Array(32).fill(9),
      handle: 'test-client',
      keyName: 'test-client-key'
    })
    session.profile.keyAgent = keyAgent as never
    const capability = {
      ...FAKE_CAP,
      controller: 'did:webvh:QmScid:was.example.test:space:space-1:id'
    } as unknown as IZcap

    expect(managementZcapClient({ session, capability })).toBe(
      session.profile.zcapClient
    )
  })

  it('falls back to the session root client with no keyAgent held', async () => {
    const session = await makeSession()
    const capability = {
      ...FAKE_CAP,
      controller: 'did:key:z6MkSomeoneElse'
    } as unknown as IZcap

    expect(managementZcapClient({ session, capability })).toBe(
      session.profile.zcapClient
    )
  })
})

describe('backfillPassphraseUnlockMethod', () => {
  it('is a no-op without a passphrase unlockMethod in the profile', async () => {
    const idb = createFakeIdb()
    const session = await makeSession() // no profile.unlockMethod

    const result = await backfillPassphraseUnlockMethod({ session, idb })
    expect(result).toBeNull()
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('still returns an existing registry for a non-passphrase session', async () => {
    const idb = createFakeIdb()
    const session = await makeSession() // e.g. a passkey login
    await putUnlockMethods({ session, record: sampleRecord(), idb })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    // The Settings section loads through this function for every session; a
    // passkey-login session must see the account's registry (not `null`, which
    // would read as "no registry" and invite an overwriting re-creation).
    const result = await backfillPassphraseUnlockMethod({
      session,
      idb,
      createIfMissing: true
    })
    expect(result).toEqual(sampleRecord())
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('does not create a registry without createIfMissing', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({ unlockSpaceId: 'ps-space' })

    const result = await backfillPassphraseUnlockMethod({ session, idb })
    expect(result).toBeNull()
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('creates the registry with a passphrase entry when createIfMissing', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      manageCapability: FAKE_CAP
    })

    const result = await backfillPassphraseUnlockMethod({
      session,
      idb,
      createIfMissing: true
    })

    expect(result).not.toBeNull()
    expect(result!.userHandle).toBeTruthy()
    expect(result!.methods).toHaveLength(1)
    expect(result!.methods[0]).toMatchObject({
      type: 'passphrase',
      unlockSpaceId: 'ps-space',
      manageCapability: FAKE_CAP
    })
    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
  })

  it('appends the passphrase entry when the existing registry has none', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({ unlockSpaceId: 'ps-space' })
    // An existing registry (one passkey entry, no passphrase).
    await putUnlockMethods({ session, record: sampleRecord(), idb })

    const result = await backfillPassphraseUnlockMethod({ session, idb })
    expect(result!.methods).toHaveLength(2)
    expect(
      result!.methods.some(
        method =>
          method.type === 'passphrase' && method.unlockSpaceId === 'ps-space'
      )
    ).toBe(true)
  })

  it('replaces the passphrase entry when its unlockSpaceId changed, preserving createdAt', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({
      unlockSpaceId: 'new-ps-space'
    })
    const existing: PassphraseUnlockMethod = {
      type: 'passphrase',
      createdAt: '2026-01-01T00:00:00.000Z',
      unlockSpaceId: 'old-ps-space'
    }
    await putUnlockMethods({
      session,
      record: {
        version: 1,
        userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [existing]
      },
      idb
    })

    const result = await backfillPassphraseUnlockMethod({ session, idb })
    expect(result!.methods).toHaveLength(1)
    const entry = result!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    expect(entry!.unlockSpaceId).toBe('new-ps-space')
    expect(entry!.createdAt).toBe('2026-01-01T00:00:00.000Z')
  })

  it('refreshes the passphrase entry when its management zcap nears expiry', async () => {
    const idb = createFakeIdb()
    const fresh = capExpiringIn({ msFromNow: ONE_YEAR_MS })
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      manageCapability: fresh
    })
    const existing: PassphraseUnlockMethod = {
      type: 'passphrase',
      createdAt: '2026-01-01T00:00:00.000Z',
      unlockSpaceId: 'ps-space',
      manageCapability: capExpiringIn({ msFromNow: 1000 })
    }
    await putUnlockMethods({
      session,
      record: {
        version: 1,
        userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [existing]
      },
      idb
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session, idb })
    const entry = result!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    expect(entry!.manageCapability).toEqual(fresh)
    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
  })

  it('leaves a passphrase entry with a fresh management zcap alone', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      manageCapability: capExpiringIn({ msFromNow: ONE_YEAR_MS })
    })
    const stored = capExpiringIn({ msFromNow: ONE_YEAR_MS / 2 })
    await putUnlockMethods({
      session,
      record: {
        version: 1,
        userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          {
            type: 'passphrase',
            createdAt: '2026-01-01T00:00:00.000Z',
            unlockSpaceId: 'ps-space',
            manageCapability: stored
          }
        ]
      },
      idb
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session, idb })
    const entry = result!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    expect(entry!.manageCapability).toEqual(stored)
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('a passkey session refreshes its own expiring management zcap', async () => {
    const idb = createFakeIdb()
    const fresh = capExpiringIn({ msFromNow: ONE_YEAR_MS })
    const session = await makeSession()
    session.profile.unlockMethod = {
      type: 'passkey',
      unlockSpaceId: 'unlock-space-abc',
      manageCapability: fresh
    }
    await putUnlockMethods({
      session,
      record: {
        version: 1,
        userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          passkeyEntry({
            manageCapability: capExpiringIn({ msFromNow: 1000 })
          })
        ]
      },
      idb
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session, idb })
    const entry = result!.methods.find(
      (method): method is PasskeyUnlockMethod => method.type === 'passkey'
    )
    expect(entry!.manageCapability).toEqual(fresh)
    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
  })

  it('a passkey session with a fresh stored zcap writes nothing', async () => {
    const idb = createFakeIdb()
    const session = await makeSession()
    session.profile.unlockMethod = {
      type: 'passkey',
      unlockSpaceId: 'unlock-space-abc',
      manageCapability: capExpiringIn({ msFromNow: ONE_YEAR_MS })
    }
    const stored = capExpiringIn({ msFromNow: ONE_YEAR_MS / 2 })
    await putUnlockMethods({
      session,
      record: {
        version: 1,
        userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [passkeyEntry({ manageCapability: stored })]
      },
      idb
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session, idb })
    const entry = result!.methods.find(
      (method): method is PasskeyUnlockMethod => method.type === 'passkey'
    )
    expect(entry!.manageCapability).toEqual(stored)
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('is idempotent: a second call writes nothing', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({ unlockSpaceId: 'ps-space' })
    await backfillPassphraseUnlockMethod({
      session,
      idb,
      createIfMissing: true
    })
    vi.clearAllMocks()

    const result = await backfillPassphraseUnlockMethod({ session, idb })
    expect(result).not.toBeNull()
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })
})

describe('adoptPassphraseRebind', () => {
  it('repoints the session so the backfill follows the passphrase change', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({
      unlockSpaceId: 'old-ps-space'
    })
    // The registry as it stood before the change: the passphrase entry names
    // the (now deleted) old unlock Space.
    await backfillPassphraseUnlockMethod({
      session,
      idb,
      createIfMissing: true
    })

    const persistClientKeys = vi.fn(async () => {})
    adoptPassphraseRebind({
      session,
      unlockSpaceId: 'new-ps-space',
      manageCapability: FAKE_CAP,
      persistClientKeys
    })
    // Later re-wraps run over the new client-key record, not the deleted one.
    expect(session.profile.persistClientKeys).toBe(persistClientKeys)

    const result = await backfillPassphraseUnlockMethod({ session, idb })
    const entry = result!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    expect(entry!.unlockSpaceId).toBe('new-ps-space')
    expect(entry!.manageCapability).toEqual(FAKE_CAP)

    // A second run leaves it there: the entry is never rewritten back to the
    // deleted unlock Space.
    const again = await backfillPassphraseUnlockMethod({ session, idb })
    const stillThere = again!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    expect(stillThere!.unlockSpaceId).toBe('new-ps-space')
  })
})

describe('rewrapUnlockMethodsRecord', () => {
  /**
   * A second, distinct vault key set (a different seed), standing in for the
   * post-rotation user key's vault keys.
   */
  async function makeVaultKeys(fillByte: number) {
    const seed = new Uint8Array(32)
    seed.fill(fillByte)
    const agent = await CapabilityAgent.fromSeed({
      seed,
      handle: `test-rewrap-${fillByte}`,
      keyName: 'test-rewrap-key'
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
    return {
      keyAgreementKey: keyAgreementKey as IKeyAgreementKey,
      keyResolver: keyResolver as IKeyResolver
    }
  }

  it('re-seals the stored record so only the new keys decrypt it', async () => {
    const idb = createFakeIdb()
    const session = await makeSession()
    await putUnlockMethods({ session, record: sampleRecord(), idb })

    const from = {
      keyAgreementKey: session.profile.keyAgreementKey! as IKeyAgreementKey,
      keyResolver: session.profile.keyResolver! as IKeyResolver
    }
    const to = await makeVaultKeys(9)
    await rewrapUnlockMethodsRecord({
      storageServerUrl: 'https://was.example.test',
      zcapClient: {} as never,
      spaceId: DATA_SPACE_ID,
      from,
      to
    })

    // A session holding the NEW vault keys reads the registry.
    const rotatedSession = await makeSession()
    rotatedSession.profile.keyAgreementKey = to.keyAgreementKey as never
    rotatedSession.profile.keyResolver = to.keyResolver as never
    const read = await getUnlockMethods({ session: rotatedSession, idb })
    expect(read).toEqual(sampleRecord())

    // The old keys no longer route the envelope.
    await expect(getUnlockMethods({ session, idb })).rejects.toThrow()
  })

  it('is a no-op when no registry exists', async () => {
    const from = await makeVaultKeys(3)
    const to = await makeVaultKeys(4)
    vi.mocked(putUnlockMethodsRecord).mockClear()
    await rewrapUnlockMethodsRecord({
      storageServerUrl: 'https://was.example.test',
      zcapClient: {} as never,
      spaceId: DATA_SPACE_ID,
      from,
      to
    })
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })
})
