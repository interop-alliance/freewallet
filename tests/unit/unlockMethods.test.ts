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
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest'
import { addSink, captureSink } from '@interop/logger'
import { CapabilityAgent } from '@interop/webkms-client'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IDelegatedZcap,
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
  versions: new Map<string, number>(),
  getError: undefined as unknown,
  // What the mocked Space delete reports: `not-found` is the server's masked
  // 404 (absent OR unauthorized).
  deleteOutcome: 'deleted' as 'deleted' | 'not-found',
  // A one-shot hook fired at the START of the next PUT -- the seam the CAS
  // tests use to land a concurrent write between a read and its PUT.
  beforePut: undefined as (() => void | Promise<void>) | undefined,
  // Whether the read-only retirement gate refuses (WC-187).
  preflightRefuses: false,
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
    async ({
      spaceId,
      record,
      ifMatch,
      ifNoneMatch
    }: {
      spaceId: string
      record: unknown
      ifMatch?: string
      ifNoneMatch?: boolean
    }) => {
      if (wasState.beforePut) {
        const hook = wasState.beforePut
        wasState.beforePut = undefined
        await hook()
      }
      const { PreconditionFailedError } = await import('@interop/was-client')
      const exists = wasState.records.has(spaceId)
      const version = wasState.versions.get(spaceId) ?? 0
      if (ifNoneMatch && exists) {
        throw new PreconditionFailedError(
          'A registry record already exists (If-None-Match).'
        )
      }
      if (ifMatch !== undefined && (!exists || ifMatch !== `v${version}`)) {
        throw new PreconditionFailedError(
          'The registry record changed since the read (If-Match).'
        )
      }
      if (ifMatch === undefined && !ifNoneMatch) {
        throw new Error(
          'Unconditional registry write: every PUT must carry a precondition.'
        )
      }
      wasState.records.set(spaceId, record)
      wasState.versions.set(spaceId, version + 1)
      return { etag: `v${version + 1}` }
    }
  ),
  getUnlockMethodsRecord: vi.fn(async ({ spaceId }: { spaceId: string }) => {
    if (wasState.getError) {
      throw wasState.getError
    }
    return wasState.records.has(spaceId)
      ? {
          record: wasState.records.get(spaceId),
          etag: `v${wasState.versions.get(spaceId) ?? 0}`
        }
      : null
  })
}))

vi.mock('@interop/wallet-core/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keyring')>()),
  deleteUnlockSpaceWithCapability: vi.fn(async () => {
    wasState.calls.push('deleteUnlockSpace')
    return { outcome: wasState.deleteOutcome }
  })
}))

vi.mock('@/session/credentialRotation', () => ({
  preflightCredentialRetirement: vi.fn(async () => {
    wasState.calls.push('preflightCredentialRetirement')
    if (wasState.preflightRefuses) {
      const err = new Error(
        "did:webvh: the credential's ladder VM could not be claimed."
      )
      err.name = 'UnclaimedLadderVmRetirementError'
      Object.assign(err, {
        unclaimedLadderVmIds: ['did:webvh:account#z6MkStandingLadderVm'],
        retryableWithLadderSeed: true
      })
      throw err
    }
  }),
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
  deleteUnlockMethodSpace,
  getUnlockMethods,
  getUnlockMethodsWithClient,
  managementZcapClient,
  refreshTransientManageCapability,
  refreshStandingDelegationFields,
  revokeUnlockMethod,
  revokeUnlockMethodByCeremony,
  rewrapUnlockMethodsRecord,
  updateUnlockMethods,
  updateUnlockMethodsWithClient,
  upsertPassphraseUnlockMethod,
  type PasskeyUnlockMethod,
  type PassphraseUnlockMethod,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import { PreconditionFailedError } from '@interop/was-client'
import { RecordEnvelopeDecryptError } from '@/session/recordEnvelope'
import { deleteUnlockSpaceWithCapability } from '@interop/wallet-core/keyring'
import { rotateOffUnlockCredential } from '@/session/credentialRotation'
import { browserLocalSessionPersistence } from '@/session/persistence'
import { zcapClientForSigner } from '@interop/wallet-core/identity'
import { rootCapabilityId } from '@interop/was-client/paths'
import { DELETION_ZCAP_TTL_MS } from '@interop/wallet-core/clientAnnex'
import { mintUserKey, type UserKey } from '@interop/wallet-core/keys'
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
 * data controller / Space id the registry addresses. The `zcapClient` is real
 * too: the unlock-Space deletion mints a DELETE-only child of the entry's
 * management zcap, which is an actual delegation signature.
 *
 * @returns {Promise<Session>}
 */
async function makeSession(idb?: IDBFactory): Promise<Session> {
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
    profile: {
      keyAgent: agent,
      keyAgreementKey,
      keyResolver,
      zcapClient: zcapClientForSigner({ signer: agent.getSigner() }),
      persistence: browserLocalSessionPersistence({ idb })
    },
    storage: { spaceId: DATA_SPACE_ID },
    isGuest: false
  } as unknown as Session
}

function sampleRecord(): UnlockMethodsRecord {
  return {
    version: 1,
    webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
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
const UNLOCK_SPACE_URL = 'https://was.example.test/space/unlock-space-abc'

/**
 * A REAL management zcap on the unlock Space: GET/PUT/DELETE, a year out,
 * delegated from the Space's root. It has to be real rather than a
 * stand-in object now that the deletion path delegates a DELETE-only child
 * from it -- the delegation library computes the child's capability chain
 * from the parent's own proof.
 */
let FAKE_CAP: IZcap

/**
 * The did:key this suite's session signs management invocations as.
 */
let SESSION_CLIENT_DID: string

/**
 * A stand-in management zcap expiring the given interval from now, for the
 * backfill's expiry-refresh cases. The action set is optional: only the
 * action-coverage cases care about it.
 *
 * @param options {object}
 * @param options.msFromNow {number}
 * @param [options.allowedAction] {string[]}
 * @returns {IZcap}
 */
function capExpiringIn({
  msFromNow,
  allowedAction
}: {
  msFromNow: number
  allowedAction?: string[]
}): IZcap {
  return {
    id: `urn:zcap:test-management-${msFromNow}-${(allowedAction ?? []).join('')}`,
    invocationTarget: 'https://was.example.test/space/unlock-space-abc',
    expires: new Date(Date.now() + msFromNow).toISOString(),
    ...(allowedAction ? { allowedAction } : {})
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
  manageCapability,
  idb
}: {
  unlockSpaceId: string
  manageCapability?: IZcap
  idb?: IDBFactory
}): Promise<Session> {
  const session = await makeSession(idb)
  session.profile.unlockMethod = {
    type: 'passphrase',
    unlockSpaceId,
    manageCapability
  }
  return session
}

/**
 * Seeds the stored registry through the compare-and-swap wrapper (the bare
 * unconditional put no longer exists).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.record {UnlockMethodsRecord}
 * @returns {Promise<void>}
 */
async function seedRegistry({
  session,
  record
}: {
  session: Session
  record: UnlockMethodsRecord
}): Promise<void> {
  await updateUnlockMethods({ session, mutate: () => record })
}

beforeAll(async () => {
  const { profile } = await makeSession()
  // Delegated to the identity this session's signer acts as, which is what
  // the deletion path's read-only pre-flight checks.
  SESSION_CLIENT_DID = profile.keyAgent!.id
  FAKE_CAP = (await profile.zcapClient.delegate({
    capability: rootCapabilityId(UNLOCK_SPACE_URL),
    invocationTarget: UNLOCK_SPACE_URL,
    controller: SESSION_CLIENT_DID,
    allowedActions: ['GET', 'PUT', 'DELETE'],
    expires: new Date(Date.now() + 365 * 24 * 3600 * 1000)
  })) as IZcap
})

beforeEach(() => {
  wasState.url = 'https://was.example.test'
  wasState.records.clear()
  wasState.versions.clear()
  wasState.getError = undefined
  wasState.deleteOutcome = 'deleted'
  wasState.beforePut = undefined
  wasState.preflightRefuses = false
  wasState.calls = []
  vi.clearAllMocks()
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('put / get round-trip', () => {
  it('survives wrap/unwrap and stores an encrypted (versioned) envelope remotely', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const record = sampleRecord()

    await seedRegistry({ session, record })
    expect(ensureUnlockMethodsCollection).toHaveBeenCalledOnce()

    // The remote body is the JWE-wrapped envelope, not the plaintext record.
    const stored = wasState.records.get(DATA_SPACE_ID) as {
      version: number
      wrapped: { jwe?: unknown }
    }
    expect(stored.version).toBe(1)
    expect(stored.wrapped.jwe).toBeDefined()
    expect(JSON.stringify(stored)).not.toContain('unlock-space-abc')

    vi.mocked(getUnlockMethodsRecord).mockClear()
    const found = await getUnlockMethods({ session })
    expect(found).toEqual(record)
    expect(getUnlockMethodsRecord).toHaveBeenCalledOnce()
  })

  it('returns null when no registry exists anywhere', async () => {
    const session = await makeSession(createFakeIdb())
    const found = await getUnlockMethods({ session })
    expect(found).toBeNull()
  })

  it('rejects a stored record whose outer version is not 1', async () => {
    const session = await makeSession()
    wasState.records.set(DATA_SPACE_ID, { version: 2, wrapped: {} })

    await expect(getUnlockMethods({ session })).rejects.toThrow(/version/)
  })
})

describe('no-WAS cache-only path', () => {
  it('writes and reads the registry from the cache with no remote call', async () => {
    wasState.url = undefined
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const record = sampleRecord()

    await seedRegistry({ session, record })
    expect(ensureUnlockMethodsCollection).not.toHaveBeenCalled()
    expect(wasState.records.size).toBe(0)

    const found = await getUnlockMethods({ session })
    expect(found).toEqual(record)
    expect(getUnlockMethodsRecord).not.toHaveBeenCalled()
  })
})

describe('remote-first read', () => {
  it('reads remote on a cache miss and refreshes the local cache', async () => {
    const session = await makeSession(createFakeIdb())
    const record = sampleRecord()
    // Populate the remote (and a throwaway profile's cache) via one idb, then
    // read on a fresh idb whose cache starts empty.
    await seedRegistry({ session, record })
    vi.clearAllMocks()

    const freshIdb = createFakeIdb()
    const freshSession = await makeSession(freshIdb)
    expect(
      await loadUnlockMethodsCache({
        controller: DATA_CONTROLLER,
        idb: freshIdb
      })
    ).toBeNull()

    const found = await getUnlockMethods({ session: freshSession })
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
    const session = await makeSession(idb)
    await seedRegistry({ session, record: sampleRecord() })
    // The registry was deleted remotely while this profile's cache still holds
    // a copy.
    wasState.records.clear()

    const found = await getUnlockMethods({ session })
    expect(found).toBeNull()
    expect(
      await loadUnlockMethodsCache({ controller: DATA_CONTROLLER, idb })
    ).toBeNull()
  })

  it('rethrows a remote read failure', async () => {
    const session = await makeSession()
    const networkError = new Error('NetworkError when attempting to fetch')
    wasState.getError = networkError

    await expect(getUnlockMethods({ session })).rejects.toBe(networkError)
  })
})

describe('revokeUnlockMethod', () => {
  it('deletes the unlock Space, drops the keyring cache, and removes the registry entry', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({ manageCapability: FAKE_CAP })
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      }
    })
    // Seed a keyring cache for the unlock Space so its removal is observable.
    await saveKeyringCache({
      spaceId: entry.unlockSpaceId,
      record: { version: 1, wrapped: {} },
      idb
    })
    vi.clearAllMocks()

    await revokeUnlockMethod({ session, entry, idb })

    // The Space delete was invoked with a DELETE-only CHILD of the entry's
    // capability, never the stored three-verb capability itself.
    expect(deleteUnlockSpaceWithCapability).toHaveBeenCalledOnce()
    const args = vi.mocked(deleteUnlockSpaceWithCapability).mock.calls[0][0]
    expect(args.spaceId).toBe(entry.unlockSpaceId)
    const child = args.capability as IDelegatedZcap
    expect(child).not.toBe(FAKE_CAP)
    expect(child.allowedAction).toEqual(['DELETE'])
    expect(child.parentCapability).toBe((FAKE_CAP as IDelegatedZcap).id)

    // The keyring cache for the unlock Space is gone.
    await expect(
      loadKeyringCache({ spaceId: entry.unlockSpaceId, idb })
    ).resolves.toBeNull()

    // The registry no longer lists the entry.
    const after = await getUnlockMethods({ session })
    expect(after!.methods).toHaveLength(0)
  })

  it('throws when a WAS server is configured and the entry has no capability', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry()

    await expect(revokeUnlockMethod({ session, entry, idb })).rejects.toThrow()
    expect(deleteUnlockSpaceWithCapability).not.toHaveBeenCalled()
    // The refusal is read-only and comes BEFORE the retirement: the advice to
    // tap the passkey is only possible while the credential still stands, and
    // a retry must still find a removable entry.
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
  })

  it('refuses an expired capability before retiring the credential', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({
      manageCapability: {
        ...(FAKE_CAP as unknown as Record<string, unknown>),
        expires: new Date(Date.now() - 60_000).toISOString()
      } as unknown as IZcap
    })

    await expect(revokeUnlockMethod({ session, entry, idb })).rejects.toThrow(
      /expired-capability/
    )
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(deleteUnlockSpaceWithCapability).not.toHaveBeenCalled()
  })

  it('skips the Space delete but still cleans up with no WAS server', async () => {
    wasState.url = undefined
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry()
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      }
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
    const after = await getUnlockMethods({ session })
    expect(after!.methods).toHaveLength(0)
  })
})

describe('deleteUnlockMethodSpace', () => {
  it('deletes the unlock Space and the local trio, leaving the registry alone', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({ manageCapability: FAKE_CAP })
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      }
    })
    await saveKeyringCache({
      spaceId: entry.unlockSpaceId,
      record: { version: 1, wrapped: {} },
      idb
    })
    vi.clearAllMocks()

    await deleteUnlockMethodSpace({ session, entry })

    expect(deleteUnlockSpaceWithCapability).toHaveBeenCalledOnce()
    const args = vi.mocked(deleteUnlockSpaceWithCapability).mock.calls[0][0]
    expect(args.spaceId).toBe(entry.unlockSpaceId)
    const child = args.capability as IDelegatedZcap
    // The DELETE-only child: the parent's target unchanged, one action, and
    // a ten-minute lifetime under the parent's own expiry.
    expect(child.allowedAction).toEqual(['DELETE'])
    expect(child.invocationTarget).toBe(UNLOCK_SPACE_URL)
    expect(child.controller).toBe(SESSION_CLIENT_DID)
    expect(Date.parse(child.expires) - Date.now()).toBeLessThanOrEqual(
      DELETION_ZCAP_TTL_MS + 1000
    )
    // The REMOTE half only: the keyring cache is the caller's local-wipe
    // stage to remove, past the pivot.
    await expect(
      loadKeyringCache({ spaceId: entry.unlockSpaceId, idb })
    ).resolves.not.toBeNull()
    // No rotation, and no registry rewrite: both die with the account Space
    // the caller is about to wipe.
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    const after = await getUnlockMethods({ session })
    expect(after!.methods).toHaveLength(1)
  })

  it('reports the residue for an entry with no management zcap', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry()
    await saveKeyringCache({
      spaceId: entry.unlockSpaceId,
      record: { version: 1, wrapped: {} },
      idb
    })

    const outcome = await deleteUnlockMethodSpace({ session, entry })

    // Stated residue, named rather than silently skipped.
    expect(outcome).toEqual({
      unlockSpaceId: entry.unlockSpaceId,
      space: 'no-capability'
    })
    expect(deleteUnlockSpaceWithCapability).not.toHaveBeenCalled()
  })

  it('reports the residue for an entry whose management zcap has expired', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({
      manageCapability: {
        ...(FAKE_CAP as unknown as Record<string, unknown>),
        expires: new Date(Date.now() - 60_000).toISOString()
      } as unknown as IZcap
    })

    const outcome = await deleteUnlockMethodSpace({ session, entry })

    // A child of an expired parent would verify nowhere, so nothing is minted
    // and nothing is sent -- and the walk still continues.
    expect(outcome.space).toBe('expired-capability')
    expect(deleteUnlockSpaceWithCapability).not.toHaveBeenCalled()
  })

  it('refuses a capability naming a delegatee this session cannot act as', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({
      manageCapability: {
        ...(FAKE_CAP as unknown as Record<string, unknown>),
        controller: 'did:key:z6MkSomeOtherEnrolledClient'
      } as unknown as IZcap
    })

    const outcome = await deleteUnlockMethodSpace({ session, entry })

    // A child signed by a delegator the parent does not name comes back as a
    // masked 404, which the walk would read as "already gone" and drop the
    // entry around a Space that still stands. Refused locally instead.
    expect(outcome.space).toBe('foreign-controller')
    expect(deleteUnlockSpaceWithCapability).not.toHaveBeenCalled()
  })

  it("refuses a capability naming another deployment's Space URL", async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({
      manageCapability: {
        ...(FAKE_CAP as unknown as Record<string, unknown>),
        invocationTarget: 'https://was.example.test/was/space/unlock-space-abc'
      } as unknown as IZcap
    })

    const outcome = await deleteUnlockMethodSpace({ session, entry })

    expect(outcome.space).toBe('stale-target')
    expect(deleteUnlockSpaceWithCapability).not.toHaveBeenCalled()
  })

  it("reports the server's masked 404 as not-found", async () => {
    wasState.deleteOutcome = 'not-found'
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({ manageCapability: FAKE_CAP })

    const outcome = await deleteUnlockMethodSpace({ session, entry })

    // Absent OR unauthorized -- the server masks the two, so the walk records
    // what it was told rather than concluding the Space is gone.
    expect(outcome.space).toBe('not-found')
  })

  it('signs the child with a caller-supplied delegator and delegatee', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({ manageCapability: FAKE_CAP })
    const seed = new Uint8Array(32)
    seed.fill(9)
    const ladderAgent = await CapabilityAgent.fromSeed({
      seed,
      handle: 'ladder-vm',
      keyName: 'ladder-vm-key'
    })

    await deleteUnlockMethodSpace({
      session,
      entry,
      signer: {
        zcapClient: zcapClientForSigner({ signer: ladderAgent.getSigner() }),
        controller: ladderAgent.id
      }
    })

    const args = vi.mocked(deleteUnlockSpaceWithCapability).mock.calls[0][0]
    const child = args.capability as IDelegatedZcap
    expect(child.controller).toBe(ladderAgent.id)
    expect(child.allowedAction).toEqual(['DELETE'])
  })

  it('mints as the delegator and sends as the invoker', async () => {
    // Two different keys, and mixing them is a masked 404: the child's parent
    // must be signed by the parent's own controller (the ladder VM under its
    // account verification method), while the DELETE must be SENT by the
    // child's own controller -- the ladder VM's bare did:key, which the
    // account document lists under no `capabilityInvocation` relation.
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({ manageCapability: FAKE_CAP })
    const seed = new Uint8Array(32)
    seed.fill(9)
    const ladderAgent = await CapabilityAgent.fromSeed({
      seed,
      handle: 'ladder-vm',
      keyName: 'ladder-vm-key'
    })
    const delegator = zcapClientForSigner({
      signer: ladderAgent.getSigner()
    })
    const invoker = zcapClientForSigner({ signer: ladderAgent.getSigner() })

    await deleteUnlockMethodSpace({
      session,
      entry,
      signer: { zcapClient: delegator, invoker, controller: ladderAgent.id }
    })

    const args = vi.mocked(deleteUnlockSpaceWithCapability).mock.calls[0][0]
    expect(args.zcapClient).toBe(invoker)
    expect(args.zcapClient).not.toBe(delegator)
    // The child is still the delegator's signature, delegated to the invoker.
    const child = args.capability as IDelegatedZcap
    expect(child.controller).toBe(ladderAgent.id)
  })

  it('reports a management zcap that allows no DELETE as a residue', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({
      manageCapability: {
        ...(FAKE_CAP as unknown as Record<string, unknown>),
        allowedAction: ['GET', 'PUT']
      } as unknown as IZcap
    })

    const outcome = await deleteUnlockMethodSpace({ session, entry })

    // A child of it would verify nowhere, so nothing is minted and nothing is
    // sent; the walk names the Space and carries on.
    expect(outcome.space).toBe('unsupported-capability')
    expect(deleteUnlockSpaceWithCapability).not.toHaveBeenCalled()
  })

  it('skips the server delete with no WAS server configured', async () => {
    wasState.url = undefined
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({ manageCapability: FAKE_CAP })
    await saveKeyringCache({
      spaceId: entry.unlockSpaceId,
      record: { version: 1, wrapped: {} },
      idb
    })

    await deleteUnlockMethodSpace({ session, entry })

    expect(deleteUnlockSpaceWithCapability).not.toHaveBeenCalled()
  })

  it('leaves the entry local state for the caller local wipe', async () => {
    // The DELETEs run before the pivot, so a run refused at the account Space
    // must leave this browser exactly as it found it rather than having
    // quietly un-remembered every other credential on it.
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = passkeyEntry({ manageCapability: FAKE_CAP })
    await saveKeyringCache({
      spaceId: entry.unlockSpaceId,
      record: { version: 1, wrapped: {} },
      idb
    })

    await deleteUnlockMethodSpace({ session, entry })

    await expect(
      loadKeyringCache({ spaceId: entry.unlockSpaceId, idb })
    ).resolves.not.toBeNull()
  })
})

describe('refreshTransientManageCapability', () => {
  /**
   * Seeds the registry the way a session-less writer does, sealed to the
   * given user key.
   *
   * @param options {object}
   * @param options.userKey {UserKey}
   * @param options.record {UnlockMethodsRecord}
   * @returns {Promise<void>}
   */
  async function seedViaClient({
    userKey,
    record
  }: {
    userKey: UserKey
    record: UnlockMethodsRecord
  }): Promise<void> {
    await updateUnlockMethodsWithClient({
      zcapClient: {} as never,
      spaceId: DATA_SPACE_ID,
      userKey,
      mutate: () => record
    })
  }

  /**
   * Runs the refresh with this suite's fixed identifiers.
   *
   * @param options {object}
   * @param options.userKey {UserKey}
   * @param [options.keyAgreementKeyMultibase] {string}
   * @returns {Promise<void>}
   */
  async function refresh({
    userKey,
    keyAgreementKeyMultibase
  }: {
    userKey: UserKey
    keyAgreementKeyMultibase?: string
  }): Promise<void> {
    await refreshTransientManageCapability({
      zcapClient: {} as never,
      spaceId: DATA_SPACE_ID,
      userKey,
      capability: FAKE_CAP,
      unlockSpaceId: 'unlock-space-abc',
      manageCapability: FAKE_CAP,
      ...(keyAgreementKeyMultibase ? { keyAgreementKeyMultibase } : {})
    })
  }

  /**
   * A one-entry registry whose passphrase entry names this suite's unlock
   * Space.
   *
   * @param [entry] {Partial<PassphraseUnlockMethod>}
   * @returns {UnlockMethodsRecord}
   */
  function registryWith(
    entry: Partial<PassphraseUnlockMethod> = {}
  ): UnlockMethodsRecord {
    return {
      version: 1,
      webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
      methods: [
        {
          type: 'passphrase',
          createdAt: '2026-08-19T00:00:00.000Z',
          unlockSpaceId: 'unlock-space-abc',
          ...entry
        } as PassphraseUnlockMethod
      ]
    }
  }

  it('writes the fresh capability to an entry carrying none', async () => {
    const userKey = await mintUserKey()
    await seedViaClient({ userKey, record: registryWith() })
    vi.clearAllMocks()

    await refresh({ userKey })

    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
    const after = await getUnlockMethodsWithClient({
      zcapClient: {} as never,
      spaceId: DATA_SPACE_ID,
      userKey
    })
    expect(after!.methods[0].manageCapability).toEqual(FAKE_CAP)
  })

  it('writes when the stored capability is expiring or narrower', async () => {
    const userKey = await mintUserKey()
    await seedViaClient({
      userKey,
      record: registryWith({
        manageCapability: capExpiringIn({ msFromNow: 24 * 3600 * 1000 })
      })
    })
    vi.clearAllMocks()

    await refresh({ userKey })

    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()

    // And the widening case: a stored GET/DELETE capability, still fresh, is
    // replaced by the GET/PUT/DELETE mint.
    await seedViaClient({
      userKey,
      record: registryWith({
        manageCapability: capExpiringIn({
          msFromNow: ONE_YEAR_MS,
          allowedAction: ['GET', 'DELETE']
        })
      })
    })
    vi.clearAllMocks()

    await refresh({ userKey })

    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
  })

  it("writes when the stored capability names another deployment's target", async () => {
    const userKey = await mintUserKey()
    await seedViaClient({
      userKey,
      record: registryWith({
        manageCapability: {
          ...(capExpiringIn({
            msFromNow: ONE_YEAR_MS,
            allowedAction: ['GET', 'PUT', 'DELETE']
          }) as unknown as Record<string, unknown>),
          // A root-anchored target minted before the mint moved onto
          // was-client's path helpers: unusable on a sub-path deployment, and
          // neither expiring nor narrower, so only the target comparison
          // catches it.
          invocationTarget: 'https://was.example.test/space/other-space'
        } as unknown as IZcap
      })
    })
    vi.clearAllMocks()

    await refresh({ userKey })

    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
    const after = await getUnlockMethodsWithClient({
      zcapClient: {} as never,
      spaceId: DATA_SPACE_ID,
      userKey
    })
    expect(after!.methods[0].manageCapability).toEqual(FAKE_CAP)
  })

  it('writes nothing when the stored capability is neither expiring nor narrower', async () => {
    const userKey = await mintUserKey()
    await seedViaClient({
      userKey,
      record: registryWith({
        manageCapability: capExpiringIn({
          msFromNow: ONE_YEAR_MS,
          allowedAction: ['GET', 'PUT', 'DELETE']
        })
      })
    })
    vi.clearAllMocks()

    await refresh({ userKey })

    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('creates nothing when no registry exists', async () => {
    const userKey = await mintUserKey()
    vi.clearAllMocks()

    await refresh({ userKey })

    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
    expect(ensureUnlockMethodsCollection).not.toHaveBeenCalled()
  })

  it("skips an entry recording another credential's key-agreement key", async () => {
    const userKey = await mintUserKey()
    await seedViaClient({
      userKey,
      record: registryWith({ keyAgreementKeyMultibase: 'zOtherCredentialKak' })
    })
    vi.clearAllMocks()

    // The pending-retirement shape: the entry names the NEW unlock Space
    // while recording the OLD credential's members, so it is not this
    // credential's to write.
    await refresh({ userKey, keyAgreementKeyMultibase: 'zThisCredentialKak' })

    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('warns and skips when the registry read throws', async () => {
    const userKey = await mintUserKey()
    wasState.getError = new Error('the registry record will not decrypt')
    const capture = captureSink()
    addSink(capture.sink)

    await refresh({ userKey })

    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        ns: 'fw:session:methods',
        level: 'warn',
        msg: expect.stringContaining('Could not refresh the management zcap')
      })
    )
  })
})

describe('the standing delegation scalar pairs (FW-194)', () => {
  it('carries the delegatedClients pair forward through a backfill upsert', async () => {
    const base: UnlockMethodsRecord = {
      version: 1,
      webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
      methods: [
        {
          type: 'passphrase',
          createdAt: '2026-08-19T00:00:00.000Z',
          unlockSpaceId: 'unlock-space-1',
          delegationKeyId: 'did:key:zBridge#zBridge',
          delegationExpires: '2027-08-19T00:00:00.000Z',
          delegatedClientsKeyId: 'did:key:zSibling#zSibling',
          delegatedClientsExpires: '2027-08-19T00:00:00.000Z'
        } as PassphraseUnlockMethod
      ]
    }
    // A backfill (no fresh standing fields) must not erase the sibling pair.
    const updated = upsertPassphraseUnlockMethod({
      record: base,
      unlockSpaceId: 'unlock-space-1'
    })
    const entry = updated.methods[0] as PassphraseUnlockMethod
    expect(entry.delegatedClientsKeyId).toBe('did:key:zSibling#zSibling')
    expect(entry.delegatedClientsExpires).toBe('2027-08-19T00:00:00.000Z')
  })

  it('refreshStandingDelegationFields records both fresh pairs', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          {
            type: 'passphrase',
            createdAt: '2026-08-19T00:00:00.000Z',
            unlockSpaceId: 'unlock-space-1',
            delegationKeyId: 'did:key:zOld#zOld',
            delegatedClientsKeyId: 'did:key:zOldSibling#zOldSibling'
          } as PassphraseUnlockMethod
        ]
      }
    })
    await refreshStandingDelegationFields({
      session,
      unlockSpaceId: 'unlock-space-1',
      delegationKeyId: 'did:key:zFresh#zFresh',
      delegationExpires: '2027-08-19T00:00:00.000Z',
      delegatedClientsKeyId: 'did:key:zFreshSibling#zFreshSibling',
      delegatedClientsExpires: '2027-08-19T01:00:00.000Z'
    })
    const record = await getUnlockMethods({ session })
    const entry = record!.methods[0] as PassphraseUnlockMethod
    expect(entry.delegationKeyId).toBe('did:key:zFresh#zFresh')
    expect(entry.delegatedClientsKeyId).toBe(
      'did:key:zFreshSibling#zFreshSibling'
    )
    expect(entry.delegatedClientsExpires).toBe('2027-08-19T01:00:00.000Z')
  })

  it('writes nothing when the entry records another credential', async () => {
    // The pending-retirement state: the entry points at the login's unlock
    // Space but records the credential whose retirement did not finish.
    // Stamping a fresh rung there would make the completer strike the
    // CURRENT passphrase's ladder.
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          {
            type: 'passphrase',
            createdAt: '2026-08-19T00:00:00.000Z',
            unlockSpaceId: 'unlock-space-1',
            keyAgreementKeyMultibase: 'z6LSPendingCredentialKak',
            updateKeyMultibase: 'z6MkPendingRung'
          } as PassphraseUnlockMethod
        ]
      }
    })
    await refreshStandingDelegationFields({
      session,
      unlockSpaceId: 'unlock-space-1',
      keyAgreementKeyMultibase: 'z6LSLoginCredentialKak',
      updateKeyMultibase: 'z6MkLoginRung',
      delegationKeyId: 'did:key:zFresh#zFresh'
    })
    const record = await getUnlockMethods({ session })
    const entry = record!.methods[0] as PassphraseUnlockMethod
    expect(entry.updateKeyMultibase).toBe('z6MkPendingRung')
    expect(entry.delegationKeyId).toBeUndefined()
  })

  it('writes when the entry records the acting credential', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          {
            type: 'passphrase',
            createdAt: '2026-08-19T00:00:00.000Z',
            unlockSpaceId: 'unlock-space-1',
            keyAgreementKeyMultibase: 'z6LSLoginCredentialKak',
            updateKeyMultibase: 'z6MkStaleRung'
          } as PassphraseUnlockMethod
        ]
      }
    })
    await refreshStandingDelegationFields({
      session,
      unlockSpaceId: 'unlock-space-1',
      keyAgreementKeyMultibase: 'z6LSLoginCredentialKak',
      updateKeyMultibase: 'z6MkFreshRung'
    })
    const record = await getUnlockMethods({ session })
    const entry = record!.methods[0] as PassphraseUnlockMethod
    expect(entry.updateKeyMultibase).toBe('z6MkFreshRung')
  })
})

describe('the credential rotation inside a revocation', () => {
  /**
   * A passkey entry carrying a standing configuration, so the rotation ceremony has
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
    const session = await makeSession(idb)
    const entry = standingEntry()
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      }
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
    const session = await makeSession(idb)
    const entry = {
      type: 'recovery-code',
      label: 'Recovery code',
      createdAt: '2026-08-01T00:00:00.000Z',
      // The suite's one management zcap targets this Space, and the deletion
      // pre-flight now checks that the recorded target is the one this
      // deployment addresses.
      unlockSpaceId: 'unlock-space-abc',
      manageCapability: FAKE_CAP,
      recoveryKid: 'did:key:z6LSCode#kak',
      keyAgreementKeyMultibase: 'z6LSCodeKak',
      updateKeyMultibase: 'z6MkCodeUpdate'
    } as const
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      }
    })

    const outcome = await revokeUnlockMethod({ session, entry, idb })
    expect(outcome).toBeNull()
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
  })

  it('taps the passkey before rotating, on the ceremony path', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry = standingEntry()
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      }
    })
    wasState.calls = []

    const outcome = await revokeUnlockMethodByCeremony({ session, entry, idb })

    expect(wasState.calls).toEqual([
      'assertPasskeyPrf',
      'preflightCredentialRetirement',
      'rotateOffUnlockCredential',
      'deleteUnlockMethod'
    ])
    expect(outcome?.rotated).toBe(true)
    const after = await getUnlockMethods({ session })
    expect(after!.methods).toHaveLength(0)
  })
})

describe('the retirement gate on the tap-confirmed removal (WC-187)', () => {
  it('refuses before any write, leaving the passkey standing', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    const entry: PasskeyUnlockMethod = {
      ...passkeyEntry({ manageCapability: FAKE_CAP }),
      keyAgreementKeyMultibase: 'z6LSStandingPasskeyKak',
      updateKeyMultibase: 'z6MkStandingPasskeyRung'
    }
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [entry]
      }
    })
    wasState.calls = []
    wasState.preflightRefuses = true

    const thrown = await revokeUnlockMethodByCeremony({
      session,
      entry,
      idb
    }).catch((err: unknown) => err)

    expect(thrown).toMatchObject({
      name: 'UnclaimedLadderVmRetirementError',
      unclaimedLadderVmIds: ['did:webvh:account#z6MkStandingLadderVm'],
      retryableWithLadderSeed: true
    })
    // The tap happened; nothing after it did. The entry is still there, so
    // the removal is still available once the refusal is answered.
    expect(wasState.calls).toEqual([
      'assertPasskeyPrf',
      'preflightCredentialRetirement'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    const after = await getUnlockMethods({ session })
    expect(after!.methods).toHaveLength(1)
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
    const session = await makeSession(idb) // no profile.unlockMethod

    const result = await backfillPassphraseUnlockMethod({ session })
    expect(result).toBeNull()
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('still returns an existing registry for a non-passphrase session', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb) // e.g. a passkey login
    await seedRegistry({ session, record: sampleRecord() })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    // The Settings section loads through this function for every session; a
    // passkey-login session must see the account's registry (not `null`, which
    // would read as "no registry" and invite an overwriting re-creation).
    const result = await backfillPassphraseUnlockMethod({
      session,
      createIfMissing: true
    })
    expect(result).toEqual(sampleRecord())
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('does not create a registry without createIfMissing', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      idb
    })

    const result = await backfillPassphraseUnlockMethod({ session })
    expect(result).toBeNull()
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('creates the registry with a passphrase entry when createIfMissing', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      manageCapability: FAKE_CAP,
      idb
    })

    const result = await backfillPassphraseUnlockMethod({
      session,
      createIfMissing: true
    })

    expect(result).not.toBeNull()
    expect(result!.webAuthnUserId).toBeTruthy()
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
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      idb
    })
    // An existing registry (one passkey entry, no passphrase).
    await seedRegistry({ session, record: sampleRecord() })

    const result = await backfillPassphraseUnlockMethod({ session })
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
      unlockSpaceId: 'new-ps-space',
      idb
    })
    const existing: PassphraseUnlockMethod = {
      type: 'passphrase',
      createdAt: '2026-01-01T00:00:00.000Z',
      unlockSpaceId: 'old-ps-space'
    }
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [existing]
      }
    })

    const result = await backfillPassphraseUnlockMethod({ session })
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
      manageCapability: fresh,
      idb
    })
    const existing: PassphraseUnlockMethod = {
      type: 'passphrase',
      createdAt: '2026-01-01T00:00:00.000Z',
      unlockSpaceId: 'ps-space',
      manageCapability: capExpiringIn({ msFromNow: 1000 })
    }
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [existing]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
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
      manageCapability: capExpiringIn({ msFromNow: ONE_YEAR_MS }),
      idb
    })
    const stored = capExpiringIn({ msFromNow: ONE_YEAR_MS / 2 })
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          {
            type: 'passphrase',
            createdAt: '2026-01-01T00:00:00.000Z',
            unlockSpaceId: 'ps-space',
            manageCapability: stored
          }
        ]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    expect(entry!.manageCapability).toEqual(stored)
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('a passkey session refreshes its own expiring management zcap', async () => {
    const idb = createFakeIdb()
    const fresh = capExpiringIn({ msFromNow: ONE_YEAR_MS })
    const session = await makeSession(idb)
    session.profile.unlockMethod = {
      type: 'passkey',
      unlockSpaceId: 'unlock-space-abc',
      manageCapability: fresh
    }
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          passkeyEntry({
            manageCapability: capExpiringIn({ msFromNow: 1000 })
          })
        ]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PasskeyUnlockMethod => method.type === 'passkey'
    )
    expect(entry!.manageCapability).toEqual(fresh)
    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
  })

  it('a passkey session with a fresh stored zcap writes nothing', async () => {
    const idb = createFakeIdb()
    const session = await makeSession(idb)
    session.profile.unlockMethod = {
      type: 'passkey',
      unlockSpaceId: 'unlock-space-abc',
      manageCapability: capExpiringIn({ msFromNow: ONE_YEAR_MS })
    }
    const stored = capExpiringIn({ msFromNow: ONE_YEAR_MS / 2 })
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [passkeyEntry({ manageCapability: stored })]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PasskeyUnlockMethod => method.type === 'passkey'
    )
    expect(entry!.manageCapability).toEqual(stored)
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('refreshes an expiring passphrase entry with the standing PUT action set', async () => {
    const idb = createFakeIdb()
    const fresh = capExpiringIn({
      msFromNow: ONE_YEAR_MS,
      allowedAction: ['GET', 'PUT', 'DELETE']
    })
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      manageCapability: fresh,
      idb
    })
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          {
            type: 'passphrase',
            createdAt: '2026-01-01T00:00:00.000Z',
            unlockSpaceId: 'ps-space',
            manageCapability: capExpiringIn({
              msFromNow: 1000,
              allowedAction: ['GET', 'PUT', 'DELETE']
            })
          }
        ]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    expect(entry!.manageCapability).toEqual(fresh)
    expect(
      (entry!.manageCapability as unknown as { allowedAction: string[] })
        .allowedAction
    ).toContain('PUT')
    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
  })

  it('leaves a non-expiring wide passphrase capability alone against a narrow mint', async () => {
    const idb = createFakeIdb()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      manageCapability: capExpiringIn({
        msFromNow: ONE_YEAR_MS,
        allowedAction: ['GET', 'DELETE']
      }),
      idb
    })
    const stored = capExpiringIn({
      msFromNow: ONE_YEAR_MS / 2,
      allowedAction: ['GET', 'PUT', 'DELETE']
    })
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          {
            type: 'passphrase',
            createdAt: '2026-01-01T00:00:00.000Z',
            unlockSpaceId: 'ps-space',
            manageCapability: stored
          }
        ]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    expect(entry!.manageCapability).toEqual(stored)
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
    expect(warn).not.toHaveBeenCalled()
    warn.mockRestore()
  })

  it('leaves a non-expiring wide passkey capability alone against a narrow mint', async () => {
    const idb = createFakeIdb()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const session = await makeSession(idb)
    session.profile.unlockMethod = {
      type: 'passkey',
      unlockSpaceId: 'unlock-space-abc',
      manageCapability: capExpiringIn({
        msFromNow: ONE_YEAR_MS,
        allowedAction: ['GET', 'DELETE']
      })
    }
    const stored = capExpiringIn({
      msFromNow: ONE_YEAR_MS / 2,
      allowedAction: ['GET', 'PUT', 'DELETE']
    })
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [passkeyEntry({ manageCapability: stored })]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PasskeyUnlockMethod => method.type === 'passkey'
    )
    expect(entry!.manageCapability).toEqual(stored)
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
    expect(warn).not.toHaveBeenCalled()
    warn.mockRestore()
  })

  it('refreshes an expiring wide passphrase capability even with a narrow mint, loudly', async () => {
    const idb = createFakeIdb()
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const fresh = capExpiringIn({
      msFromNow: ONE_YEAR_MS,
      allowedAction: ['GET', 'DELETE']
    })
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      manageCapability: fresh,
      idb
    })
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          {
            type: 'passphrase',
            createdAt: '2026-01-01T00:00:00.000Z',
            unlockSpaceId: 'ps-space',
            manageCapability: capExpiringIn({
              msFromNow: 1000,
              allowedAction: ['GET', 'PUT', 'DELETE']
            })
          }
        ]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    // A dead capability would lose DELETE beside PUT; the narrowing is
    // logged rather than refused.
    expect(entry!.manageCapability).toEqual(fresh)
    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
    expect(error).toHaveBeenCalled()
    error.mockRestore()
  })

  it('never narrows an unrestricted stored capability before expiry', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      manageCapability: capExpiringIn({
        msFromNow: ONE_YEAR_MS,
        allowedAction: ['GET', 'PUT', 'DELETE']
      }),
      idb
    })
    const stored = capExpiringIn({ msFromNow: ONE_YEAR_MS / 2 })
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          {
            type: 'passphrase',
            createdAt: '2026-01-01T00:00:00.000Z',
            unlockSpaceId: 'ps-space',
            manageCapability: stored
          }
        ]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    expect(entry!.manageCapability).toEqual(stored)
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('refreshes an expiring passkey entry with the standing PUT action set', async () => {
    const idb = createFakeIdb()
    const fresh = capExpiringIn({
      msFromNow: ONE_YEAR_MS,
      allowedAction: ['GET', 'PUT', 'DELETE']
    })
    const session = await makeSession(idb)
    session.profile.unlockMethod = {
      type: 'passkey',
      unlockSpaceId: 'unlock-space-abc',
      manageCapability: fresh
    }
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          passkeyEntry({
            manageCapability: capExpiringIn({
              msFromNow: 1000,
              allowedAction: ['GET', 'PUT', 'DELETE']
            })
          })
        ]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PasskeyUnlockMethod => method.type === 'passkey'
    )
    expect(entry!.manageCapability).toEqual(fresh)
    expect(
      (entry!.manageCapability as unknown as { allowedAction: string[] })
        .allowedAction
    ).toContain('PUT')
    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
  })

  it('re-widens a passphrase entry a past login narrowed, before expiry', async () => {
    const idb = createFakeIdb()
    const fresh = capExpiringIn({
      msFromNow: ONE_YEAR_MS,
      allowedAction: ['GET', 'PUT', 'DELETE']
    })
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      manageCapability: fresh,
      idb
    })
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          {
            type: 'passphrase',
            createdAt: '2026-01-01T00:00:00.000Z',
            unlockSpaceId: 'ps-space',
            manageCapability: capExpiringIn({
              msFromNow: ONE_YEAR_MS / 2,
              allowedAction: ['GET', 'DELETE']
            })
          }
        ]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    expect(entry!.manageCapability).toEqual(fresh)
    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
  })

  it('re-widens a passkey entry a past login narrowed, before expiry', async () => {
    const idb = createFakeIdb()
    const fresh = capExpiringIn({
      msFromNow: ONE_YEAR_MS,
      allowedAction: ['GET', 'PUT', 'DELETE']
    })
    const session = await makeSession(idb)
    session.profile.unlockMethod = {
      type: 'passkey',
      unlockSpaceId: 'unlock-space-abc',
      manageCapability: fresh
    }
    await seedRegistry({
      session,
      record: {
        version: 1,
        webAuthnUserId: 'AAAAAAAAAAAAAAAAAAAAAA',
        methods: [
          passkeyEntry({
            manageCapability: capExpiringIn({
              msFromNow: ONE_YEAR_MS / 2,
              allowedAction: ['GET', 'DELETE']
            })
          })
        ]
      }
    })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PasskeyUnlockMethod => method.type === 'passkey'
    )
    expect(entry!.manageCapability).toEqual(fresh)
    expect(putUnlockMethodsRecord).toHaveBeenCalledOnce()
  })

  it('is idempotent: a second call writes nothing', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({
      unlockSpaceId: 'ps-space',
      idb
    })
    await backfillPassphraseUnlockMethod({
      session,
      createIfMissing: true
    })
    vi.clearAllMocks()

    const result = await backfillPassphraseUnlockMethod({ session })
    expect(result).not.toBeNull()
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })
})

describe('adoptPassphraseRebind', () => {
  it('repoints the session so the backfill follows the passphrase change', async () => {
    const idb = createFakeIdb()
    const session = await makePassphraseSession({
      unlockSpaceId: 'old-ps-space',
      idb
    })
    // The registry as it stood before the change: the passphrase entry names
    // the (now deleted) old unlock Space.
    await backfillPassphraseUnlockMethod({
      session,
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

    const result = await backfillPassphraseUnlockMethod({ session })
    const entry = result!.methods.find(
      (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
    )
    expect(entry!.unlockSpaceId).toBe('new-ps-space')
    expect(entry!.manageCapability).toEqual(FAKE_CAP)

    // A second run leaves it there: the entry is never rewritten back to the
    // deleted unlock Space.
    const again = await backfillPassphraseUnlockMethod({ session })
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
    const session = await makeSession(idb)
    await seedRegistry({ session, record: sampleRecord() })

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
    const rotatedSession = await makeSession(idb)
    rotatedSession.profile.keyAgreementKey = to.keyAgreementKey as never
    rotatedSession.profile.keyResolver = to.keyResolver as never
    const read = await getUnlockMethods({ session: rotatedSession })
    expect(read).toEqual(sampleRecord())

    // The old keys no longer route the envelope.
    await expect(getUnlockMethods({ session })).rejects.toThrow()
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

describe('the registry compare-and-swap (FW-299)', () => {
  /**
   * A distinct vault key set (a different seed), standing in for another
   * writer's post-rotation user key.
   */
  async function makeVaultKeys(fillByte: number) {
    const seed = new Uint8Array(32)
    seed.fill(fillByte)
    const agent = await CapabilityAgent.fromSeed({
      seed,
      handle: `test-cas-${fillByte}`,
      keyName: 'test-cas-key'
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

  it('closes the seal-downgrade race: a stale re-seal conflicts and cannot undo a fresh one', async () => {
    // Tab A holds the pre-rotation keys; tab B rotates the user key and
    // re-seals the registry between A's read and A's PUT. A's stale-based
    // hygiene re-seal must conflict, re-read, and refuse the fresh base it
    // cannot open -- not land a record sealed back to the old keys.
    const session = await makeSession(createFakeIdb())
    await seedRegistry({ session, record: sampleRecord() })
    const from = {
      keyAgreementKey: session.profile.keyAgreementKey! as IKeyAgreementKey,
      keyResolver: session.profile.keyResolver! as IKeyResolver
    }
    const freshSeal = await makeVaultKeys(11)
    const staleTarget = await makeVaultKeys(12)
    // B's rotation re-seal lands between A's read and A's first PUT.
    wasState.beforePut = async () => {
      await rewrapUnlockMethodsRecord({
        storageServerUrl: 'https://was.example.test',
        zcapClient: {} as never,
        spaceId: DATA_SPACE_ID,
        from,
        to: freshSeal
      })
    }
    vi.mocked(putUnlockMethodsRecord).mockClear()

    await expect(
      rewrapUnlockMethodsRecord({
        storageServerUrl: 'https://was.example.test',
        zcapClient: {} as never,
        spaceId: DATA_SPACE_ID,
        from,
        to: staleTarget
      })
    ).rejects.toBeInstanceOf(RecordEnvelopeDecryptError)
    // B's PUT landed; A's first PUT conflicted and its retry refused the
    // fresh base instead of writing.
    expect(putUnlockMethodsRecord).toHaveBeenCalledTimes(2)

    // The landed record still opens under B's fresh seal -- no downgrade.
    const reader = await makeSession(createFakeIdb())
    reader.profile.keyAgreementKey = freshSeal.keyAgreementKey as never
    reader.profile.keyResolver = freshSeal.keyResolver as never
    await expect(getUnlockMethods({ session: reader })).resolves.toEqual(
      sampleRecord()
    )
  })

  it('rethrows the conflict after three attempts, with no stale write landed', async () => {
    const session = await makeSession(createFakeIdb())
    await seedRegistry({ session, record: sampleRecord() })
    // Bump the stored version behind every attempt, so each PUT is stale.
    const bump = () => {
      const version = wasState.versions.get(DATA_SPACE_ID) ?? 0
      wasState.versions.set(DATA_SPACE_ID, version + 1)
      wasState.beforePut = bump
    }
    wasState.beforePut = bump
    vi.mocked(putUnlockMethodsRecord).mockClear()

    await expect(
      updateUnlockMethods({
        session,
        mutate: current => ({
          ...(current as UnlockMethodsRecord),
          webAuthnUserId: 'STALEWRITEHANDLEAAAAAA'
        })
      })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    expect(putUnlockMethodsRecord).toHaveBeenCalledTimes(3)

    // Nothing stale landed: the stored record is untouched.
    wasState.beforePut = undefined
    await expect(getUnlockMethods({ session })).resolves.toEqual(sampleRecord())
  })

  it("re-applies a lost race on the fresh base, keeping both writers' intents", async () => {
    // The within-one-login backstop: one writer upserts a passphrase entry,
    // the other renames the passkey. The loser conflicts and re-applies on
    // the winner's record, so neither intent is silently reverted.
    const session = await makeSession(createFakeIdb())
    await seedRegistry({ session, record: sampleRecord() })
    wasState.beforePut = async () => {
      await updateUnlockMethods({
        session,
        mutate: current =>
          upsertPassphraseUnlockMethod({
            record: current as UnlockMethodsRecord,
            unlockSpaceId: 'unlock-space-pp'
          })
      })
    }

    const result = await updateUnlockMethods({
      session,
      mutate: current => ({
        ...(current as UnlockMethodsRecord),
        methods: (current as UnlockMethodsRecord).methods.map(method =>
          method.type === 'passkey' ? { ...method, label: 'Renamed' } : method
        )
      })
    })

    expect(result?.methods.map(method => method.type).sort()).toEqual([
      'passkey',
      'passphrase'
    ])
    expect(
      result?.methods.find(method => method.type === 'passkey')
    ).toMatchObject({ label: 'Renamed' })
    await expect(getUnlockMethods({ session })).resolves.toEqual(result)
  })

  it('writes nothing when mutate resolves null', async () => {
    const session = await makeSession(createFakeIdb())
    await seedRegistry({ session, record: sampleRecord() })
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await updateUnlockMethods({ session, mutate: () => null })

    expect(result).toEqual(sampleRecord())
    expect(putUnlockMethodsRecord).not.toHaveBeenCalled()
  })

  it('first-materializes create-if-absent and upserts into a record that won the create race', async () => {
    const session = await makeSession(createFakeIdb())
    const other = sampleRecord()
    // Another writer creates the first record between this writer's read
    // (which found nothing) and its create.
    wasState.beforePut = async () => {
      const winner = await makeSession(createFakeIdb())
      await seedRegistry({ session: winner, record: other })
    }
    vi.mocked(putUnlockMethodsRecord).mockClear()

    const result = await updateUnlockMethods({
      session,
      mutate: current =>
        upsertPassphraseUnlockMethod({
          record: current ?? {
            version: 1,
            webAuthnUserId: 'FRESHMINTEDHANDLEAAAAA',
            methods: []
          },
          unlockSpaceId: 'unlock-space-pp'
        })
    })

    // The first attempt was a create-if-absent; losing it retried and
    // upserted into the existing record, whose handle and entries survive.
    const firstPut = vi.mocked(putUnlockMethodsRecord).mock.calls[0]![0]
    expect(firstPut.ifNoneMatch).toBe(true)
    expect(result?.webAuthnUserId).toBe(other.webAuthnUserId)
    expect(result?.methods.map(method => method.type).sort()).toEqual([
      'passkey',
      'passphrase'
    ])
    await expect(getUnlockMethods({ session })).resolves.toEqual(result)
  })
})
