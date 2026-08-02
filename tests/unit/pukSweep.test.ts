// @vitest-environment node
/**
 * Unit tests for the login-time cascade-completion sweep wiring in
 * `src/session/initSession.ts`: with the roster read in hand and a remote
 * store attached, session creation fires `cascadeCollectionsToPuk` behind
 * `storageReady` and exposes it as `session.pukSweep` -- best-effort (a
 * failed sweep resolves `null`, never rejects, never fails the login), and
 * absent whenever there is nothing to sweep from (no roster yet, an offline
 * roster check, no remote store, a guest). The seed-to-identity derivation
 * runs for real; every remote/durable seam is mocked.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  },
  get KMS_SERVER_URL() {
    return undefined
  }
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  pukRosterDescriptorStore: vi.fn(() => ({ isFakeRosterStore: true })),
  readPukRoster: vi.fn(async () => null),
  pukVaultKeys: vi.fn(({ puk }: { puk: { id: string } }) => ({
    keyAgreementKey: { id: `${puk.id}#kak` },
    keyResolver: async () => ({})
  }))
}))

vi.mock('@/lib/sessionKey', () => ({
  loadPukEpochPin: vi.fn(async () => null),
  savePukEpochPin: vi.fn(async () => undefined)
}))

vi.mock('@/session/pukCascade', () => ({
  cascadeCollectionsToPuk: vi.fn(async () => ({ outcomes: {}, failed: [] }))
}))

vi.mock('@/stores/storageManager', () => ({
  StorageManager: { initStorageClients: vi.fn() }
}))

import { readPukRoster } from '@interop/wallet-core/keys'
import { cascadeCollectionsToPuk } from '@/session/pukCascade'
import { StorageManager } from '@/stores/storageManager'
import { initSessionFromSeed } from '@/session/initSession'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

const OLD_PUK = { id: 'did:key:z6LSOldPuk', secret: new Uint8Array(32).fill(1) }
const FRESH_PUK = {
  id: 'did:key:z6LSFreshPuk',
  secret: new Uint8Array(32).fill(2)
}
const ROSTER_DESCRIPTOR = { rosterDescriptor: true }

function rosterRead({ rotated = false } = {}) {
  return {
    descriptor: ROSTER_DESCRIPTOR,
    puk: rotated ? FRESH_PUK : OLD_PUK,
    rotated,
    latestEpochId: rotated ? FRESH_PUK.id : OLD_PUK.id
  }
}

/**
 * A storage stub whose `ensureUserCollections` promise the test controls, so
 * ordering ("the sweep waits for provisioning") is observable.
 */
function makeFakeStorage({ withRemote = true } = {}) {
  let resolveProvisioning!: () => void
  let rejectProvisioning!: (err: Error) => void
  const provisioning = new Promise<void>((resolve, reject) => {
    resolveProvisioning = resolve
    rejectProvisioning = reject
  })
  const remoteStore = { isFakeRemoteStore: true } as unknown as WASRemoteStore
  const storage = {
    ensureUserCollections: vi.fn(() => provisioning),
    get remoteStore() {
      return withRemote ? remoteStore : undefined
    }
  } as unknown as StorageManager
  return { storage, remoteStore, resolveProvisioning, rejectProvisioning }
}

function randomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

beforeEach(() => {
  vi.clearAllMocks()
  state.wasUrl = 'https://was.example.test'
  vi.mocked(readPukRoster).mockResolvedValue(null)
})

describe('the login-time cascade-completion sweep', () => {
  it('fires the cascade behind storageReady and exposes it as pukSweep', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(readPukRoster).mockResolvedValue(rosterRead() as never)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK
    })
    expect(session.pukSweep).toBeDefined()

    // The sweep is chained behind provisioning: nothing runs until
    // `ensureUserCollections` settles.
    await Promise.resolve()
    expect(vi.mocked(cascadeCollectionsToPuk)).not.toHaveBeenCalled()

    fake.resolveProvisioning()
    const result = await session.pukSweep
    expect(result).toEqual({ outcomes: {}, failed: [] })
    expect(vi.mocked(cascadeCollectionsToPuk)).toHaveBeenCalledExactlyOnceWith({
      remoteStore: fake.remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: session.profile.clientKeyAgreementKey,
      puk: OLD_PUK
    })
  })

  it('sweeps with the freshly adopted PUK when the roster read rotated', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(readPukRoster).mockResolvedValue(
      rosterRead({ rotated: true }) as never
    )
    const onPukRotated = vi.fn(async () => undefined)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK,
      onPukRotated
    })
    expect(onPukRotated).toHaveBeenCalledExactlyOnceWith(FRESH_PUK)

    fake.resolveProvisioning()
    await session.pukSweep
    expect(vi.mocked(cascadeCollectionsToPuk)).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ puk: FRESH_PUK })
    )
  })

  it('still sweeps when provisioning itself failed', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(readPukRoster).mockResolvedValue(rosterRead() as never)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK
    })
    session.storageReady?.catch(() => {})
    fake.rejectProvisioning(new Error('provisioning down'))

    const result = await session.pukSweep
    expect(result).toEqual({ outcomes: {}, failed: [] })
    expect(vi.mocked(cascadeCollectionsToPuk)).toHaveBeenCalledOnce()
  })

  it('resolves null (never rejects) when the sweep itself fails', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(readPukRoster).mockResolvedValue(rosterRead() as never)
    vi.mocked(cascadeCollectionsToPuk).mockRejectedValue(
      new Error('sweep broke')
    )

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK
    })
    fake.resolveProvisioning()
    await expect(session.pukSweep).resolves.toBeNull()
  })

  it('does not fire without a roster (an account provisioning has not created one)', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(readPukRoster).mockResolvedValue(null)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK
    })
    expect(session.pukSweep).toBeUndefined()
  })

  it('does not fire when the roster check was offline (cached PUK kept)', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(readPukRoster).mockRejectedValue(new Error('network down'))

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK
    })
    expect(session.pukSweep).toBeUndefined()
    expect(session.profile.puk).toEqual(OLD_PUK)
  })

  it('does not fire without a remote store', async () => {
    const fake = makeFakeStorage({ withRemote: false })
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(readPukRoster).mockResolvedValue(rosterRead() as never)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK
    })
    expect(session.pukSweep).toBeUndefined()
  })

  it('does not fire for a guest session (no roster read at all)', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: false
    })

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK,
      isGuest: true
    })
    expect(vi.mocked(readPukRoster)).not.toHaveBeenCalled()
    expect(session.pukSweep).toBeUndefined()
  })

  it('does not fire when provisioning is deferred (provisionStorage: false)', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(readPukRoster).mockResolvedValue(rosterRead() as never)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK,
      provisionStorage: false
    })
    expect(session.pukSweep).toBeUndefined()
    expect(vi.mocked(cascadeCollectionsToPuk)).not.toHaveBeenCalled()
  })
})
