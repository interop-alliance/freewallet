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
  pukVaultKeys: vi.fn(({ puk }: { puk: { id: string } }) => ({
    keyAgreementKey: { id: `${puk.id}#kak` },
    keyResolver: async () => ({})
  }))
}))

// The roster policy itself lives in wallet-core (`clients`): the login read and
// the convergence onto the account document are the two seams this file drives,
// and their internals (the roster read, the log verification, the offline
// swallow) are that package's own tests to keep.
vi.mock('@interop/wallet-core/clients', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/clients')>()),
  checkPukRosterAtLogin: vi.fn(async () => null),
  convergePukRosterToAccount: vi.fn(async () => ({
    rotated: false,
    staleRecipientIds: [],
    puk: null,
    descriptor: null
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

import {
  checkPukRosterAtLogin,
  convergePukRosterToAccount
} from '@interop/wallet-core/clients'
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
const CONVERGED_DESCRIPTOR = { rosterDescriptor: 'converged' }
const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

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
  const refreshEncryptedDescriptors = vi.fn(async () => undefined)
  const adoptRotatedVaultKeys = vi.fn(async () => undefined)
  const storage = {
    ensureUserCollections: vi.fn(() => provisioning),
    refreshEncryptedDescriptors,
    adoptRotatedVaultKeys,
    get remoteStore() {
      return withRemote ? remoteStore : undefined
    }
  } as unknown as StorageManager
  return {
    storage,
    remoteStore,
    refreshEncryptedDescriptors,
    adoptRotatedVaultKeys,
    resolveProvisioning,
    rejectProvisioning
  }
}

function randomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

/**
 * The convergence's own best-effort default: a healthy roster (and equally a
 * document that could not be fetched or verified) hands the fan-out back the
 * key and descriptor the login already had.
 */
function convergenceLeavesInputUnchanged() {
  vi.mocked(convergePukRosterToAccount).mockImplementation((async ({
    puk,
    descriptor
  }: {
    puk: unknown
    descriptor: unknown
  }) => ({
    rotated: false,
    staleRecipientIds: [],
    puk,
    descriptor
  })) as never)
}

beforeEach(() => {
  vi.clearAllMocks()
  state.wasUrl = 'https://was.example.test'
  vi.mocked(checkPukRosterAtLogin).mockResolvedValue(null)
  convergenceLeavesInputUnchanged()
})

describe('the login-time cascade-completion sweep', () => {
  it('fires the cascade behind storageReady and exposes it as pukSweep', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(rosterRead() as never)

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
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(
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
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(rosterRead() as never)

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

  it('refreshes the session ciphers when the sweep moved an epoch', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(rosterRead() as never)
    // The sweep completed a crashed cascade: one collection took a fresh
    // epoch. The ciphers were built before the sweep, so a post-sweep write
    // would otherwise stay sealed under the retired epoch.
    vi.mocked(cascadeCollectionsToPuk).mockResolvedValue({
      outcomes: {
        'private-credentials': 'rotated',
        'wallet-activity': 'noop'
      },
      failed: []
    } as never)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK
    })
    fake.resolveProvisioning()
    await session.pukSweep
    expect(fake.refreshEncryptedDescriptors).toHaveBeenCalledOnce()
  })

  it('skips the cipher refresh when the sweep left every epoch in place', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(rosterRead() as never)
    // noop keeps the epoch; an escrow adds a recipient without moving it.
    vi.mocked(cascadeCollectionsToPuk).mockResolvedValue({
      outcomes: {
        'private-credentials': 'noop',
        'wallet-activity': 'escrowed'
      },
      failed: []
    } as never)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK
    })
    fake.resolveProvisioning()
    await session.pukSweep
    expect(fake.refreshEncryptedDescriptors).not.toHaveBeenCalled()
  })

  it('resolves null (never rejects) when the sweep itself fails', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(rosterRead() as never)
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
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(null)

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
    // An unreachable server is the roster policy's own swallow: it keeps the
    // cached key authoritative and reports no read at all.
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(null)

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
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(rosterRead() as never)

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
    expect(vi.mocked(checkPukRosterAtLogin)).not.toHaveBeenCalled()
    expect(session.pukSweep).toBeUndefined()
  })

  it('does not fire when provisioning is deferred (provisionStorage: false)', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(rosterRead() as never)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK,
      provisionStorage: false
    })
    expect(session.pukSweep).toBeUndefined()
    expect(vi.mocked(cascadeCollectionsToPuk)).not.toHaveBeenCalled()
  })
})

describe('the roster stage of the sweep', () => {
  it('finishes a torn disconnect and sweeps with the converged key', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(rosterRead() as never)
    // The convergence found the roster still wrapping the current key to a
    // recipient the document no longer keys, rotated it, and handed back the
    // fresh key through the adoption callback.
    vi.mocked(convergePukRosterToAccount).mockImplementation((async ({
      onPukAdopted
    }: {
      onPukAdopted?: (adopted: unknown) => Promise<void>
    }) => {
      await onPukAdopted?.({
        puk: FRESH_PUK,
        latestEpochId: FRESH_PUK.id,
        descriptor: CONVERGED_DESCRIPTOR
      })
      return {
        rotated: true,
        staleRecipientIds: ['did:key:z6MkGone#z6LSGone'],
        puk: FRESH_PUK,
        descriptor: CONVERGED_DESCRIPTOR
      }
    }) as never)
    const onPukRotated = vi.fn(async () => undefined)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK,
      accountPointer: POINTER,
      onPukRotated
    })
    fake.resolveProvisioning()
    await session.pukSweep

    expect(
      vi.mocked(convergePukRosterToAccount)
    ).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        pointer: {
          did: POINTER.did,
          spaceId: POINTER.spaceId,
          host: POINTER.host
        },
        descriptor: ROSTER_DESCRIPTOR,
        puk: OLD_PUK
      })
    )
    // The fresh key is adopted -- persisted for the next login, swapped into
    // the live session -- and the fan-out runs against it.
    expect(onPukRotated).toHaveBeenCalledWith(FRESH_PUK)
    expect(session.profile.puk).toEqual(FRESH_PUK)
    expect(fake.adoptRotatedVaultKeys).toHaveBeenCalledOnce()
    expect(vi.mocked(cascadeCollectionsToPuk)).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        rosterDescriptor: CONVERGED_DESCRIPTOR,
        puk: FRESH_PUK
      })
    )
    warn.mockRestore()
  })

  it('leaves a healthy roster alone and sweeps with the login key', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(rosterRead() as never)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK,
      accountPointer: POINTER
    })
    fake.resolveProvisioning()
    await session.pukSweep

    expect(vi.mocked(convergePukRosterToAccount)).toHaveBeenCalledOnce()
    expect(fake.adoptRotatedVaultKeys).not.toHaveBeenCalled()
    expect(vi.mocked(cascadeCollectionsToPuk)).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        rosterDescriptor: ROSTER_DESCRIPTOR,
        puk: OLD_PUK
      })
    )
  })

  it('sweeps anyway when the account document cannot be verified', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(rosterRead() as never)
    // An unfetchable or unverifiable document is swallowed inside the
    // convergence, which hands back the login's own key and descriptor.
    convergenceLeavesInputUnchanged()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK,
      accountPointer: POINTER
    })
    fake.resolveProvisioning()
    await session.pukSweep

    expect(fake.adoptRotatedVaultKeys).not.toHaveBeenCalled()
    expect(vi.mocked(cascadeCollectionsToPuk)).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        rosterDescriptor: ROSTER_DESCRIPTOR,
        puk: OLD_PUK
      })
    )
    warn.mockRestore()
  })

  it('does not run for an account whose pointer names no did:webvh', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkPukRosterAtLogin).mockResolvedValue(rosterRead() as never)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      puk: OLD_PUK,
      accountPointer: { ...POINTER, did: undefined }
    })
    fake.resolveProvisioning()
    await session.pukSweep

    expect(vi.mocked(convergePukRosterToAccount)).not.toHaveBeenCalled()
    expect(vi.mocked(cascadeCollectionsToPuk)).toHaveBeenCalledOnce()
  })
})
