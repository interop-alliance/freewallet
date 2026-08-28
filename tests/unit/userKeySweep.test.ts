// @vitest-environment node
/**
 * Unit tests for the login-time cascade-completion sweep wiring in
 * `src/session/initSession.ts`: with the roster read in hand and a remote
 * store attached, session creation fires `cascadeCollectionsToUserKey` behind
 * `storageReady` and exposes it as `session.userKeySweep` -- best-effort (a
 * failed sweep resolves `null`, never rejects, never fails the login), and
 * absent whenever there is nothing to sweep from (no roster yet, an offline
 * roster check, no remote store, a guest). The seed-to-identity derivation
 * runs for real; every remote/durable seam is mocked.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined
}))

// The visit's in-memory roster-epoch pin, stubbed on the browser-local
// strategy so the login's read and the adoption's write are both observable.
const epochPins = vi.hoisted(() => ({
  load: vi.fn(
    async (_options: { accountDid: string }) => null as string | null
  ),
  saveFromDescriptor: vi.fn(
    async (_options: {
      accountDid: string
      epochId: string
      descriptor: { epochs?: Array<{ id: string }> }
    }) => undefined
  )
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

// The sweep's in-band adoption re-seals the unlock-methods registry before
// it swaps the session onto the converged key, and only swaps when that
// re-seal reports success. This account has no registry written yet, which
// makes the re-seal the no-op it should be here.
vi.mock('@/stores/wasRemoteStore', async importOriginal => ({
  ...(await importOriginal<typeof import('@/stores/wasRemoteStore')>()),
  getUnlockMethodsRecord: vi.fn(async () => null)
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  userKeyRosterDescriptorStore: vi.fn(() => ({ isFakeRosterStore: true })),
  userKeyVaultKeys: vi.fn(({ userKey }: { userKey: { id: string } }) => ({
    keyAgreementKey: { id: `${userKey.id}#kak` },
    keyResolver: async () => ({})
  }))
}))

// The roster policy itself lives in wallet-core (`clients`): the login read and
// the convergence onto the account document are the two seams this file drives,
// and their internals (the roster read, the log verification, the offline
// swallow) are that package's own tests to keep.
vi.mock('@interop/wallet-core/clients', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/clients')>()),
  checkUserKeyRosterAtLogin: vi.fn(async () => null),
  convergeUserKeyRosterToAccount: vi.fn(async () => ({
    rotated: false,
    staleRecipientIds: [],
    userKey: null,
    descriptor: null
  }))
}))

vi.mock('@/session/persistence', async importOriginal => {
  const actual = await importOriginal<typeof import('@/session/persistence')>()
  return {
    ...actual,
    browserLocalSessionPersistence: vi.fn(
      (
        options?: Parameters<typeof actual.browserLocalSessionPersistence>[0]
      ) => ({
        ...actual.browserLocalSessionPersistence(options),
        epochPins
      })
    )
  }
})

vi.mock('@/session/userKeyCascade', () => ({
  cascadeCollectionsToUserKey: vi.fn(async () => ({ outcomes: {}, failed: [] }))
}))

vi.mock('@/stores/storageManager', () => ({
  StorageManager: { initStorageClients: vi.fn() }
}))

import {
  checkUserKeyRosterAtLogin,
  convergeUserKeyRosterToAccount
} from '@interop/wallet-core/clients'
import { cascadeCollectionsToUserKey } from '@/session/userKeyCascade'
import { StorageManager } from '@/stores/storageManager'
import { initSessionFromSeed } from '@/session/initSession'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

const OLD_USER_KEY = {
  id: 'did:key:z6LSOldUserKey',
  secret: new Uint8Array(32).fill(1)
}
const FRESH_USER_KEY = {
  id: 'did:key:z6LSFreshUserKey',
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
    userKey: rotated ? FRESH_USER_KEY : OLD_USER_KEY,
    rotated,
    latestEpochId: rotated ? FRESH_USER_KEY.id : OLD_USER_KEY.id
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
  vi.mocked(convergeUserKeyRosterToAccount).mockImplementation((async ({
    userKey,
    descriptor
  }: {
    userKey: unknown
    descriptor: unknown
  }) => ({
    rotated: false,
    staleRecipientIds: [],
    userKey,
    descriptor
  })) as never)
}

beforeEach(() => {
  vi.clearAllMocks()
  state.wasUrl = 'https://was.example.test'
  vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(null)
  convergenceLeavesInputUnchanged()
})

describe('the login-time cascade-completion sweep', () => {
  it('fires the cascade behind storageReady and exposes it as userKeySweep', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    expect(session.userKeySweep).toBeDefined()

    // The sweep is chained behind provisioning: nothing runs until
    // `ensureUserCollections` settles.
    await Promise.resolve()
    expect(vi.mocked(cascadeCollectionsToUserKey)).not.toHaveBeenCalled()

    fake.resolveProvisioning()
    const result = await session.userKeySweep
    expect(result).toEqual({ outcomes: {}, failed: [] })
    expect(
      vi.mocked(cascadeCollectionsToUserKey)
    ).toHaveBeenCalledExactlyOnceWith({
      remoteStore: fake.remoteStore,
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: session.profile.clientKeyAgreementKey,
      userKey: OLD_USER_KEY
    })
  })

  it('sweeps with the freshly adopted user key when the roster read rotated', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead({ rotated: true }) as never
    )
    const persistClientKeys = vi.fn(async () => undefined)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER,
      persistClientKeys
    })
    expect(persistClientKeys).toHaveBeenCalledExactlyOnceWith({
      userKey: FRESH_USER_KEY
    })

    fake.resolveProvisioning()
    await session.userKeySweep
    expect(
      vi.mocked(cascadeCollectionsToUserKey)
    ).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ userKey: FRESH_USER_KEY })
    )
  })

  it('still sweeps when provisioning itself failed', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    session.storageReady?.catch(() => {})
    fake.rejectProvisioning(new Error('provisioning down'))

    const result = await session.userKeySweep
    expect(result).toEqual({ outcomes: {}, failed: [] })
    expect(vi.mocked(cascadeCollectionsToUserKey)).toHaveBeenCalledOnce()
  })

  it('refreshes the session ciphers when the sweep moved an epoch', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )
    // The sweep completed a crashed cascade: one collection took a fresh
    // epoch. The ciphers were built before the sweep, so a post-sweep write
    // would otherwise stay sealed under the retired epoch.
    vi.mocked(cascadeCollectionsToUserKey).mockResolvedValue({
      outcomes: {
        'private-credentials': 'rotated',
        'wallet-activity': 'noop'
      },
      failed: []
    } as never)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    fake.resolveProvisioning()
    await session.userKeySweep
    expect(fake.refreshEncryptedDescriptors).toHaveBeenCalledOnce()
  })

  it('skips the cipher refresh when the sweep left every epoch in place', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )
    // noop keeps the epoch; an escrow adds a recipient without moving it.
    vi.mocked(cascadeCollectionsToUserKey).mockResolvedValue({
      outcomes: {
        'private-credentials': 'noop',
        'wallet-activity': 'escrowed'
      },
      failed: []
    } as never)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    fake.resolveProvisioning()
    await session.userKeySweep
    expect(fake.refreshEncryptedDescriptors).not.toHaveBeenCalled()
  })

  it('resolves null (never rejects) when the sweep itself fails', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )
    vi.mocked(cascadeCollectionsToUserKey).mockRejectedValue(
      new Error('sweep broke')
    )

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    fake.resolveProvisioning()
    await expect(session.userKeySweep).resolves.toBeNull()
  })

  it('does not fire without a roster (an account provisioning has not created one)', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(null)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    expect(session.userKeySweep).toBeUndefined()
  })

  it('does not fire when the roster check was offline (cached user key kept)', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    // An unreachable server is the roster policy's own swallow: it keeps the
    // cached key authoritative and reports no read at all.
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(null)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    expect(session.userKeySweep).toBeUndefined()
    expect(session.profile.userKey).toEqual(OLD_USER_KEY)
  })

  it('does not fire without a remote store', async () => {
    const fake = makeFakeStorage({ withRemote: false })
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    expect(session.userKeySweep).toBeUndefined()
  })

  it('does not fire for a guest session (no roster read at all)', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: false
    })

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      isGuest: true
    })
    expect(vi.mocked(checkUserKeyRosterAtLogin)).not.toHaveBeenCalled()
    expect(session.userKeySweep).toBeUndefined()
  })

  it('does not fire when provisioning is deferred (provisionStorage: false)', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      provisionStorage: false
    })
    expect(session.userKeySweep).toBeUndefined()
    expect(vi.mocked(cascadeCollectionsToUserKey)).not.toHaveBeenCalled()
  })
})

describe('a failed user-key persist at login (browser not remembered)', () => {
  /**
   * Makes the mocked login read behave like the real one: the adoption
   * callback runs after a successful read, and its throw is the app's to
   * handle (wallet-core no longer swallows it into the offline null path).
   */
  function readInvokesAdoptionCallback({ rotated = false } = {}) {
    vi.mocked(checkUserKeyRosterAtLogin).mockImplementation((async (opts: {
      onRosterRead?: (adopted: unknown) => Promise<void>
    }) => {
      const read = rosterRead({ rotated })
      await opts.onRosterRead?.({
        userKey: read.userKey,
        latestEpochId: read.latestEpochId,
        descriptor: read.descriptor
      })
      return read
    }) as never)
  }

  it('adopts a rotated key in memory even when the client-key record write fails', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    readInvokesAdoptionCallback({ rotated: true })
    const persistClientKeys = vi.fn(async () => {
      throw new Error('IndexedDB write failed')
    })

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER,
      persistClientKeys
    })
    expect(session.userKeyPersistFailed).toBe(true)
    // The session still runs on the freshly adopted key; only this browser's
    // stored copy stayed behind.
    expect(session.profile.userKey).toEqual(FRESH_USER_KEY)
  })

  it('leaves the flag unset when both persists succeed', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    readInvokesAdoptionCallback({ rotated: true })
    const persistClientKeys = vi.fn(async () => undefined)

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER,
      persistClientKeys
    })
    expect(session.userKeyPersistFailed).toBeUndefined()
    expect(session.profile.userKey).toEqual(FRESH_USER_KEY)
  })
})

describe('the roster stage of the sweep', () => {
  it('finishes a torn disconnect and sweeps with the converged key', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )
    // The convergence found the roster still wrapping the current key to a
    // recipient the document no longer keys, rotated it, and handed back the
    // fresh key through the adoption callback.
    vi.mocked(convergeUserKeyRosterToAccount).mockImplementation((async ({
      onUserKeyAdopted
    }: {
      onUserKeyAdopted?: (adopted: unknown) => Promise<void>
    }) => {
      await onUserKeyAdopted?.({
        userKey: FRESH_USER_KEY,
        latestEpochId: FRESH_USER_KEY.id,
        descriptor: CONVERGED_DESCRIPTOR
      })
      return {
        rotated: true,
        staleRecipientIds: ['did:key:z6MkGone#z6LSGone'],
        userKey: FRESH_USER_KEY,
        descriptor: CONVERGED_DESCRIPTOR
      }
    }) as never)
    const persistClientKeys = vi.fn(async () => undefined)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER,
      persistClientKeys
    })
    fake.resolveProvisioning()
    await session.userKeySweep

    expect(
      vi.mocked(convergeUserKeyRosterToAccount)
    ).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        pointer: {
          did: POINTER.did,
          spaceId: POINTER.spaceId,
          host: POINTER.host
        },
        descriptor: ROSTER_DESCRIPTOR,
        userKey: OLD_USER_KEY
      })
    )
    // The epoch pin is keyed by the account DID, never by the Space id a
    // substituted pointer could change.
    expect(epochPins.load).toHaveBeenCalledWith(
      expect.objectContaining({ accountDid: POINTER.did })
    )
    // The fresh key is adopted -- persisted for the next login, swapped into
    // the live session -- and the fan-out runs against it.
    expect(persistClientKeys).toHaveBeenCalledWith({ userKey: FRESH_USER_KEY })
    expect(session.profile.userKey).toEqual(FRESH_USER_KEY)
    expect(fake.adoptRotatedVaultKeys).toHaveBeenCalledOnce()
    expect(
      vi.mocked(cascadeCollectionsToUserKey)
    ).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        rosterDescriptor: CONVERGED_DESCRIPTOR,
        userKey: FRESH_USER_KEY
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
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    fake.resolveProvisioning()
    await session.userKeySweep

    expect(vi.mocked(convergeUserKeyRosterToAccount)).toHaveBeenCalledOnce()
    expect(fake.adoptRotatedVaultKeys).not.toHaveBeenCalled()
    expect(
      vi.mocked(cascadeCollectionsToUserKey)
    ).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        rosterDescriptor: ROSTER_DESCRIPTOR,
        userKey: OLD_USER_KEY
      })
    )
  })

  it('sweeps anyway when the account document cannot be verified', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )
    // An unfetchable or unverifiable document is swallowed inside the
    // convergence, which hands back the login's own key and descriptor.
    convergenceLeavesInputUnchanged()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    fake.resolveProvisioning()
    await session.userKeySweep

    expect(fake.adoptRotatedVaultKeys).not.toHaveBeenCalled()
    expect(
      vi.mocked(cascadeCollectionsToUserKey)
    ).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        rosterDescriptor: ROSTER_DESCRIPTOR,
        userKey: OLD_USER_KEY
      })
    )
    warn.mockRestore()
  })

  it('does not run for an account whose pointer names no DID', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: true
    })
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )

    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: { ...POINTER, did: undefined }
    })
    fake.resolveProvisioning()

    // The roster read itself requires a pointer that names the account DID
    // (the epoch-signature check resolves the signer against the account
    // log), so a did-less pointer skips the read -- and with no roster in
    // hand there is no sweep at all.
    expect(vi.mocked(checkUserKeyRosterAtLogin)).not.toHaveBeenCalled()
    expect(session.userKeySweep).toBeUndefined()
    expect(vi.mocked(convergeUserKeyRosterToAccount)).not.toHaveBeenCalled()
    expect(vi.mocked(cascadeCollectionsToUserKey)).not.toHaveBeenCalled()
  })
})
