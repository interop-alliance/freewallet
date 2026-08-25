// @vitest-environment node
/**
 * Unit tests for the FW-300 split in `src/session/initSession.ts`: the
 * login-time registry passes ride `session.registryReady` -- one ordered
 * promise chain seeded behind storage provisioning -- while
 * `session.storageReady` stays the raw provisioning promise, so a login
 * page can navigate as soon as the collections are ready. The chain keeps
 * the FW-296 total order (the user-key sweep fold first, then the re-seal
 * repair, the torn-retirement repair, the bare-passkey rebuild, the
 * backfill), is skipped outright when provisioning itself failed (the
 * session is abandoned), and never rejects.
 * The keyring and every remote/durable seam are mocked; the seed-to-identity
 * derivation runs for real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined,
  events: [] as string[]
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

vi.mock('@/session/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/keyring')>()),
  fetchKeyring: vi.fn(),
  fetchTransientKeyring: vi.fn()
}))

// Full factory (no importOriginal): the module imports back from the module
// under test, and loading the original inside the factory would hand that
// cycle the REAL composition.
vi.mock('@/session/transientLogin', () => ({
  routeUnlockLogin: vi.fn(),
  transientSessionFromKeyringHit: vi.fn()
}))
vi.mock('@/lib/kms', () => ({ ensureKeystore: vi.fn() }))
vi.mock('@/stores/storageManager', () => ({
  StorageManager: { initStorageClients: vi.fn() }
}))
vi.mock('@/session/standingUnlock', () => ({
  canSelfEnroll: vi.fn(() => false),
  selfEnrollStandingClient: vi.fn()
}))

// The chain's passes, each recording its turn on the shared event list.
vi.mock('@/session/registryReseal', () => ({
  repairStaleUnlockRegistrySeal: vi.fn(async () => {
    state.events.push('reseal')
  })
}))
vi.mock('@/session/pendingRetirement', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/pendingRetirement')>()),
  repairTornPassphraseRetirement: vi.fn(async () => {
    state.events.push('torn-retirement')
  }),
  rebuildBarePasskeyEntry: vi.fn(async () => {
    state.events.push('bare-passkey')
  })
}))
vi.mock('@/session/unlockMethods', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/unlockMethods')>()),
  backfillPassphraseUnlockMethod: vi.fn(async () => {
    state.events.push('backfill')
    return null
  }),
  refreshStandingDelegationFields: vi.fn(async () => null)
}))
vi.mock('@/session/clientAnnexGc', () => ({
  sweepClientAnnexGenerations: vi.fn(async () => {
    state.events.push('annex-gc')
    return null
  })
}))

// The roster read succeeds (so the re-seal repair's gate is open) and the
// sweep's convergence leaves the login key unchanged.
vi.mock('@interop/wallet-core/clients', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/clients')>()),
  checkUserKeyRosterAtLogin: vi.fn(),
  convergeUserKeyRosterToAccount: vi.fn()
}))
vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  userKeyRosterDescriptorStore: vi.fn(() => ({ isFakeRosterStore: true })),
  userKeyVaultKeys: vi.fn(({ userKey }: { userKey: { id: string } }) => ({
    keyAgreementKey: { id: `${userKey.id}#kak` },
    keyResolver: async () => ({})
  }))
}))
vi.mock('@/lib/sessionKey', () => ({
  loadUserKeyEpochPin: vi.fn(async () => null),
  saveUserKeyEpochPin: vi.fn(async () => undefined),
  savePinFromDescriptor: vi.fn(async () => undefined),
  sessionLogPinStore: vi.fn(() => ({
    read: async () => null,
    write: async () => undefined
  }))
}))
vi.mock('@/session/userKeyCascade', () => ({
  cascadeCollectionsToUserKey: vi.fn(async () => {
    state.events.push('user-key-sweep')
    return { outcomes: {}, failed: [] }
  })
}))

import {
  checkUserKeyRosterAtLogin,
  convergeUserKeyRosterToAccount
} from '@interop/wallet-core/clients'
import { repairStaleUnlockRegistrySeal } from '@/session/registryReseal'
import { backfillPassphraseUnlockMethod } from '@/session/unlockMethods'
import { fetchKeyring } from '@/session/keyring'
import { routeUnlockLogin } from '@/session/transientLogin'
import { StorageManager } from '@/stores/storageManager'
import { loginWithPassphrase } from '@/session/initSession'
import { mintUserKey } from '@interop/wallet-core/keys'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

const PASSPHRASE = 'correct horse battery staple'
const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

/**
 * A storage stub whose `ensureUserCollections` promise the test controls, so
 * the split ("storageReady resolves while the chain is still blocked") is
 * observable.
 */
function makeFakeStorage() {
  let resolveProvisioning!: () => void
  let rejectProvisioning!: (err: Error) => void
  const provisioning = new Promise<void>((resolve, reject) => {
    resolveProvisioning = resolve
    rejectProvisioning = reject
  })
  const storage = {
    ensureUserCollections: vi.fn(() => provisioning),
    refreshEncryptedDescriptors: vi.fn(async () => undefined),
    adoptRotatedVaultKeys: vi.fn(async () => undefined),
    remoteStore: { isFakeRemoteStore: true } as unknown as WASRemoteStore
  } as unknown as StorageManager
  return { storage, resolveProvisioning, rejectProvisioning }
}

async function didFromSeed(seed: Uint8Array): Promise<string> {
  const agent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'bootstrap',
    keyName: 'boostrap-key'
  })
  return agent.id
}

function randomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

/**
 * Resolves to whether the promise settled within a macrotask turn -- the
 * "is this still pending" probe the split assertions need.
 */
async function settled(promise: Promise<unknown> | undefined) {
  if (!promise) {
    return false
  }
  const sentinel = Symbol('pending')
  const winner = await Promise.race([
    promise.then(
      () => 'settled',
      () => 'settled'
    ),
    new Promise(resolve => setTimeout(() => resolve(sentinel), 20))
  ])
  return winner !== sentinel
}

async function arrangeEnrolledLogin() {
  const clientSeed = randomSeed()
  const controller = await didFromSeed(clientSeed)
  const userKey = await mintUserKey()
  vi.mocked(fetchKeyring).mockResolvedValue({
    controller,
    pointer: POINTER,
    // The ENROLLED shape: a record missing any of the four members would
    // route into the pending-record resume instead of the ordinary login.
    clientKeys: {
      clientSeed,
      userKey,
      webvhUpdateKeys: { updateSeed: randomSeed(), stagedSeed: randomSeed() },
      controller,
      pointerDid: POINTER.did
    },
    unlockSpaceId: 'unlock-space-test',
    createdAt: new Date().toISOString()
  } as never)
  const fake = makeFakeStorage()
  vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
    storage: fake.storage,
    userExists: true
  } as never)
  // A healthy roster read: the cached user key confirmed current, so the
  // sweep runs with the login key and the re-seal repair's gate is open.
  vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue({
    descriptor: { rosterDescriptor: true },
    userKey,
    rotated: false,
    latestEpochId: userKey.id
  } as never)
  vi.mocked(convergeUserKeyRosterToAccount).mockImplementation((async ({
    userKey: sweepKey,
    descriptor
  }: {
    userKey: unknown
    descriptor: unknown
  }) => ({
    rotated: false,
    staleRecipientIds: [],
    userKey: sweepKey,
    descriptor
  })) as never)
  return fake
}

beforeEach(() => {
  vi.clearAllMocks()
  state.wasUrl = 'https://was.example.test'
  state.events = []
  // `clearAllMocks` keeps implementations, so re-arm the pass a test blocks
  // on a controllable promise back to its recording default.
  vi.mocked(repairStaleUnlockRegistrySeal).mockImplementation(async () => {
    state.events.push('reseal')
    return 'ok'
  })
  vi.mocked(routeUnlockLogin).mockImplementation((async ({
    credential
  }: {
    credential?: unknown
  }) => ({
    durability: 'durable',
    ...(credential ? { credential } : {})
  })) as never)
})

describe('the FW-300 storageReady / registryReady split', () => {
  it('resolves storageReady as soon as provisioning is done, while the chain is still blocked', async () => {
    const fake = await arrangeEnrolledLogin()
    // Block the chain at its first registry pass.
    let releaseReseal!: () => void
    vi.mocked(repairStaleUnlockRegistrySeal).mockImplementation(
      () =>
        new Promise<'ok'>(resolve => {
          releaseReseal = () => {
            state.events.push('reseal')
            resolve('ok')
          }
        })
    )

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    expect(session!.registryReady).toBeInstanceOf(Promise)

    fake.resolveProvisioning()
    // Navigation's gate: provisioning alone.
    await session!.storageReady
    expect(await settled(session!.registryReady)).toBe(false)
    expect(backfillPassphraseUnlockMethod).not.toHaveBeenCalled()

    releaseReseal()
    await session!.registryReady
    expect(backfillPassphraseUnlockMethod).toHaveBeenCalledOnce()
  })

  it('keeps the FW-296 order on registryReady: sweep, re-seal repair, torn-retirement, bare-passkey, backfill, annex GC', async () => {
    const fake = await arrangeEnrolledLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()
    await session!.registryReady
    await session!.clientAnnexGcSweep

    expect(state.events).toEqual([
      'user-key-sweep',
      'reseal',
      'torn-retirement',
      'bare-passkey',
      'backfill',
      'annex-gc'
    ])
  })

  it('skips the chain but still settles registryReady when provisioning failed', async () => {
    const fake = await arrangeEnrolledLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    session!.storageReady!.catch(() => {})
    fake.rejectProvisioning(new Error('provisioning exploded'))

    // The rejection propagates through every stage's `.then` (skipping it)
    // and the trailing catch settles the chain for its awaiters.
    await expect(session!.registryReady).resolves.toBeUndefined()
    expect(repairStaleUnlockRegistrySeal).not.toHaveBeenCalled()
    expect(backfillPassphraseUnlockMethod).not.toHaveBeenCalled()
    await expect(session!.storageReady).rejects.toThrow('provisioning exploded')
  })
})
