// @vitest-environment node
/**
 * Unit tests for the remembered login's mender block
 * (`src/session/menders/`, started from `src/session/initSession.ts`): the
 * registry-writing registrations settle `session.registryReady` while
 * `session.storageReady` stays the raw provisioning promise, so a login page
 * can navigate as soon as the collections are ready. The block keeps one
 * total order (the provisioning seed, the user key sweep, the four shared
 * registry passes, the standing-delegation refresh, the ladder-rung
 * refresh, the pointer heal, the generation-delegation heal, then the
 * app-key sweep, the annex GC and the keystore report), is abandoned when
 * provisioning itself
 * failed, and neither promise rejects. The order pin reads
 * `session.mends`, which carries one entry per invariant every registration
 * reported, so it covers the whole block rather than the passes that
 * happen to log.
 * The keyring and every remote seam are mocked; the seed-to-identity
 * derivation runs for real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { CapabilityAgent } from '@interop/capability-agent'

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
    return { skipped: 'not-enrolled' }
  })
}))
vi.mock('@/session/appKeySweep', () => ({
  sweepStrandedAppKeys: vi.fn(async () => {
    state.events.push('app-key-sweep')
    return { deleted: 0, retracted: 0 }
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
import { sweepStrandedAppKeys } from '@/session/appKeySweep'
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
    // The real manager keeps the keystore promotion it fires rather than
    // handing it back, and the block's tail reports it from there.
    ensurePromotedController: vi.fn(async () => {
      ;(
        storage as unknown as {
          keystorePromotion?: Promise<{ outcome: string }>
        }
      ).keystorePromotion = Promise.resolve({ outcome: 'clean' as const })
      return { promoted: true }
    }),
    // Where the real manager keeps the promotion storage provisioning fired,
    // read by the block's tail when the pointer heal fired none.
    keystorePromotion: undefined as Promise<{ outcome: string }> | undefined,
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

/**
 * The unpromoted account the pointer heal converges: an unlock record still
 * serving the signup-time did:key, with the account DID landing on the
 * profile at provisioning (where the log is published or adopted).
 */
async function arrangeUnpromotedLogin() {
  const clientSeed = randomSeed()
  const controller = await didFromSeed(clientSeed)
  const userKey = await mintUserKey()
  const persistAccountPointer = vi.fn(async () => undefined)
  const stale = { ...POINTER, did: controller }
  vi.mocked(fetchKeyring).mockResolvedValue({
    controller,
    pointer: stale,
    persistAccountPointer,
    clientKeys: {
      clientSeed,
      userKey,
      webvhUpdateKeys: { updateSeed: randomSeed(), stagedSeed: randomSeed() },
      controller,
      pointerDid: stale.did
    },
    unlockSpaceId: 'unlock-space-test',
    createdAt: new Date().toISOString()
  } as never)
  const fake = makeFakeStorage()
  vi.mocked(fake.storage.ensureUserCollections).mockImplementation((({
    profile
  }: {
    profile: { didWebvh?: { did: string } }
  }) => {
    profile.didWebvh = { did: POINTER.did }
    return Promise.resolve()
  }) as never)
  vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
    storage: fake.storage,
    userExists: true
  } as never)
  return { fake, stale, persistAccountPointer }
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
  vi.mocked(sweepStrandedAppKeys).mockImplementation(async () => {
    state.events.push('app-key-sweep')
    return { deleted: 0, retracted: 0 }
  })
  vi.mocked(routeUnlockLogin).mockImplementation((async ({
    credential
  }: {
    credential?: unknown
  }) => ({
    login: 'remembered',
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

  it('keeps one total order over the whole block, and every registration reports', async () => {
    const fake = await arrangeEnrolledLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()
    await session!.registryReady
    const report = (await session!.mends)!

    // The passes that log, in the order the block ran them.
    expect(state.events).toEqual([
      'user-key-sweep',
      'reseal',
      'torn-retirement',
      'bare-passkey',
      'backfill',
      'app-key-sweep',
      'annex-gc'
    ])
    // The routing entry the login fired, then every registration of the
    // block, by the invariants it reports: the provisioning seed, the sweep's two, the four shared passes, the two
    // standing refreshes, the pointer heal's two, the generation-delegation
    // heal, then the tail -- the two sweeps and the keystore report. A
    // registration that stopped reporting would drop its ids from this
    // list.
    expect(report.map(entry => entry.invariant)).toEqual([
      // The routing entry this login fired: the forgotten-browser detector
      // stood down on a log it could not verify (nothing serves one here).
      'this-browser-is-still-an-enrolled-client',
      'standard-collections-are-provisioned',
      'roster-wraps-exactly-the-document-key-set',
      'collection-epochs-name-the-current-user-key',
      'unlock-registry-opens-under-the-current-user-key',
      'registry-passphrase-entry-names-the-standing-credential',
      'passkey-entry-carries-its-standing-configuration',
      'registry-lists-the-passphrase-method',
      'standing-delegations-verify-under-the-current-document',
      'registry-records-the-committed-ladder-rung',
      'account-pointer-names-the-account-did',
      'space-controller-is-the-account-did',
      'generation-delegation-is-current',
      'app-keys-live-only-in-app-connections',
      'no-annex-generation-outlives-its-pointer',
      'keystore-controller-is-the-account-did'
    ])
    // `registryReady` settles at the registry-writing registrations' last
    // entry, and `mends` behind the two tail sweeps.
    expect(
      report.findIndex(
        entry => entry.invariant === 'generation-delegation-is-current'
      )
    ).toBeLessThan(
      report.findIndex(
        entry => entry.invariant === 'app-keys-live-only-in-app-connections'
      )
    )
  })

  it('settles registryReady before the tail sweeps have run', async () => {
    const fake = await arrangeEnrolledLogin()
    let releaseSweep!: () => void
    vi.mocked(sweepStrandedAppKeys).mockImplementation(
      () =>
        new Promise<{ deleted: number; retracted: number }>(resolve => {
          releaseSweep = () => {
            state.events.push('app-key-sweep')
            resolve({ deleted: 0, retracted: 0 })
          }
        })
    )

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()
    await session!.registryReady
    expect(await settled(session!.mends)).toBe(false)
    expect(state.events).not.toContain('app-key-sweep')

    releaseSweep()
    await session!.mends
    expect(state.events).toContain('annex-gc')
  })

  it('runs the pointer heal on an unpromoted account, and reports its predicates', async () => {
    const { stale, persistAccountPointer } = await arrangeUnpromotedLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    await session!.registryReady
    const report = (await session!.mends)!

    expect(persistAccountPointer).toHaveBeenCalledWith({
      ...stale,
      did: POINTER.did
    })
    expect(session!.storage.ensurePromotedController).toHaveBeenCalledWith({
      profile: session!.profile
    })
    for (const invariant of [
      'account-pointer-names-the-account-did',
      'space-controller-is-the-account-did',
      'keystore-controller-is-the-account-did'
    ]) {
      expect(
        report.find(entry => entry.invariant === invariant),
        invariant
      ).toMatchObject({ outcome: 'clean' })
    }
  })

  it('settles registryReady without waiting on the keystore promotion', async () => {
    const { fake } = await arrangeUnpromotedLogin()
    // A KMS round trip that never answers: the keystore report sits in the
    // block's tail, so `registryReady` (which every Settings ceremony
    // awaits) settles regardless, and `session.mends` is what waits.
    let releaseKeystore!: () => void
    vi.mocked(fake.storage.ensurePromotedController).mockImplementation(
      async () => {
        ;(
          fake.storage as unknown as {
            keystorePromotion?: Promise<{ outcome: string }>
          }
        ).keystorePromotion = new Promise(resolve => {
          releaseKeystore = () => resolve({ outcome: 'clean' as const })
        })
        return { promoted: true }
      }
    )

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()
    await session!.registryReady
    expect(await settled(session!.mends)).toBe(false)

    releaseKeystore()
    const report = (await session!.mends)!
    expect(
      report.find(
        entry => entry.invariant === 'keystore-controller-is-the-account-did'
      )
    ).toMatchObject({ outcome: 'clean' })
  })

  it('reports the promotion provisioning fired when the pointer heal fired none', async () => {
    const fake = await arrangeEnrolledLogin()
    // A promoted pointer: the heal is a no-op and hands the block nothing,
    // while provisioning's own `ensurePromotedController` fired the keystore
    // promotion and the manager kept it.
    ;(
      fake.storage as unknown as {
        keystorePromotion?: Promise<{ outcome: string }>
      }
    ).keystorePromotion = Promise.resolve({ outcome: 'clean' })

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()
    const report = (await session!.mends)!

    expect(
      report.find(
        entry => entry.invariant === 'keystore-controller-is-the-account-did'
      )
    ).toMatchObject({ outcome: 'clean' })
  })

  it('reports no promotion when neither the heal nor provisioning ran one', async () => {
    const fake = await arrangeEnrolledLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()
    const report = (await session!.mends)!

    expect(
      report.find(
        entry => entry.invariant === 'keystore-controller-is-the-account-did'
      )
    ).toMatchObject({ outcome: 'noop', detail: { reason: 'no-promotion' } })
  })

  it('abandons the block but still settles both promises when provisioning failed', async () => {
    const fake = await arrangeEnrolledLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    session!.storageReady!.catch(() => {})
    fake.rejectProvisioning(new Error('provisioning exploded'))

    // The seed's failure aborts the block, and both promises settle for
    // their awaiters. The two tail sweeps are behind that gate now, so a
    // session whose provisioning was refused runs neither.
    await expect(session!.registryReady).resolves.toBeUndefined()
    expect(repairStaleUnlockRegistrySeal).not.toHaveBeenCalled()
    expect(backfillPassphraseUnlockMethod).not.toHaveBeenCalled()
    expect(state.events).toEqual([])
    expect((await session!.mends)!.map(entry => entry.outcome)).toEqual([
      // The detector's stand-down, then the seed's failure.
      'refused',
      'failed'
    ])
    await expect(session!.storageReady).rejects.toThrow('provisioning exploded')
  })
})
