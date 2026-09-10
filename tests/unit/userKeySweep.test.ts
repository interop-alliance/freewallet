// @vitest-environment node
/**
 * Unit tests for the login-time cascade-completion sweep in
 * `src/session/userKeySweep.ts`: its two stages (the roster convergence onto
 * the account's verified document, then the collection fan-out under the key
 * that convergence settled on), and its wiring as the first registration of
 * the remembered login's mender block.
 *
 * The block's seed is storage provisioning, so the sweep runs behind it and a
 * rejected provisioning aborts the block before the sweep is reached. With
 * nothing to sweep from (no roster yet, an offline roster check, no remote
 * store, a guest) the registration fires no cascade and reports both of its
 * invariants `noop`; a throwing sweep is caught by the runner, which warns and
 * reports both `failed`. The seed-to-identity derivation runs for real; every
 * remote and browser-local seam is mocked.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent } from '@interop/capability-agent'

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

// The two seams a passphrase login reaches before the session exists: the
// keyring hit, and the post-KDF routing that decides the remembered chain.
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

// The rest of the remembered block, stood down to its quiet reading: this
// file asserts on the sweep registration's own two entries, and every other
// registration's behavior is its own test file's.
vi.mock('@/session/registryPasses', () => ({
  promotedAccountPointer: vi.fn(() => null),
  promotedAccountView: vi.fn(async () => null),
  blockRegistryRead: vi.fn(() => ({
    read: async () => null,
    invalidate: () => undefined
  })),
  resealRegistryPass: vi.fn(async () => ({ outcome: 'noop' })),
  tornRetirementPass: vi.fn(async () => ({ outcome: 'noop' })),
  barePasskeyPass: vi.fn(async () => ({ outcome: 'noop' })),
  backfillRegistryPass: vi.fn(async () => ({ outcome: 'noop' }))
}))
vi.mock('@/session/pointerHeal', () => ({
  healAccountPointer: vi.fn(async () => ({
    pointer: { outcome: 'noop' },
    controller: { outcome: 'noop' }
  }))
}))
vi.mock('@/session/appKeySweep', () => ({
  sweepStrandedAppKeys: vi.fn(async () => ({ deleted: 0, retracted: 0 }))
}))
vi.mock('@/session/clientAnnexGc', () => ({
  sweepClientAnnexGenerations: vi.fn(async () => ({ skipped: 'no-annex' }))
}))

import {
  checkUserKeyRosterAtLogin,
  convergeUserKeyRosterToAccount
} from '@interop/wallet-core/clients'
import { cascadeCollectionsToUserKey } from '@/session/userKeyCascade'
import { fetchKeyring } from '@/session/keyring'
import { routeUnlockLogin } from '@/session/transientLogin'
import { StorageManager } from '@/stores/storageManager'
import { initSessionFromSeed, loginWithPassphrase } from '@/session/initSession'
import { sweepUserKeyToDocument } from '@/session/userKeySweep'
import type { Session } from '@/types/auth'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

const PASSPHRASE = 'correct horse battery staple'
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

/**
 * The two invariants the sweep registration reports, in report order.
 */
const ROSTER_INVARIANT = 'roster-wraps-exactly-the-document-key-set'
const COLLECTIONS_INVARIANT = 'collection-epochs-name-the-current-user-key'

function rosterRead({ rotated = false } = {}) {
  return {
    descriptor: ROSTER_DESCRIPTOR,
    userKey: rotated ? FRESH_USER_KEY : OLD_USER_KEY,
    rotated,
    latestEpochId: rotated ? FRESH_USER_KEY.id : OLD_USER_KEY.id
  }
}

/**
 * The sweep's own entries in this session's mend report, by invariant.
 *
 * @param session {Session}
 * @returns {Promise<object>}   the roster-stage entry and the fan-out entry,
 *   each undefined when the block never reached the registration
 */
async function sweepEntries(session: Session) {
  const report = (await session.mends) ?? []
  return {
    roster: report.find(entry => entry.invariant === ROSTER_INVARIANT),
    collections: report.find(entry => entry.invariant === COLLECTIONS_INVARIANT)
  }
}

/**
 * A storage stub whose `ensureUserCollections` promise the test controls, so
 * ordering ("the sweep waits for the block's provisioning seed") is
 * observable.
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
  const holdRotatedVaultKeys = vi.fn(() => undefined)
  const storage = {
    ensureUserCollections: vi.fn(() => provisioning),
    refreshEncryptedDescriptors,
    adoptRotatedVaultKeys,
    holdRotatedVaultKeys,
    get remoteStore() {
      return withRemote ? remoteStore : undefined
    }
  } as unknown as StorageManager
  return {
    storage,
    remoteStore,
    refreshEncryptedDescriptors,
    adoptRotatedVaultKeys,
    holdRotatedVaultKeys,
    resolveProvisioning,
    rejectProvisioning
  }
}

function randomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

async function didFromSeed(seed: Uint8Array): Promise<string> {
  const agent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'bootstrap',
    keyName: 'boostrap-key'
  })
  return agent.id
}

/**
 * Arranges a passphrase login that routes remembered on an enrolled record,
 * so `loginWithPassphrase` builds the session and starts the mender block the
 * sweep is registered in.
 *
 * @param [options] {object}
 * @param [options.withRemote] {boolean}   whether the storage stub exposes a
 *   remote store
 * @returns {Promise<object>}   the storage stub, whose provisioning promise
 *   the test releases
 */
async function arrangeRememberedLogin({ withRemote = true } = {}) {
  const clientSeed = randomSeed()
  const controller = await didFromSeed(clientSeed)
  vi.mocked(fetchKeyring).mockResolvedValue({
    controller,
    pointer: POINTER,
    // The ENROLLED shape: a record missing any of the four members would
    // route into the pending-record resume instead of the ordinary login.
    clientKeys: {
      clientSeed,
      userKey: OLD_USER_KEY,
      webvhUpdateKeys: { updateSeed: randomSeed(), stagedSeed: randomSeed() },
      controller,
      pointerDid: POINTER.did
    },
    unlockSpaceId: 'unlock-space-test',
    createdAt: new Date().toISOString()
  } as never)
  const fake = makeFakeStorage({ withRemote })
  vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
    storage: fake.storage,
    userExists: true
  } as never)
  return fake
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
  vi.mocked(cascadeCollectionsToUserKey).mockResolvedValue({
    outcomes: {},
    failed: []
  })
  vi.mocked(routeUnlockLogin).mockImplementation((async ({
    credential
  }: {
    credential?: unknown
  }) => ({
    login: 'remembered',
    ...(credential ? { credential } : {})
  })) as never)
  convergenceLeavesInputUnchanged()
})

describe('the login-time cascade-completion sweep', () => {
  it('fires the cascade behind the block provisioning seed', async () => {
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )
    const fake = await arrangeRememberedLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })

    // The sweep is chained behind the block's seed: nothing runs until
    // `ensureUserCollections` settles.
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(vi.mocked(cascadeCollectionsToUserKey)).not.toHaveBeenCalled()

    fake.resolveProvisioning()
    const entries = await sweepEntries(session!)
    expect(entries.roster).toMatchObject({ outcome: 'noop' })
    expect(entries.collections).toMatchObject({ outcome: 'noop' })
    expect(
      vi.mocked(cascadeCollectionsToUserKey)
    ).toHaveBeenCalledExactlyOnceWith({
      remoteStore: fake.remoteStore,
      // Each collection's log-governed descriptor store, built for this
      // session so the sweep's appends sign with a key the account document
      // lists.
      storeFor: expect.any(Function),
      rosterDescriptor: ROSTER_DESCRIPTOR,
      clientKeyAgreementKey: session!.profile.clientKeyAgreementKey,
      userKey: OLD_USER_KEY
    })
  })

  it('reports the roster mended when the convergence only escrowed wraps', async () => {
    // The mender for an enrollment torn between the document entry and the
    // roster append: nothing rotates, and the login that completed the
    // escrow is the login that repaired the roster.
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )
    vi.mocked(convergeUserKeyRosterToAccount).mockImplementation((async ({
      userKey,
      descriptor
    }: {
      userKey: unknown
      descriptor: unknown
    }) => ({
      rotated: false,
      sealed: false,
      staleRecipientIds: [],
      escrowedRecipientIds: ['did:key:z6LSTornClient#kak'],
      userKey,
      descriptor
    })) as never)
    const fake = await arrangeRememberedLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()

    const entries = await sweepEntries(session!)
    expect(entries.roster).toMatchObject({
      outcome: 'clean',
      detail: { escrowedRecipients: 1 }
    })
  })

  it('reports the roster mended when the convergence only sealed the log', async () => {
    // The seal backstop: a torn revocation whose rotation no-op'd leaves the
    // roster log's head anchored before the membership change, and the
    // backstop's append is the mend.
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )
    vi.mocked(convergeUserKeyRosterToAccount).mockImplementation((async ({
      userKey,
      descriptor
    }: {
      userKey: unknown
      descriptor: unknown
    }) => ({
      rotated: false,
      sealed: true,
      staleRecipientIds: [],
      escrowedRecipientIds: [],
      userKey,
      descriptor
    })) as never)
    const fake = await arrangeRememberedLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()

    const entries = await sweepEntries(session!)
    expect(entries.roster).toMatchObject({
      outcome: 'clean',
      detail: { sealed: true }
    })
    // The fan-out is a separate predicate: nothing moved an epoch here.
    expect(entries.collections).toMatchObject({ outcome: 'noop' })
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

    const {
      session,
      rosterRead: read,
      rosterStore
    } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER,
      persistClientKeys
    })
    expect(persistClientKeys).toHaveBeenCalledExactlyOnceWith({
      userKey: FRESH_USER_KEY
    })

    await sweepUserKeyToDocument({
      session,
      store: rosterStore!,
      userKey: session.profile.userKey!,
      read: read!
    })
    expect(
      vi.mocked(cascadeCollectionsToUserKey)
    ).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ userKey: FRESH_USER_KEY })
    )
  })

  it('does not sweep when provisioning itself failed (the seed aborts the block)', async () => {
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )
    const fake = await arrangeRememberedLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    session!.storageReady?.catch(() => {})
    fake.rejectProvisioning(new Error('provisioning down'))

    // Provisioning is the remembered block's seed, and a rejected seed ends
    // the block: the session is abandoned by the login surface, so none of
    // the sweep's governed writes is wanted on it. The registration is never
    // entered, so it reports nothing at all.
    const entries = await sweepEntries(session!)
    expect(entries.roster).toBeUndefined()
    expect(entries.collections).toBeUndefined()
    expect(vi.mocked(cascadeCollectionsToUserKey)).not.toHaveBeenCalled()
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

    const {
      session,
      rosterRead: read,
      rosterStore
    } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    await sweepUserKeyToDocument({
      session,
      store: rosterStore!,
      userKey: session.profile.userKey!,
      read: read!
    })
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

    const {
      session,
      rosterRead: read,
      rosterStore
    } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    await sweepUserKeyToDocument({
      session,
      store: rosterStore!,
      userKey: session.profile.userKey!,
      read: read!
    })
    expect(fake.refreshEncryptedDescriptors).not.toHaveBeenCalled()
  })

  it('reports both invariants failed when the sweep itself throws', async () => {
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )
    vi.mocked(cascadeCollectionsToUserKey).mockRejectedValue(
      new Error('sweep broke')
    )
    const fake = await arrangeRememberedLogin()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()

    // The runner catches the throw, warns once per reported invariant, and
    // carries the block on. Only the error's name rides the report: a
    // message routinely carries a DID or a Space id.
    const entries = await sweepEntries(session!)
    expect(entries.roster).toMatchObject({
      outcome: 'failed',
      errorName: 'Error'
    })
    expect(entries.collections).toMatchObject({
      outcome: 'failed',
      errorName: 'Error'
    })
    warn.mockRestore()
  })

  it('does not fire without a roster (an account provisioning has not created one)', async () => {
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(null)
    const fake = await arrangeRememberedLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()

    const entries = await sweepEntries(session!)
    expect(entries.roster).toMatchObject({
      outcome: 'noop',
      detail: { reason: 'nothing-to-sweep-from' }
    })
    expect(entries.collections).toMatchObject({
      outcome: 'noop',
      detail: { reason: 'nothing-to-sweep-from' }
    })
    expect(vi.mocked(cascadeCollectionsToUserKey)).not.toHaveBeenCalled()
  })

  it('does not fire when the roster check was offline (cached user key kept)', async () => {
    // An unreachable server is the roster policy's own swallow: it keeps the
    // cached key authoritative and reports no read at all.
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(null)
    const fake = await arrangeRememberedLogin()

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()

    const entries = await sweepEntries(session!)
    expect(entries.roster).toMatchObject({ outcome: 'noop' })
    expect(entries.collections).toMatchObject({ outcome: 'noop' })
    expect(vi.mocked(cascadeCollectionsToUserKey)).not.toHaveBeenCalled()
    expect(session!.profile.userKey).toEqual(OLD_USER_KEY)
  })

  it('does not fire without a remote store', async () => {
    vi.mocked(checkUserKeyRosterAtLogin).mockResolvedValue(
      rosterRead() as never
    )
    const fake = await arrangeRememberedLogin({ withRemote: false })

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })
    fake.resolveProvisioning()

    const entries = await sweepEntries(session!)
    expect(entries.roster).toMatchObject({
      outcome: 'noop',
      detail: { reason: 'nothing-to-sweep-from' }
    })
    expect(entries.collections).toMatchObject({
      outcome: 'noop',
      detail: { reason: 'nothing-to-sweep-from' }
    })
    expect(vi.mocked(cascadeCollectionsToUserKey)).not.toHaveBeenCalled()
  })

  it('does not fire for a guest session (no roster read at all)', async () => {
    const fake = makeFakeStorage()
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fake.storage,
      userExists: false
    })

    // A guest builds no mender block, so its report is the settled empty one
    // every block-less session carries.
    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      isGuest: true
    })
    expect(vi.mocked(checkUserKeyRosterAtLogin)).not.toHaveBeenCalled()
    expect(await session.mends).toEqual([])
    expect(vi.mocked(cascadeCollectionsToUserKey)).not.toHaveBeenCalled()
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
    expect(await session.mends).toEqual([])
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

    const {
      session,
      rosterRead: read,
      rosterStore
    } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER,
      persistClientKeys
    })
    await sweepUserKeyToDocument({
      session,
      store: rosterStore!,
      userKey: session.profile.userKey!,
      read: read!
    })

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
    // The fresh key is adopted -- persisted for the next login, held by the
    // live session -- and the fan-out runs against it. The ciphers move only
    // once the fan-out has, on the refresh below.
    expect(persistClientKeys).toHaveBeenCalledWith({ userKey: FRESH_USER_KEY })
    expect(session.profile.userKey).toEqual(FRESH_USER_KEY)
    expect(fake.holdRotatedVaultKeys).toHaveBeenCalledOnce()
    expect(fake.adoptRotatedVaultKeys).not.toHaveBeenCalled()
    expect(fake.refreshEncryptedDescriptors).toHaveBeenCalledOnce()
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

    const {
      session,
      rosterRead: read,
      rosterStore
    } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    await sweepUserKeyToDocument({
      session,
      store: rosterStore!,
      userKey: session.profile.userKey!,
      read: read!
    })

    expect(vi.mocked(convergeUserKeyRosterToAccount)).toHaveBeenCalledOnce()
    expect(fake.holdRotatedVaultKeys).not.toHaveBeenCalled()
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

    const {
      session,
      rosterRead: read,
      rosterStore
    } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: POINTER
    })
    await sweepUserKeyToDocument({
      session,
      store: rosterStore!,
      userKey: session.profile.userKey!,
      read: read!
    })

    expect(fake.holdRotatedVaultKeys).not.toHaveBeenCalled()
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

    const { rosterRead: read, rosterStore } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: OLD_USER_KEY,
      accountPointer: { ...POINTER, did: undefined }
    })

    // The roster read itself requires a pointer that names the account DID
    // (the epoch-signature check resolves the signer against the account
    // log), so a did-less pointer skips the read -- and with neither a read
    // nor the store it came through, the sweep registration has nothing to
    // sweep from.
    expect(vi.mocked(checkUserKeyRosterAtLogin)).not.toHaveBeenCalled()
    expect(read).toBeNull()
    expect(rosterStore).toBeUndefined()
    expect(vi.mocked(convergeUserKeyRosterToAccount)).not.toHaveBeenCalled()
    expect(vi.mocked(cascadeCollectionsToUserKey)).not.toHaveBeenCalled()
  })
})
