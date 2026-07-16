// @vitest-environment node
/**
 * Unit tests for the keyring-v2 login (`loginWithPassphrase` in
 * `src/session/initSession.ts`). The keyring is the only login path: the
 * passphrase resolves through `fetchKeyringSeed` to the account's real data
 * seed. The keyring module is mocked so the branch matrix (keyring hit,
 * controller mismatch, miss, fetch rejection) runs deterministically; the
 * network-touching boundaries (`StorageManager.initStorageClients`,
 * `ensureKeystore`) are stubbed, while the CapabilityAgent seed derivation runs
 * for real so the controller sanity check exercises the true did:key.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'

vi.mock('@/session/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/keyring')>()),
  fetchKeyringSeed: vi.fn()
}))
vi.mock('@/lib/kms', () => ({ ensureKeystore: vi.fn() }))
vi.mock('@/stores/storageManager', () => ({
  StorageManager: { initStorageClients: vi.fn() }
}))

import { StorageManager } from '@/stores/storageManager'
import { fetchKeyringSeed, KeyringRecordUnusableError } from '@/session/keyring'
import { loginWithPassphrase } from '@/session/initSession'
import { ensureKeystore } from '@/lib/kms'

const PASSPHRASE = 'correct horse battery staple'

/**
 * A storage stub carrying the `ensureUserCollections` seam that session
 * creation fires (as `session.storageReady`).
 */
function makeFakeStorage() {
  return {
    isFakeStorage: true,
    ensureUserCollections: vi.fn().mockResolvedValue(undefined)
  } as unknown as StorageManager
}
let fakeStorage = makeFakeStorage()

/**
 * The did:key a seed reconstitutes to under the bootstrap parameters -- the
 * identity `initSessionFromSeed` assigns and the controller a valid keyring
 * record carries.
 */
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

beforeEach(() => {
  fakeStorage = makeFakeStorage()
  vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
    storage: fakeStorage,
    userExists: false
  })
  vi.mocked(ensureKeystore).mockResolvedValue(undefined as never)
  vi.mocked(fetchKeyringSeed).mockReset()
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

describe('loginWithPassphrase -- keyring hit', () => {
  it('builds the session from the unwrapped seed', async () => {
    const seed = randomSeed()
    const controller = await didFromSeed(seed)
    vi.mocked(fetchKeyringSeed).mockResolvedValue({
      seed,
      controller,
      unlockSpaceId: 'unlock-space-test'
    })
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fakeStorage,
      userExists: true
    })

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE
    })

    expect(session).not.toBeNull()
    expect(session!.user.id).toBe(controller)
    expect(userExists).toBe(true)
  })

  it('fires ensureUserCollections as storageReady by default', async () => {
    const seed = randomSeed()
    const controller = await didFromSeed(seed)
    vi.mocked(fetchKeyringSeed).mockResolvedValue({
      seed,
      controller,
      unlockSpaceId: 'unlock-space-test'
    })

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })

    expect(fakeStorage.ensureUserCollections).toHaveBeenCalledOnce()
    expect(session!.storageReady).toBeInstanceOf(Promise)
  })

  it('forwards provisionStorage: false (the signup probe) to skip provisioning', async () => {
    const seed = randomSeed()
    const controller = await didFromSeed(seed)
    vi.mocked(fetchKeyringSeed).mockResolvedValue({
      seed,
      controller,
      unlockSpaceId: 'unlock-space-test'
    })

    const { session } = await loginWithPassphrase({
      passphrase: PASSPHRASE,
      provisionStorage: false
    })

    expect(fakeStorage.ensureUserCollections).not.toHaveBeenCalled()
    expect(session!.storageReady).toBeUndefined()
  })

  it('reports userExists: false when the data Space is missing (half-finished signup)', async () => {
    const seed = randomSeed()
    const controller = await didFromSeed(seed)
    vi.mocked(fetchKeyringSeed).mockResolvedValue({
      seed,
      controller,
      unlockSpaceId: 'unlock-space-test'
    })
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fakeStorage,
      userExists: false
    })

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE
    })

    expect(session).not.toBeNull()
    expect(userExists).toBe(false)
  })

  it('throws on a controller / identity mismatch (corrupt record)', async () => {
    vi.mocked(fetchKeyringSeed).mockResolvedValue({
      seed: randomSeed(),
      controller: 'did:key:z6MkWrongControllerForThisSeed',
      unlockSpaceId: 'unlock-space-test'
    })

    await expect(
      loginWithPassphrase({ passphrase: PASSPHRASE })
    ).rejects.toThrow(KeyringRecordUnusableError)
  })
})

describe('loginWithPassphrase -- keyring miss', () => {
  it('returns a null session and userExists: false when no keyring exists', async () => {
    vi.mocked(fetchKeyringSeed).mockResolvedValue(null)

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE
    })

    expect(session).toBeNull()
    expect(userExists).toBe(false)
    expect(StorageManager.initStorageClients).not.toHaveBeenCalled()
  })
})

describe('loginWithPassphrase -- fetch failure', () => {
  it('propagates a fetchKeyringSeed rejection (e.g. remote unreachable)', async () => {
    vi.mocked(fetchKeyringSeed).mockRejectedValue(
      new Error('storage unreachable')
    )

    await expect(
      loginWithPassphrase({ passphrase: PASSPHRASE })
    ).rejects.toThrow('storage unreachable')
    expect(StorageManager.initStorageClients).not.toHaveBeenCalled()
  })
})
