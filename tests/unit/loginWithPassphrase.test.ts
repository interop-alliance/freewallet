// @vitest-environment node
/**
 * Unit tests for the keyring-v2 login (`loginWithPassphrase` in
 * `src/session/initSession.ts`). The keyring is the only login path: the
 * passphrase resolves through `fetchKeyring` to the account pointer and this
 * client's local key set -- never to any account-reconstructing secret. The
 * keyring module is mocked so the branch matrix (enrolled hit, located but
 * not enrolled, controller mismatch, miss, fetch rejection) runs
 * deterministically; the network-touching boundaries
 * (`StorageManager.initStorageClients`, `ensureKeystore`) are stubbed, while
 * the CapabilityAgent seed derivation runs for real so the controller sanity
 * check exercises the true did:key.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'

vi.mock('@/session/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/keyring')>()),
  fetchKeyring: vi.fn()
}))
vi.mock('@/lib/kms', () => ({ ensureKeystore: vi.fn() }))
vi.mock('@/stores/storageManager', () => ({
  StorageManager: { initStorageClients: vi.fn() }
}))

import { StorageManager } from '@/stores/storageManager'
import { fetchKeyring, KeyringRecordUnusableError } from '@/session/keyring'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import { loginWithPassphrase } from '@/session/initSession'
import { ensureKeystore } from '@/lib/kms'
import { mintPuk } from '@interop/wallet-core/keys'
import { epochKeyIdFor } from '@interop/was-client/edv'

const PASSPHRASE = 'correct horse battery staple'
const POINTER: AccountPointer = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

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
 * The did:key a client seed reconstitutes to under the bootstrap parameters --
 * the identity `initSessionFromSeed` assigns and the controller a valid
 * keyring record carries for its enrolling client.
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
  vi.mocked(fetchKeyring).mockReset()
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

describe('loginWithPassphrase -- enrolled keyring hit', () => {
  it('builds the session from the local client key set', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      pointer: POINTER,
      clientKeys: { clientSeed },
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

  it('stamps the account pointer on the profile', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      pointer: POINTER,
      clientKeys: { clientSeed },
      unlockSpaceId: 'unlock-space-test'
    })

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })

    expect(session!.profile.accountPointer).toEqual(POINTER)
  })

  it('makes the recovered PUK recipient zero (the profile KAK) and carries it on the profile', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    const puk = await mintPuk()
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      clientKeys: { clientSeed, puk },
      unlockSpaceId: 'unlock-space-test'
    })

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })

    const { profile } = vi.mocked(StorageManager.initStorageClients).mock
      .calls[0][0]
    expect(profile.keyAgreementKey!.id).toBe(epochKeyIdFor(puk.id))
    expect(session!.profile.puk).toBe(puk)
  })

  it('keeps the seed-derived KAK for a legacy record with no PUK', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      clientKeys: { clientSeed },
      unlockSpaceId: 'unlock-space-test'
    })

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })

    const { profile } = vi.mocked(StorageManager.initStorageClients).mock
      .calls[0][0]
    // The legacy vault KAK is the Montgomery twin of the signing key, so its
    // id is rooted in the account's own did:key controller.
    expect(profile.keyAgreementKey!.id.startsWith(controller)).toBe(true)
    expect(session!.profile.puk).toBeUndefined()
  })

  it('fires ensureUserCollections as storageReady by default', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      clientKeys: { clientSeed },
      unlockSpaceId: 'unlock-space-test'
    })

    const { session } = await loginWithPassphrase({ passphrase: PASSPHRASE })

    expect(fakeStorage.ensureUserCollections).toHaveBeenCalledOnce()
    expect(session!.storageReady).toBeInstanceOf(Promise)
  })

  it('forwards provisionStorage: false (the signup probe) to skip provisioning', async () => {
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      clientKeys: { clientSeed },
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
    const clientSeed = randomSeed()
    const controller = await didFromSeed(clientSeed)
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller,
      clientKeys: { clientSeed },
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
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller: 'did:key:z6MkWrongControllerForThisSeed',
      clientKeys: { clientSeed: randomSeed() },
      unlockSpaceId: 'unlock-space-test'
    })

    await expect(
      loginWithPassphrase({ passphrase: PASSPHRASE })
    ).rejects.toThrow(KeyringRecordUnusableError)
  })
})

describe('loginWithPassphrase -- located but not enrolled', () => {
  it('returns a null session and userExists: true when this client holds no key set', async () => {
    // The passphrase located the account (the record exists and unwraps) but
    // there are no local client keys: unlocking is not sufficient to BE the
    // account, so no session is built and storage is never touched.
    vi.mocked(fetchKeyring).mockResolvedValue({
      controller: 'did:key:z6MkDataControllerForTests',
      pointer: POINTER,
      unlockSpaceId: 'unlock-space-test'
    })

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE
    })

    expect(session).toBeNull()
    expect(userExists).toBe(true)
    expect(StorageManager.initStorageClients).not.toHaveBeenCalled()
  })
})

describe('loginWithPassphrase -- keyring miss', () => {
  it('returns a null session and userExists: false when no keyring exists', async () => {
    vi.mocked(fetchKeyring).mockResolvedValue(null)

    const { session, userExists } = await loginWithPassphrase({
      passphrase: PASSPHRASE
    })

    expect(session).toBeNull()
    expect(userExists).toBe(false)
    expect(StorageManager.initStorageClients).not.toHaveBeenCalled()
  })
})

describe('loginWithPassphrase -- fetch failure', () => {
  it('propagates a fetchKeyring rejection (e.g. remote unreachable)', async () => {
    vi.mocked(fetchKeyring).mockRejectedValue(new Error('storage unreachable'))

    await expect(
      loginWithPassphrase({ passphrase: PASSPHRASE })
    ).rejects.toThrow('storage unreachable')
    expect(StorageManager.initStorageClients).not.toHaveBeenCalled()
  })
})
