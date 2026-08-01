// @vitest-environment node
/**
 * Unit tests for the session bootstrap (`src/session/initSession.ts`):
 * seed-to-identity derivation via CapabilityAgent, the zcap-agent and
 * key-material wiring on the profile, guest vs regular sessions,
 * `userExists` reporting, and KMS keystore provisioning (wired
 * when configured, non-fatal on failure). The network-touching boundaries --
 * `StorageManager.initStorageClients` (IndexedDB + WAS) and `ensureKeystore`
 * (WebKMS) -- are stubbed; the CapabilityAgent / ZcapClient / key-agreement
 * derivation runs for real, since it is pure and deterministic in node.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import { ZcapClient } from '@interop/ezcap'

/**
 * The KMS server url the bootstrap reads from app.config, made mutable so a
 * single test can drop it to exercise the "no KMS configured" branch. The
 * mock exposes it through a getter so the module's live binding sees changes.
 */
const KMS_SERVER_URL = 'https://kms.example.test/kms'
let kmsServerUrl: string | undefined = KMS_SERVER_URL

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get KMS_SERVER_URL() {
    return kmsServerUrl
  }
}))
vi.mock('@/lib/kms', () => ({ ensureKeystore: vi.fn() }))
vi.mock('@/stores/storageManager', () => ({
  StorageManager: { initStorageClients: vi.fn() }
}))

import { ensureKeystore } from '@/lib/kms'
import { StorageManager } from '@/stores/storageManager'
import { agentsFromSeed } from '@interop/wallet-core/identity'
import { initGuestSession, initSessionFromSeed } from '@/session/initSession'

const KEYSTORE_ID = `${KMS_SERVER_URL}/keystores/z6QkKeystore`

function randomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

/**
 * Independently derives the did:key the bootstrap should assign, using the
 * exact CapabilityAgent parameters `agentsFromSeed` uses.
 */
async function expectedDid(seed: Uint8Array): Promise<string> {
  const agent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'bootstrap',
    keyName: 'boostrap-key'
  })
  return agent.id
}

/**
 * A storage stub carrying the `ensureUserCollections` seam that session
 * creation now fires (as `session.storageReady`). Each call returns a fresh
 * one so the spy assertions are per-test.
 */
function makeFakeStorage() {
  return {
    isFakeStorage: true,
    ensureUserCollections: vi.fn().mockResolvedValue(undefined)
  } as unknown as StorageManager
}
let fakeStorage = makeFakeStorage()

beforeEach(() => {
  kmsServerUrl = KMS_SERVER_URL
  fakeStorage = makeFakeStorage()
  vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
    storage: fakeStorage,
    userExists: false
  })
  vi.mocked(ensureKeystore).mockResolvedValue({
    keystoreId: KEYSTORE_ID
  } as never)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

describe('agentsFromSeed', () => {
  it('derives the identity, zcap client, and key-agreement material', async () => {
    const seed = randomSeed()
    const { keyAgent, zcapClient, keyAgreementKey, keyResolver } =
      await agentsFromSeed({ seed })

    expect(keyAgent.id).toBe(await expectedDid(seed))
    expect(keyAgent.id).toMatch(/^did:key:z6Mk/)
    expect(zcapClient).toBeInstanceOf(ZcapClient)
    // The X25519 key-agreement key is derived under the same did:key DID.
    expect(keyAgreementKey.id).toContain(keyAgent.id)
    expect(keyResolver).toBeInstanceOf(Function)
  })

  it('is deterministic: the same seed yields the same did:key', async () => {
    const seed = randomSeed()
    const first = await agentsFromSeed({ seed })
    const second = await agentsFromSeed({ seed })
    expect(second.keyAgent.id).toBe(first.keyAgent.id)
    expect(second.keyAgreementKey.id).toBe(first.keyAgreementKey.id)
  })

  it('resolves its own key-agreement key id and rejects any other', async () => {
    const { keyAgreementKey, keyResolver } = await agentsFromSeed({
      seed: randomSeed()
    })
    const resolved = await keyResolver({ id: keyAgreementKey.id })
    // The library widens the KAK to IKeyAgreementKey (no `type` /
    // `publicKeyMultibase` statically), so assert the resolved descriptor's
    // concrete values instead: an X25519 2020 key whose fragment is its own
    // public key multibase.
    expect(resolved).toMatchObject({
      id: keyAgreementKey.id,
      type: 'X25519KeyAgreementKey2020',
      publicKeyMultibase: keyAgreementKey.id.split('#')[1]
    })
    await expect(keyResolver({ id: 'did:key:z6MkOther#x' })).rejects.toThrow(
      'Unknown key id'
    )
  })
})

describe('initSessionFromSeed', () => {
  it('assigns the did:key identity and wires the profile', async () => {
    const seed = randomSeed()
    const { session } = await initSessionFromSeed({
      seed,
      email: 'user@example.test'
    })

    expect(session.user.id).toBe(await expectedDid(seed))
    expect(session.user.email).toBe('user@example.test')
    expect(session.profile.keyAgent?.id).toBe(session.user.id)
    expect(session.profile.zcapClient).toBeInstanceOf(ZcapClient)
    expect(session.profile.keyAgreementKey).toBeDefined()
    expect(session.profile.keyResolver).toBeInstanceOf(Function)
    expect(session.storage).toBe(fakeStorage)
  })

  it('is deterministic across logins with the same seed', async () => {
    const seed = randomSeed()
    const first = await initSessionFromSeed({ seed })
    const second = await initSessionFromSeed({ seed })
    expect(second.session.user.id).toBe(first.session.user.id)
  })

  it('stamps a fresh login as not a guest', async () => {
    const { session } = await initSessionFromSeed({ seed: randomSeed() })
    expect(session.isGuest).toBe(false)
  })

  it('carries the client seed on a non-guest profile', async () => {
    const seed = randomSeed()
    const { session } = await initSessionFromSeed({ seed })
    expect(Array.from(session.profile.clientSeed as Uint8Array)).toEqual(
      Array.from(seed)
    )
  })

  it('omits the client seed on a guest profile', async () => {
    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      isGuest: true
    })
    expect(session.profile.clientSeed).toBeUndefined()
  })

  it('passes the derived user and profile to the storage bootstrap', async () => {
    const { session } = await initSessionFromSeed({ seed: randomSeed() })
    expect(StorageManager.initStorageClients).toHaveBeenCalledWith({
      user: session.user,
      profile: session.profile,
      isGuest: false,
      remoteDirect: false
    })
  })

  it('fires ensureUserCollections as session.storageReady by default', async () => {
    const { session } = await initSessionFromSeed({ seed: randomSeed() })
    expect(fakeStorage.ensureUserCollections).toHaveBeenCalledWith({
      user: session.user,
      profile: session.profile
    })
    expect(session.storageReady).toBeInstanceOf(Promise)
    await expect(session.storageReady).resolves.toBeUndefined()
  })

  it('skips provisioning (no storageReady) when provisionStorage is false', async () => {
    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      provisionStorage: false
    })
    expect(fakeStorage.ensureUserCollections).not.toHaveBeenCalled()
    expect(session.storageReady).toBeUndefined()
  })

  it('reports userExists for a returning identity', async () => {
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fakeStorage,
      userExists: true
    })
    const { userExists } = await initSessionFromSeed({ seed: randomSeed() })
    expect(userExists).toBe(true)
  })

  it('reports a brand-new identity as not existing', async () => {
    const { userExists } = await initSessionFromSeed({ seed: randomSeed() })
    expect(userExists).toBe(false)
  })

  it('propagates a storage-unreachable failure to the caller', async () => {
    vi.mocked(StorageManager.initStorageClients).mockRejectedValue(
      new Error('storage unreachable')
    )
    await expect(initSessionFromSeed({ seed: randomSeed() })).rejects.toThrow(
      'storage unreachable'
    )
  })

  describe('KMS keystore provisioning', () => {
    it('provisions a keystore and binds it onto the profile', async () => {
      const { session } = await initSessionFromSeed({ seed: randomSeed() })

      expect(ensureKeystore).toHaveBeenCalledWith({
        kmsServerUrl: KMS_SERVER_URL,
        keyAgent: session.profile.keyAgent,
        zcapClient: session.profile.zcapClient
      })
      expect(session.profile.keystoreAgent).toMatchObject({
        keystoreId: KEYSTORE_ID
      })
    })

    it('is non-fatal: a provisioning failure still returns the session', async () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
      vi.mocked(ensureKeystore).mockRejectedValue(new Error('kms down'))

      const { session } = await initSessionFromSeed({ seed: randomSeed() })

      expect(session.profile.keystoreAgent).toBeUndefined()
      expect(warnSpy).toHaveBeenCalledWith(
        'KMS keystore provisioning failed:',
        expect.any(Error)
      )
    })

    it('skips the KMS entirely when none is configured', async () => {
      kmsServerUrl = undefined
      const { session } = await initSessionFromSeed({ seed: randomSeed() })
      expect(ensureKeystore).not.toHaveBeenCalled()
      expect(session.profile.keystoreAgent).toBeUndefined()
    })
  })
})

describe('initGuestSession', () => {
  it('creates a guest session that never touches the KMS', async () => {
    const { session } = await initGuestSession()

    expect(session.isGuest).toBe(true)
    expect(session.user.email).toBe('guest@example.com')
    expect(ensureKeystore).not.toHaveBeenCalled()
    expect(StorageManager.initStorageClients).toHaveBeenCalledWith(
      expect.objectContaining({ isGuest: true })
    )
    // Guest is a new-wallet flow: provisioning is owned by provisionNewWallet,
    // so session creation must not fire ensureUserCollections.
    expect(fakeStorage.ensureUserCollections).not.toHaveBeenCalled()
    expect(session.storageReady).toBeUndefined()
  })

  it('derives a fresh random identity per guest session', async () => {
    const first = await initGuestSession()
    const second = await initGuestSession()
    expect(second.session.user.id).not.toBe(first.session.user.id)
    expect(first.session.user.id).toMatch(/^did:key:z6Mk/)
  })
})
