// @vitest-environment node
/**
 * Unit tests for the session bootstrap (`src/session/initSession.ts`):
 * passphrase-to-identity derivation via CapabilityAgent, the zcap-agent and
 * key-material wiring on the profile, guest vs regular sessions, the `full`
 * tier stamp, `userExists` reporting, and KMS keystore provisioning (wired
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
import {
  agentsFromSecret,
  initGuestSession,
  initSessionFromSecret
} from '@/session/initSession'

const SECRET = 'correct horse battery staple'
const KEYSTORE_ID = `${KMS_SERVER_URL}/keystores/z6QkKeystore`

/**
 * Independently derives the did:key the bootstrap should assign, using the
 * exact CapabilityAgent parameters `agentsFromSecret` uses.
 */
async function expectedDid(secret: string | Uint8Array): Promise<string> {
  const agent = await CapabilityAgent.fromSecret({
    secret,
    handle: 'bootstrap',
    keyName: 'boostrap-key'
  })
  return agent.id
}

const fakeStorage = { isFakeStorage: true } as never

beforeEach(() => {
  kmsServerUrl = KMS_SERVER_URL
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

describe('agentsFromSecret', () => {
  it('derives the identity, zcap client, and key-agreement material', async () => {
    const { keyAgent, zcapClient, keyAgreementKey, keyResolver } =
      await agentsFromSecret({ secret: SECRET })

    expect(keyAgent.id).toBe(await expectedDid(SECRET))
    expect(keyAgent.id).toMatch(/^did:key:z6Mk/)
    expect(zcapClient).toBeInstanceOf(ZcapClient)
    // The X25519 key-agreement key is derived under the same did:key DID.
    expect(keyAgreementKey.id).toContain(keyAgent.id)
    expect(keyResolver).toBeInstanceOf(Function)
  })

  it('is deterministic: the same secret yields the same did:key', async () => {
    const first = await agentsFromSecret({ secret: SECRET })
    const second = await agentsFromSecret({ secret: SECRET })
    expect(second.keyAgent.id).toBe(first.keyAgent.id)
    expect(second.keyAgreementKey.id).toBe(first.keyAgreementKey.id)
  })

  it('resolves its own key-agreement key id and rejects any other', async () => {
    const { keyAgreementKey, keyResolver } = await agentsFromSecret({
      secret: SECRET
    })
    const resolved = await keyResolver({ id: keyAgreementKey.id })
    expect(resolved).toMatchObject({
      id: keyAgreementKey.id,
      type: keyAgreementKey.type,
      publicKeyMultibase: keyAgreementKey.publicKeyMultibase
    })
    await expect(keyResolver({ id: 'did:key:z6MkOther#x' })).rejects.toThrow(
      'Unknown key id'
    )
  })
})

describe('initSessionFromSecret', () => {
  it('assigns the did:key identity and wires the profile', async () => {
    const { session } = await initSessionFromSecret({
      secret: SECRET,
      email: 'user@example.test'
    })

    expect(session.user.id).toBe(await expectedDid(SECRET))
    expect(session.user.email).toBe('user@example.test')
    expect(session.profile.keyAgent?.id).toBe(session.user.id)
    expect(session.profile.zcapClient).toBeInstanceOf(ZcapClient)
    expect(session.profile.keyAgreementKey).toBeDefined()
    expect(session.profile.keyResolver).toBeInstanceOf(Function)
    expect(session.storage).toBe(fakeStorage)
  })

  it('is deterministic across logins with the same secret', async () => {
    const first = await initSessionFromSecret({ secret: SECRET })
    const second = await initSessionFromSecret({ secret: SECRET })
    expect(second.session.user.id).toBe(first.session.user.id)
  })

  it('stamps a fresh login as the `full` tier and not a guest', async () => {
    const { session } = await initSessionFromSecret({ secret: SECRET })
    expect(session.tier).toBe('full')
    expect(session.isGuest).toBe(false)
  })

  it('passes the derived user and profile to the storage bootstrap', async () => {
    const { session } = await initSessionFromSecret({ secret: SECRET })
    expect(StorageManager.initStorageClients).toHaveBeenCalledWith({
      user: session.user,
      profile: session.profile,
      isGuest: false
    })
  })

  it('reports userExists for a returning identity', async () => {
    vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
      storage: fakeStorage,
      userExists: true
    })
    const { userExists } = await initSessionFromSecret({ secret: SECRET })
    expect(userExists).toBe(true)
  })

  it('reports a brand-new identity as not existing', async () => {
    const { userExists } = await initSessionFromSecret({ secret: SECRET })
    expect(userExists).toBe(false)
  })

  it('propagates a storage-unreachable failure to the caller', async () => {
    vi.mocked(StorageManager.initStorageClients).mockRejectedValue(
      new Error('storage unreachable')
    )
    await expect(initSessionFromSecret({ secret: SECRET })).rejects.toThrow(
      'storage unreachable'
    )
  })

  describe('KMS keystore provisioning', () => {
    it('provisions a keystore and binds it onto the profile', async () => {
      const { session } = await initSessionFromSecret({ secret: SECRET })

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

      const { session } = await initSessionFromSecret({ secret: SECRET })

      expect(session.profile.keystoreAgent).toBeUndefined()
      expect(session.tier).toBe('full')
      expect(warnSpy).toHaveBeenCalledWith(
        'KMS keystore provisioning failed:',
        expect.any(Error)
      )
    })

    it('skips the KMS entirely when none is configured', async () => {
      kmsServerUrl = undefined
      const { session } = await initSessionFromSecret({ secret: SECRET })
      expect(ensureKeystore).not.toHaveBeenCalled()
      expect(session.profile.keystoreAgent).toBeUndefined()
    })
  })
})

describe('initGuestSession', () => {
  it('creates a guest session that never touches the KMS', async () => {
    const { session } = await initGuestSession()

    expect(session.isGuest).toBe(true)
    expect(session.tier).toBe('full')
    expect(session.user.email).toBe('guest@example.com')
    expect(ensureKeystore).not.toHaveBeenCalled()
    expect(StorageManager.initStorageClients).toHaveBeenCalledWith(
      expect.objectContaining({ isGuest: true })
    )
  })

  it('derives a fresh random identity per guest session', async () => {
    const first = await initGuestSession()
    const second = await initGuestSession()
    expect(second.session.user.id).not.toBe(first.session.user.id)
    expect(first.session.user.id).toMatch(/^did:key:z6Mk/)
  })
})
