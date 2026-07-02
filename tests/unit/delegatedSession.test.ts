// @vitest-environment node
/**
 * Unit tests for the refresh-surviving delegated session
 * (`src/session/delegatedSession.ts`): the shape of the zcaps delegated at
 * login, the persisted record, restore validation (expiry, key mismatch),
 * and logout revocation. The session key module is stubbed (node has no
 * IndexedDB) and the storage bootstrap is spied on the real static.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import type { Session } from '@/types/auth'

vi.mock('@/lib/sessionKey', () => ({
  getOrCreateSessionKeyPair: vi.fn(),
  loadSessionKeyPair: vi.fn(),
  loadSessionRecord: vi.fn(),
  saveSessionRecord: vi.fn(),
  clearPersistedSession: vi.fn(),
  sessionKeySigner: vi.fn()
}))
vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  WAS_SERVER_URL: 'https://was.example.test'
}))

import { KmsClient } from '@interop/webkms-client'
import * as sessionKey from '@/lib/sessionKey'
import {
  endDelegatedSession,
  persistDelegatedSession,
  restoreDelegatedSession,
  type PersistedSessionRecord
} from '@/session/delegatedSession'
import { StorageManager } from '@/stores/storageManager'

const SPACE_URL = 'https://was.example.test/space/space-1'
const KEYSTORE_ID = 'https://was.example.test/kms/keystores/z6QkKeystore'
const SESSION_DID = 'did:key:z6MkSession'

const fakeKeyPair = {} as CryptoKeyPair
const fakeSigner = {
  id: `${SESSION_DID}#z6MkSession`,
  sign: vi.fn()
}

/**
 * Builds a full-tier session stub whose zcapClient records delegations.
 */
function fullSessionStub() {
  const delegate = vi.fn(
    async ({ invocationTarget }: { invocationTarget: string }) =>
      ({ id: `urn:zcap:delegated:${invocationTarget}` }) as unknown as IZcap
  )
  const session = {
    user: { id: 'did:key:z6MkRoot', email: 'user@example.test' },
    isGuest: false,
    tier: 'full',
    profile: {
      zcapClient: { delegate },
      keystoreAgent: { keystoreId: KEYSTORE_ID }
    },
    storage: {
      hasRemoteStorage: true,
      spaceUrl: SPACE_URL,
      spaceId: 'space-1'
    }
  } as unknown as Session
  return { session, delegate }
}

function persistedRecord(
  overrides: Partial<PersistedSessionRecord> = {}
): PersistedSessionRecord {
  return {
    controller: 'did:key:z6MkRoot',
    email: 'user@example.test',
    spaceId: 'space-1',
    sessionDid: SESSION_DID,
    expires: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    spaceReadCapability: { id: 'urn:zcap:space-read' } as unknown as IZcap,
    collectionCapabilities: {
      'private-credentials': { id: 'urn:zcap:pc' } as unknown as IZcap
    },
    keystoreId: KEYSTORE_ID,
    keystoreCapability: { id: 'urn:zcap:keystore' } as unknown as IZcap,
    ...overrides
  }
}

beforeEach(() => {
  vi.mocked(sessionKey.getOrCreateSessionKeyPair).mockResolvedValue(fakeKeyPair)
  vi.mocked(sessionKey.loadSessionKeyPair).mockResolvedValue(fakeKeyPair)
  vi.mocked(sessionKey.sessionKeySigner).mockResolvedValue({
    signer: fakeSigner,
    did: SESSION_DID
  })
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

describe('persistDelegatedSession', () => {
  it('delegates the session zcaps and persists the record', async () => {
    const { session, delegate } = fullSessionStub()

    await persistDelegatedSession({ session })

    // One space read + three standard collections + one keystore.
    expect(delegate).toHaveBeenCalledTimes(5)
    expect(delegate).toHaveBeenCalledWith(
      expect.objectContaining({
        invocationTarget: SPACE_URL,
        controller: SESSION_DID,
        allowedActions: ['GET', 'HEAD']
      })
    )
    // Collection capabilities are rooted at the Space's root capability and
    // attenuate their target down to the collection.
    expect(delegate).toHaveBeenCalledWith(
      expect.objectContaining({
        capability: `urn:zcap:root:${encodeURIComponent(SPACE_URL)}`,
        invocationTarget: `${SPACE_URL}/private-credentials`,
        allowedActions: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE']
      })
    )
    expect(delegate).toHaveBeenCalledWith(
      expect.objectContaining({
        invocationTarget: KEYSTORE_ID,
        allowedActions: ['sign']
      })
    )

    expect(sessionKey.saveSessionRecord).toHaveBeenCalledWith({
      record: expect.objectContaining({
        controller: 'did:key:z6MkRoot',
        email: 'user@example.test',
        spaceId: 'space-1',
        sessionDid: SESSION_DID,
        keystoreId: KEYSTORE_ID,
        collectionCapabilities: expect.objectContaining({
          'private-credentials': expect.anything(),
          'public-credentials': expect.anything(),
          'wallet-activity': expect.anything()
        })
      })
    })
  })

  it('persists through a supplied IDBFactory (the popup storage-access handle)', async () => {
    const { session } = fullSessionStub()
    const idb = {} as IDBFactory

    await persistDelegatedSession({ session, idb })

    expect(sessionKey.getOrCreateSessionKeyPair).toHaveBeenCalledWith({ idb })
    expect(sessionKey.saveSessionRecord).toHaveBeenCalledWith(
      expect.objectContaining({ idb })
    )
  })

  it('skips guests and sessions without remote storage', async () => {
    const { session, delegate } = fullSessionStub()
    await persistDelegatedSession({
      session: { ...session, isGuest: true } as Session
    })
    const noRemote = fullSessionStub()
    ;(
      noRemote.session.storage as { hasRemoteStorage: boolean }
    ).hasRemoteStorage = false
    await persistDelegatedSession({ session: noRemote.session })

    expect(delegate).not.toHaveBeenCalled()
    expect(noRemote.delegate).not.toHaveBeenCalled()
    expect(sessionKey.saveSessionRecord).not.toHaveBeenCalled()
  })
})

describe('restoreDelegatedSession', () => {
  it('reconstitutes a delegated-tier session from a valid record', async () => {
    vi.mocked(sessionKey.loadSessionRecord).mockResolvedValue(persistedRecord())
    const storage = {} as never
    const initSpy = vi
      .spyOn(StorageManager, 'initDelegatedStorageClients')
      .mockResolvedValue({ storage })

    const session = await restoreDelegatedSession()

    expect(session).not.toBeNull()
    expect(session?.tier).toBe('delegated')
    expect(session?.isGuest).toBe(false)
    expect(session?.user).toEqual({
      id: 'did:key:z6MkRoot',
      email: 'user@example.test'
    })
    expect(session?.profile.keystoreId).toBe(KEYSTORE_ID)
    expect(session?.profile.keyAgent).toBeUndefined()
    expect(session?.storage).toBe(storage)
    expect(initSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: 'space-1',
        sessionCapabilities: expect.objectContaining({
          spaceRead: expect.anything(),
          collections: expect.anything()
        })
      })
    )
  })

  it('restores through a supplied IDBFactory (the popup storage-access handle)', async () => {
    vi.mocked(sessionKey.loadSessionRecord).mockResolvedValue(persistedRecord())
    vi.spyOn(StorageManager, 'initDelegatedStorageClients').mockResolvedValue({
      storage: {} as never
    })
    const idb = {} as IDBFactory

    const session = await restoreDelegatedSession({ idb })

    expect(session?.tier).toBe('delegated')
    expect(sessionKey.loadSessionRecord).toHaveBeenCalledWith({ idb })
    expect(sessionKey.loadSessionKeyPair).toHaveBeenCalledWith({ idb })
  })

  it('returns null when nothing is persisted', async () => {
    vi.mocked(sessionKey.loadSessionRecord).mockResolvedValue(null)
    vi.mocked(sessionKey.loadSessionKeyPair).mockResolvedValue(null)

    expect(await restoreDelegatedSession()).toBeNull()
    expect(sessionKey.clearPersistedSession).not.toHaveBeenCalled()
  })

  it('clears and refuses an expired record', async () => {
    vi.mocked(sessionKey.loadSessionRecord).mockResolvedValue(
      persistedRecord({
        expires: new Date(Date.now() - 1000).toISOString()
      })
    )

    expect(await restoreDelegatedSession()).toBeNull()
    expect(sessionKey.clearPersistedSession).toHaveBeenCalled()
  })

  it('clears and refuses a record whose session did does not match the key', async () => {
    vi.mocked(sessionKey.loadSessionRecord).mockResolvedValue(
      persistedRecord({ sessionDid: 'did:key:z6MkSomeOtherKey' })
    )

    expect(await restoreDelegatedSession()).toBeNull()
    expect(sessionKey.clearPersistedSession).toHaveBeenCalled()
  })
})

describe('endDelegatedSession', () => {
  it('revokes the keystore zcap and clears the persisted session', async () => {
    vi.mocked(sessionKey.loadSessionRecord).mockResolvedValue(persistedRecord())
    const revokeSpy = vi
      .spyOn(KmsClient.prototype, 'revokeCapability')
      .mockResolvedValue(undefined)

    await endDelegatedSession()

    expect(revokeSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        capabilityToRevoke: expect.objectContaining({
          id: 'urn:zcap:keystore'
        }),
        invocationSigner: fakeSigner
      })
    )
    expect(sessionKey.clearPersistedSession).toHaveBeenCalled()
  })

  it('still clears the persisted session when revocation fails', async () => {
    vi.mocked(sessionKey.loadSessionRecord).mockResolvedValue(persistedRecord())
    vi.spyOn(KmsClient.prototype, 'revokeCapability').mockRejectedValue(
      new Error('KMS unreachable')
    )

    await endDelegatedSession()

    expect(sessionKey.clearPersistedSession).toHaveBeenCalled()
  })

  it('clears without revoking when nothing is persisted', async () => {
    vi.mocked(sessionKey.loadSessionRecord).mockResolvedValue(null)
    const revokeSpy = vi.spyOn(KmsClient.prototype, 'revokeCapability')

    await endDelegatedSession()

    expect(revokeSpy).not.toHaveBeenCalled()
    expect(sessionKey.clearPersistedSession).toHaveBeenCalled()
  })
})
