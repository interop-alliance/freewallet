// @vitest-environment node
/**
 * App-side pin of the login path's roster-continuity policy in
 * `src/session/initSession.ts`, exercised through the REAL wallet-core
 * `checkUserKeyRosterAtLogin`: a chain-head rollback (possibly nothing worse
 * than replication lag) degrades to the cached user key rather than failing
 * the login, while a fork or SCID/method switch still refuses the session.
 * The roster store is faked at the app's own seam (`accountRosterStore`), so
 * the wallet-core policy between the store and the session runs for real.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined,
  storeRead: (async () => null) as () => Promise<unknown>
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
  userKeyVaultKeys: vi.fn(({ userKey }: { userKey: { id: string } }) => ({
    keyAgreementKey: { id: `${userKey.id}#kak` },
    keyResolver: async () => ({})
  }))
}))

vi.mock('@/session/rosterStore', () => ({
  accountRosterStore: vi.fn(() => ({
    read: () => state.storeRead()
  })),
  sessionRosterStore: vi.fn()
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

vi.mock('@/stores/storageManager', () => ({
  StorageManager: { initStorageClients: vi.fn() }
}))

import { StorageManager } from '@/stores/storageManager'
import { initSessionFromSeed } from '@/session/initSession'

const CACHED_USER_KEY = {
  id: 'did:key:z6LSCachedUserKey',
  secret: new Uint8Array(32).fill(1)
}
const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

/**
 * A continuity refusal as the roster store raises it, matched by wallet-core
 * on `name` + `reason` (foreign-copy safe).
 *
 * @param reason {string}
 * @returns {Error}
 */
function continuityError(reason: string): Error {
  return Object.assign(
    new Error(`The served log does not extend the pinned head (${reason}).`),
    { name: 'ResourceLogContinuityError', reason }
  )
}

function randomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

beforeEach(() => {
  vi.clearAllMocks()
  state.wasUrl = 'https://was.example.test'
  state.storeRead = async () => null
  vi.mocked(StorageManager.initStorageClients).mockResolvedValue({
    storage: {
      ensureUserCollections: vi.fn(async () => undefined),
      get remoteStore() {
        return undefined
      }
    } as never,
    userExists: true
  })
})

describe('the login-time roster continuity policy', () => {
  it('degrades a chain-head rollback to the cached user key', async () => {
    state.storeRead = async () => {
      throw continuityError('rollback')
    }
    const { session } = await initSessionFromSeed({
      seed: randomSeed(),
      userKey: CACHED_USER_KEY,
      accountPointer: POINTER
    })
    // Nothing rolled back is adopted; the session runs on the cached key and
    // there is no roster read to sweep from.
    expect(session.profile.userKey).toEqual(CACHED_USER_KEY)
    expect(session.userKeySweep).toBeUndefined()
    expect(session.userKeyPersistFailed).toBeUndefined()
  })

  it('still refuses the session on a fork', async () => {
    state.storeRead = async () => {
      throw continuityError('fork')
    }
    await expect(
      initSessionFromSeed({
        seed: randomSeed(),
        userKey: CACHED_USER_KEY,
        accountPointer: POINTER
      })
    ).rejects.toMatchObject({
      name: 'ResourceLogContinuityError',
      reason: 'fork'
    })
  })

  it('still refuses the session on an SCID switch', async () => {
    state.storeRead = async () => {
      throw continuityError('scid-switch')
    }
    await expect(
      initSessionFromSeed({
        seed: randomSeed(),
        userKey: CACHED_USER_KEY,
        accountPointer: POINTER
      })
    ).rejects.toMatchObject({
      name: 'ResourceLogContinuityError',
      reason: 'scid-switch'
    })
  })
})
