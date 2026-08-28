// @vitest-environment node
/**
 * FW-295: `loadUnlockRegistry` makes no unlock-methods registry call at all
 * on a transient session -- neither the backfill nor the plain read.
 */
import { describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'
import { STORAGE_IN_MEMORY, STORAGE_INDEXEDDB } from '@/session/persistence'

vi.mock('@/session/unlockMethods', () => ({
  backfillPassphraseUnlockMethod: vi.fn(),
  getUnlockMethods: vi.fn(),
  updateUnlockMethods: vi.fn()
}))
const { backfillPassphraseUnlockMethod, getUnlockMethods } =
  await import('@/session/unlockMethods')

const { loadUnlockRegistry } = await import('@/session/accountSettings')

/**
 * @param options {object}
 * @param options.storage {string}
 * @returns {Session}
 */
function fakeSession({ storage }: { storage: string }): Session {
  return {
    user: { id: 'did:key:zClientA' },
    isGuest: false,
    profile: {
      persistence: { storage }
    }
  } as unknown as Session
}

describe('loadUnlockRegistry (FW-295 transient gate)', () => {
  it('makes no registry call on a transient session', async () => {
    const session = fakeSession({ storage: STORAGE_IN_MEMORY })

    const result = await loadUnlockRegistry({ session })

    expect(result).toBeNull()
    expect(vi.mocked(backfillPassphraseUnlockMethod)).not.toHaveBeenCalled()
    expect(vi.mocked(getUnlockMethods)).not.toHaveBeenCalled()
  })

  it('backfills with createIfMissing on a browser-local session', async () => {
    const session = fakeSession({ storage: STORAGE_INDEXEDDB })
    const record = { methods: [] }
    vi.mocked(backfillPassphraseUnlockMethod).mockResolvedValue(record as never)

    const result = await loadUnlockRegistry({ session })

    expect(result).toBe(record)
    expect(vi.mocked(backfillPassphraseUnlockMethod)).toHaveBeenCalledWith({
      session,
      createIfMissing: true
    })
    expect(vi.mocked(getUnlockMethods)).not.toHaveBeenCalled()
  })
})

describe('the registry-writing ceremonies gate on session.registryReady (FW-300)', () => {
  it('holds the registry write until the login-time chain resolves', async () => {
    const { renameAccountPasskey } = await import('@/session/accountSettings')
    const { updateUnlockMethods } = await import('@/session/unlockMethods')
    const record = { methods: [] }
    vi.mocked(updateUnlockMethods).mockResolvedValue(record as never)
    let releaseChain!: () => void
    const session = {
      ...fakeSession({ storage: STORAGE_INDEXEDDB }),
      registryReady: new Promise<void>(resolve => {
        releaseChain = resolve
      })
    } as unknown as Session

    const renaming = renameAccountPasskey({
      session,
      entry: { type: 'passkey' } as never,
      label: 'Renamed'
    })
    // Give the ceremony a macrotask turn: the gate, not scheduling, must be
    // what holds the write back.
    await new Promise(resolve => setTimeout(resolve, 20))
    expect(vi.mocked(updateUnlockMethods)).not.toHaveBeenCalled()

    releaseChain()
    await expect(renaming).resolves.toBe(record)
    expect(vi.mocked(updateUnlockMethods)).toHaveBeenCalledOnce()
  })

  it('holds the update-key rotation until the login-time chain resolves', async () => {
    // Not a registry writer, but gated all the same: the rotation's
    // client-key-record save can interleave with the chain's head stage
    // (the sweep's user-key adoption persist) and strand `webvhUpdateKeys`
    // behind the published log entry. The fake remote store throws at the
    // ceremony's first post-gate touch, so the assertion is purely about
    // when that touch happens.
    const { rotateAccountUpdateKey } = await import('@/session/accountSettings')
    let releaseChain!: () => void
    const webvhIdStore = vi.fn(() => {
      throw new Error('halt before the log read')
    })
    const session = {
      ...fakeSession({ storage: STORAGE_INDEXEDDB }),
      storage: { remoteStore: { webvhIdStore } },
      registryReady: new Promise<void>(resolve => {
        releaseChain = resolve
      })
    } as unknown as Session
    session.profile.clientWebvhKeys = { updateKey: 'fake' } as never
    session.profile.persistClientKeys = vi.fn(async () => undefined) as never

    const rotating = rotateAccountUpdateKey({ session })
    // Give the ceremony a macrotask turn: the gate, not scheduling, must be
    // what holds the rotation back.
    await new Promise(resolve => setTimeout(resolve, 20))
    expect(webvhIdStore).not.toHaveBeenCalled()

    releaseChain()
    await expect(rotating).rejects.toThrow('halt before the log read')
    expect(webvhIdStore).toHaveBeenCalledOnce()
  })
})
