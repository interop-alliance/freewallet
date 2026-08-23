// @vitest-environment node
/**
 * FW-295: `loadUnlockRegistry` makes no unlock-methods registry call at all
 * on a transient session -- neither the backfill nor the plain read.
 */
import { describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'
import {
  DURABILITY_IN_MEMORY,
  DURABILITY_INDEXEDDB
} from '@/session/persistence'

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
 * @param options.durability {string}
 * @returns {Session}
 */
function fakeSession({ durability }: { durability: string }): Session {
  return {
    user: { id: 'did:key:zClientA' },
    isGuest: false,
    profile: {
      persistence: { durability }
    }
  } as unknown as Session
}

describe('loadUnlockRegistry (FW-295 transient gate)', () => {
  it('makes no registry call on a transient session', async () => {
    const session = fakeSession({ durability: DURABILITY_IN_MEMORY })

    const result = await loadUnlockRegistry({ session })

    expect(result).toBeNull()
    expect(vi.mocked(backfillPassphraseUnlockMethod)).not.toHaveBeenCalled()
    expect(vi.mocked(getUnlockMethods)).not.toHaveBeenCalled()
  })

  it('backfills with createIfMissing on a durable session', async () => {
    const session = fakeSession({ durability: DURABILITY_INDEXEDDB })
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
