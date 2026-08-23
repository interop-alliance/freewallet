// @vitest-environment node
/**
 * FW-295: a transient session makes no unlock-methods registry call at all.
 * `backfillPassphraseUnlockMethod` must return `null` before even a read on
 * a transient session, and must otherwise proceed to the ordinary read.
 */
import { describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'
import {
  DURABILITY_IN_MEMORY,
  DURABILITY_INDEXEDDB
} from '@/session/persistence'

const { backfillPassphraseUnlockMethod } =
  await import('@/session/unlockMethods')

/**
 * A minimal session shaped as `backfillPassphraseUnlockMethod` reads it: the
 * durability handle under test, plus just enough of `profile` and
 * `persistence` for the durable path to reach its first registry read (a
 * local-cache load, since no `VITE_WAS_SERVER_URL` is set in tests) without
 * throwing.
 *
 * @param options {object}
 * @param options.durability {string}
 * @returns {{ session: Session, cacheLoad: ReturnType<typeof vi.fn> }}
 */
function fakeSession({ durability }: { durability: string }): {
  session: Session
  cacheLoad: ReturnType<typeof vi.fn>
} {
  const cacheLoad = vi.fn(async () => null)
  const session = {
    user: { id: 'did:key:zClientA' },
    isGuest: false,
    profile: {
      keyAgreementKey: { publicKeyMultibase: 'zClientKak' },
      keyResolver: { resolve: vi.fn() },
      unlockMethod: undefined,
      persistence: {
        durability,
        unlockMethodsCache: {
          load: cacheLoad,
          save: vi.fn(),
          delete: vi.fn()
        }
      }
    }
  } as unknown as Session
  return { session, cacheLoad }
}

describe('backfillPassphraseUnlockMethod (FW-295 transient gate)', () => {
  it('makes no registry call on a transient session', async () => {
    const { session, cacheLoad } = fakeSession({
      durability: DURABILITY_IN_MEMORY
    })

    const result = await backfillPassphraseUnlockMethod({ session })

    expect(result).toBeNull()
    expect(cacheLoad).not.toHaveBeenCalled()
  })

  it('proceeds to the read on a durable session', async () => {
    const { session, cacheLoad } = fakeSession({
      durability: DURABILITY_INDEXEDDB
    })

    const result = await backfillPassphraseUnlockMethod({ session })

    expect(result).toBeNull()
    expect(cacheLoad).toHaveBeenCalledTimes(1)
  })
})
