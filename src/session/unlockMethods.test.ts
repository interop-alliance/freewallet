// @vitest-environment node
/**
 * The backfill reaches its registry read on BOTH storage tiers. FW-295's
 * transient gate was retired with the account-ceremony context: a transient
 * session reads and writes the registry under the visit's generation
 * delegation rather than being turned away before the first read.
 */
import { describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'
import { STORAGE_IN_MEMORY, STORAGE_INDEXEDDB } from '@/session/persistence'

const { backfillPassphraseUnlockMethod } =
  await import('@/session/unlockMethods')

/**
 * A minimal session shaped as `backfillPassphraseUnlockMethod` reads it: the
 * storage tier under test, plus just enough of `profile` and `persistence`
 * for the browser-local path to reach its first registry read (a local-cache
 * load, since no `VITE_WAS_SERVER_URL` is set in tests) without throwing.
 *
 * @param options {object}
 * @param options.storage {string}
 * @returns {{ session: Session, cacheLoad: ReturnType<typeof vi.fn> }}
 */
function fakeSession({ storage }: { storage: string }): {
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
        storage,
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

describe('backfillPassphraseUnlockMethod (both storage tiers)', () => {
  it('proceeds to the read on a transient session', async () => {
    const { session, cacheLoad } = fakeSession({
      storage: STORAGE_IN_MEMORY
    })

    const result = await backfillPassphraseUnlockMethod({ session })

    expect(result).toBeNull()
    expect(cacheLoad).toHaveBeenCalledTimes(1)
  })

  it('proceeds to the read on a browser-local session', async () => {
    const { session, cacheLoad } = fakeSession({
      storage: STORAGE_INDEXEDDB
    })

    const result = await backfillPassphraseUnlockMethod({ session })

    expect(result).toBeNull()
    expect(cacheLoad).toHaveBeenCalledTimes(1)
  })
})
