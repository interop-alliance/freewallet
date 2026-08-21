/**
 * Unit test for `StorageManager.addHistoryGenerationCollected`: annex
 * GC's owner-side digest write. Unlike every other `addHistory*` method it
 * does not mint a `uuidv7` -- the generation id IS the activity id and the
 * record's resource id, which is what collapses a torn re-run's second row at
 * read time. The synced-collection backend is a structural fake, so the
 * assertion sits exactly at the seam the method writes through.
 *
 * @vitest-environment node
 */
import { describe, expect, it, vi } from 'vitest'
import { durableSessionPersistence } from '@/session/persistence'
import type { User } from '@/types/auth'
import type { BrowserStore } from './browserStore'
import { StorageManager } from './storageManager'

const USER: User = {
  id: 'did:key:z6MkClient',
  email: 'user@example.test'
} as unknown as User

/**
 * A `StorageManager` over a local store stubbed down to the one method the
 * digest write calls, plus the recording spy itself.
 */
function makeStorage(): {
  storage: StorageManager
  addHistoryItem: ReturnType<typeof vi.fn>
} {
  const addHistoryItem = vi.fn(async () => undefined)
  const storage = new StorageManager({
    localStore: { addHistoryItem } as unknown as BrowserStore,
    persistence: durableSessionPersistence()
  })
  return { storage, addHistoryItem }
}

describe('StorageManager.addHistoryGenerationCollected', () => {
  it('writes the digest under the generation id verbatim', async () => {
    const { storage, addHistoryItem } = makeStorage()
    const generationId = 'gen-Ux3v0kQf9aPmB2hZ'

    await storage.addHistoryGenerationCollected({
      user: USER,
      generationId,
      firstEntry: '2026-05-01T00:00:00Z',
      lastEntry: '2026-08-01T00:00:00Z',
      entryCount: 4
    })

    expect(addHistoryItem).toHaveBeenCalledTimes(1)
    const { resourceId, activity } = addHistoryItem.mock.calls[0]![0] as {
      resourceId: string
      activity: {
        id: string
        type: string[]
        summary: string
        object: unknown
      }
    }
    expect(resourceId).toBe(generationId)
    expect(activity.id).toBe(generationId)
    expect(activity.type).toEqual(['GenerationCollect'])
    expect(activity.summary).toBe(
      `Collected client-annex generation "${generationId}".`
    )
    expect(activity.object).toEqual({
      generationId,
      firstEntry: '2026-05-01T00:00:00Z',
      lastEntry: '2026-08-01T00:00:00Z',
      entryCount: 4
    })
  })
})
