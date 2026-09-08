/**
 * Fires a callback each time one of the named collections' background
 * replication settles out of `syncing`. Pages list their data once at mount
 * and hold the result in state; on a fresh browser the first pull lands
 * moments after that read, so a page that did not re-read would show an
 * empty list until a manual Sync. The sync controller writes each
 * collection's status to the sync status store as its replication runs, and
 * this hook watches for the `syncing` to `synced` edge on each of them.
 */
import { useEffect, useRef } from 'react'
import { useSyncStatusStore, type SyncStatus } from '@/stores/syncStatusStore'

/**
 * @param options {object}
 * @param options.collectionIds {string[]}   the WAS collection ids whose pulls
 *   the page's view depends on
 * @param options.onSettled {() => void}   invoked once per settled pull;
 *   callers pass a stable callback (the page's own reload)
 * @returns {void}
 */
export function usePullSettled({
  collectionIds,
  onSettled
}: {
  collectionIds: string[]
  onSettled: () => void
}): void {
  const statuses = useSyncStatusStore(state => state.statuses)
  const previous = useRef<Record<string, SyncStatus | undefined>>({})
  useEffect(() => {
    let settled = false
    for (const collectionId of collectionIds) {
      const before = previous.current[collectionId]
      const now = statuses[collectionId]
      previous.current[collectionId] = now
      if (before === 'syncing' && now === 'synced') {
        settled = true
      }
    }
    if (settled) {
      onSettled()
    }
  }, [statuses, collectionIds, onSettled])
}
