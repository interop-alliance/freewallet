/**
 * Zustand store holding per-collection replication status, mirroring the WAS
 * spec's planned per-replica sync-status vocabulary. The sync controller writes
 * to it off the RxDB replication `active$` / `error$` streams; UI (e.g. a header
 * indicator or the Storage page's collection listing) reads from it. In-memory
 * only, like the session -- cleared on logout.
 */
import { create } from 'zustand'
import type { SyncStatus } from '@interop/was-client/sync'

export type { SyncStatus }

interface SyncStatusState {
  /**
   * Keyed by WAS collection id (e.g. `public-credentials`).
   */
  statuses: Record<string, SyncStatus>
  setStatus: (collectionId: string, status: SyncStatus) => void
  reset: () => void
}

export const useSyncStatusStore = create<SyncStatusState>()(set => ({
  statuses: {},
  setStatus: (collectionId, status) =>
    set(state => ({
      statuses: { ...state.statuses, [collectionId]: status }
    })),
  reset: () => set({ statuses: {} })
}))

/**
 * How long a caller waits for replication to settle before it proceeds
 * anyway. The wait is a courtesy -- it keeps a bulk read (the content
 * migration's merge checks) from deciding against a replica that is still
 * catching up -- so a slow or stuck replication delays the work by seconds
 * rather than blocking it.
 */
const IN_SYNC_WAIT_MS = 5000

/**
 * Whether one collection's replication has settled: `synced`, `error`, and
 * `idle` are all resting states, and an absent status means no replication
 * controller is carrying that collection at all (a guest, a no-WAS
 * deployment, a replica-less session), which nothing can wait for.
 *
 * @param status {SyncStatus | undefined}
 * @returns {boolean}
 */
function isSettled(status: SyncStatus | undefined): boolean {
  return status !== 'syncing'
}

/**
 * Resolves once every named collection's replication has settled, or once
 * the timeout expires -- whichever comes first.
 *
 * @param options {object}
 * @param options.collectionIds {ReadonlyArray<string>}   WAS collection ids
 * @param [options.timeoutMs] {number}
 * @returns {Promise<boolean>}   whether every collection settled in time
 */
export async function awaitCollectionsInSync({
  collectionIds,
  timeoutMs = IN_SYNC_WAIT_MS
}: {
  collectionIds: ReadonlyArray<string>
  timeoutMs?: number
}): Promise<boolean> {
  const settled = (): boolean => {
    const { statuses } = useSyncStatusStore.getState()
    return collectionIds.every(collectionId =>
      isSettled(statuses[collectionId])
    )
  }
  if (settled()) {
    return true
  }
  return await new Promise<boolean>(resolve => {
    const finish = (inSync: boolean): void => {
      clearTimeout(timer)
      unsubscribe()
      resolve(inSync)
    }
    const timer = setTimeout(() => finish(false), timeoutMs)
    const unsubscribe = useSyncStatusStore.subscribe(() => {
      if (settled()) {
        finish(true)
      }
    })
  })
}
