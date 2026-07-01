/**
 * Zustand store holding per-collection replication status, mirroring the WAS
 * spec's planned per-replica sync-status vocabulary. The sync controller writes
 * to it off the RxDB replication `active$` / `error$` streams; UI (e.g. a header
 * indicator or the Settings page) reads from it. In-memory only, like the
 * session -- cleared on logout.
 */
import { create } from 'zustand'

/**
 * A single collection's replication status:
 * - `idle`    -- configured but no cycle has run yet
 * - `syncing` -- a pull/push cycle is in flight
 * - `synced`  -- last cycle completed without error
 * - `error`   -- last cycle failed (RxDB is backing off / will retry)
 */
export type SyncStatus = 'idle' | 'syncing' | 'synced' | 'error'

interface SyncStatusState {
  /** Keyed by WAS collection id (e.g. `public-credentials`). */
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
