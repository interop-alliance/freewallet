/**
 * The connected Space's quota report as the Storage page and the Import
 * page show it: loaded on each mount of a page that shows it, reported
 * through one status value, and reloadable from a Retry button. A reload
 * reports `loading` while it runs, so a Retry click shows the skeleton and a
 * second failure lands as a fresh `error`. A session with no remote storage
 * has no quota to report, and the status stays `unavailable`.
 */
import { useCallback, useState } from 'react'
import { createLogger } from '@/lib/log'
import { quotaViewFromReport } from '@/lib/storageQuota'
import type { Session } from '@/types/auth'
import type { StorageQuotaStatus } from '@/types/storageQuota'
import { useAsyncLoad } from './useAsyncLoad'

const log = createLogger('fw:ui:storage')

/**
 * @param options {object}
 * @param options.session {Session | null}   the live session; the report is
 *   read off its storage when that storage has a Space
 * @returns {{ status: StorageQuotaStatus, reload: () => void }}
 */
export function useSpaceQuota({ session }: { session: Session | null }): {
  status: StorageQuotaStatus
  reload: () => void
} {
  const storage = session?.storage
  const enabled = Boolean(storage?.hasRemoteStorage)

  // A failed read is a status of its own, so the loader never throws and
  // `data` is the whole report.
  const {
    data: status,
    loading,
    reload: rerun
  } = useAsyncLoad<StorageQuotaStatus>(
    async () => {
      if (!storage) {
        return { kind: 'unavailable' }
      }
      try {
        const report = await storage.getSpaceQuotas()
        if (!report?.backends.length) {
          return { kind: 'unavailable' }
        }
        const quota = quotaViewFromReport(report)
        return quota ? { kind: 'ready', quota } : { kind: 'unavailable' }
      } catch (err) {
        log.error('Failed to load storage quota', { err })
        return { kind: 'error' }
      }
    },
    [storage],
    { enabled }
  )

  const [reloading, setReloading] = useState(false)
  const reload = useCallback(() => {
    setReloading(true)
    void rerun().finally(() => setReloading(false))
  }, [rerun])

  if (!enabled) {
    return { status: { kind: 'unavailable' }, reload }
  }
  if (loading || reloading || !status) {
    return { status: { kind: 'loading' }, reload }
  }
  return { status, reload }
}
