/**
 * The two listings behind the Storage page's collection rows -- the reader
 * rosters behind each row's "Shared" chip and the connected apps behind its
 * "Created by" line -- fed by one read of the activity history. Both join
 * over `wallet-activity`, and a read of it decrypts every envelope in the
 * collection, so the page reads it once here and hands the scan to both
 * rather than letting each listing scan it again.
 *
 * Each listing's failure is non-blocking: the chips or the attribution line
 * simply do not appear, and the storage listing itself stays usable. The
 * history read failing leaves both off.
 */
import { useMemo } from 'react'
import { createLogger } from '@/lib/log'
import { listSharedCollections, type CollectionShare } from '@/session/shares'
import type { ConnectedApp } from '@/lib/connectedApps'
import type { StorageCollection } from '@/lib/storage'
import type { Session } from '@/types/auth'
import { useAsyncLoad } from './useAsyncLoad'
import { useConnectedApps } from './useConnectedApps'

const log = createLogger('fw:ui:storage')

/**
 * One shared empty map, so a disabled, loading, or failed listing keeps a
 * stable identity across renders and the consumers' memos hold.
 */
const NO_SHARES: Record<string, CollectionShare[]> = {}

/**
 * @param options {object}
 * @param options.session {Session | null}   the live session; both listings
 *   stay off without one, and without remote storage
 * @param options.collections {StorageCollection[]}   the listed collections;
 *   the apps listing runs only once one of them carries a `generator`
 * @returns {{ sharesByCollection: Record<string, CollectionShare[]>,
 *   apps: ConnectedApp[], reload: () => Promise<void> }}   the two listings,
 *   and a reload that re-reads the history and re-runs both
 */
export function useStorageListings({
  session,
  collections
}: {
  session: Session | null
  collections: StorageCollection[]
}): {
  sharesByCollection: Record<string, CollectionShare[]>
  apps: ConnectedApp[]
  reload: () => Promise<void>
} {
  const hasRemoteStorage = Boolean(session?.storage?.hasRemoteStorage)
  const active = hasRemoteStorage && session !== null

  // The one history read. A reload mints a new items array, and the two
  // listings below re-run off that identity change.
  const { data: items, reload } = useAsyncLoad(
    async () => {
      if (!session) {
        return []
      }
      return session.storage.listHistoryItems()
    },
    [session],
    {
      enabled: active,
      onError: err => {
        log.error('Could not read the activity history', { err })
      }
    }
  )

  const { data: loadedShares, error: sharesError } = useAsyncLoad(
    async (): Promise<Record<string, CollectionShare[]>> => {
      if (!session || !items) {
        return NO_SHARES
      }
      return listSharedCollections({ session, items })
    },
    [session, items],
    {
      enabled: active && items !== undefined,
      onError: err => {
        log.error('Could not load the collection shares', { err })
      }
    }
  )

  const sharesByCollection = useMemo(
    () => (sharesError ? NO_SHARES : (loadedShares ?? NO_SHARES)),
    [loadedShares, sharesError]
  )

  const apps = useConnectedApps({
    storage: session?.storage,
    items,
    enabled:
      items !== undefined &&
      collections.some(({ generator }) => generator !== undefined)
  })

  return { sharesByCollection, apps, reload }
}
