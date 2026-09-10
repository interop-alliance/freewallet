/**
 * The connected applications behind the storage browser's "Created by" line,
 * loaded once per page over `listConnectedApps`. The load is non-blocking: a
 * failure is logged and reads as no apps, so the attribution line is left off
 * rather than the page failing. It runs only where the line can name an app:
 * a session with remote storage, and (where the caller names one) a
 * collection the wallet did not provision itself.
 */
import { listConnectedApps, type ConnectedApp } from '@/lib/connectedApps'
import { createLogger } from '@/lib/log'
import type { StorageManager } from '@/stores/storageManager'
import { useAsyncLoad } from './useAsyncLoad'

const log = createLogger('fw:ui:storage')

/**
 * @param options {object}
 * @param [options.storage] {StorageManager}   the session's storage
 * @param [options.enabled] {boolean}   false leaves the load off entirely
 *   (a wallet collection has no app to name); defaults to true
 * @returns {ConnectedApp[]}   the apps, latest-connected first; empty while
 *   loading, when the load is off, and after a failed load
 */
export function useConnectedApps({
  storage,
  enabled = true
}: {
  storage?: StorageManager
  enabled?: boolean
}): ConnectedApp[] {
  const active = enabled && Boolean(storage?.hasRemoteStorage)
  const { data, error } = useAsyncLoad(
    async (): Promise<ConnectedApp[]> => {
      if (!storage) {
        return []
      }
      return listConnectedApps({ storage })
    },
    [storage],
    {
      enabled: active,
      onError: err => {
        log.warn('Could not load the connected applications', { err })
      }
    }
  )
  if (!active || error) {
    return []
  }
  return data ?? []
}
