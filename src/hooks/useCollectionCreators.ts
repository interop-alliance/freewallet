/**
 * The applications behind the storage browser's "Created by" line, loaded
 * over `lookupCollectionCreators`, the same reader the consent row uses. The
 * load is non-blocking: a failure is logged and reads as no creators, so the
 * line falls back to the stamped origin rather than the page failing. It runs
 * only where the line can name an app: a session with remote storage and at
 * least one app stamp to look up. An agent's stamp names itself, and is
 * dropped by the reader.
 */
import {
  lookupCollectionCreators,
  type CollectionCreator
} from '@/lib/connectedApps'
import { appGeneratorIds } from '@/lib/collectionAttribution'
import type { CollectionGenerator } from '@interop/was-client'
import { createLogger } from '@/lib/log'
import type { HistoryItems, StorageManager } from '@/stores/storageManager'
import { useAsyncLoad } from './useAsyncLoad'

const log = createLogger('fw:ui:storage')

/**
 * One shared empty result, so a disabled, loading, or failed hook keeps a
 * stable identity across renders and the consumers' memos hold.
 */
const NO_CREATORS: ReadonlyMap<string, CollectionCreator> = new Map()

/**
 * @param options {object}
 * @param [options.storage] {StorageManager}   the session's storage
 * @param options.generators {Array<CollectionGenerator | undefined>}   the
 *   collections' stamps; a list with no app stamp leaves the load off
 * @param [options.items] {HistoryItems}
 *   the activity history, when the caller has already read it; the load then
 *   runs no history read of its own
 * @param [options.enabled] {boolean}   false leaves the load off entirely
 *   (the caller's own history read has not landed); defaults to true
 * @returns {ReadonlyMap<string, CollectionCreator>}   keyed by `generator.id`
 *   DID; empty while loading, when the load is off, and after a failed load
 */
export function useCollectionCreators({
  storage,
  generators,
  items,
  enabled = true
}: {
  storage?: StorageManager
  generators: Array<CollectionGenerator | undefined>
  items?: HistoryItems
  enabled?: boolean
}): ReadonlyMap<string, CollectionCreator> {
  // A value key over the app stamps' ids, so a caller rebuilding the same
  // list each render does not re-run the load.
  const generatorsKey = [...new Set(appGeneratorIds(generators))]
    .sort()
    .join(' ')
  const active =
    enabled && generatorsKey !== '' && Boolean(storage?.hasRemoteStorage)
  const { data, error } = useAsyncLoad(
    async (): Promise<ReadonlyMap<string, CollectionCreator>> => {
      if (!storage) {
        return NO_CREATORS
      }
      return lookupCollectionCreators({ storage, generators, items })
    },
    // `generatorsKey` stands in for `generators`: the load re-runs when the
    // app stamps' ids change, not when the caller rebuilds an equal list.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [storage, items, generatorsKey],
    {
      enabled: active,
      onError: err => {
        log.warn("Could not look up the collections' creators", { err })
      }
    }
  )
  if (!active || error) {
    return NO_CREATORS
  }
  return data ?? NO_CREATORS
}
