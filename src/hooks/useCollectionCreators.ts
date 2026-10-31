/**
 * The applications behind the storage browser's "Created by" line, looked up
 * over `lookupCollectionCreators`, the same reader the consent row uses: each
 * app `generator.id` stamp matched in memory against one read of the
 * `connections` directory, with no GET at the id a DID derives to. A caller
 * that already read the directory hands its listing in, and the lookup reads
 * nothing more; otherwise the hook reads it once. The load is non-blocking: a
 * failure is logged and reads as no creators, so the line falls back to the
 * stamped origin rather than the page failing. It runs only where the line
 * can name an app: a session with remote storage and at least one app stamp
 * to look up. An agent's stamp names itself, and is dropped by the reader.
 */
import { useMemo } from 'react'
import type { ReadConnection } from '@interop/wallet-core/connections'
import {
  lookupCollectionCreators,
  type CollectionCreator
} from '@/lib/connectedApps'
import { appGeneratorIds } from '@/lib/collectionAttribution'
import type { CollectionGenerator } from '@interop/pws-client'
import { createLogger } from '@/lib/log'
import { readDirectoryListing } from '@/session/clients'
import type { Session } from '@/types/auth'
import { useAsyncLoad } from './useAsyncLoad'

const log = createLogger('fw:ui:storage')

/**
 * One shared empty result, so a disabled, loading, or failed hook keeps a
 * stable identity across renders and the consumers' memos hold.
 */
const NO_CREATORS: ReadonlyMap<string, CollectionCreator> = new Map()

/**
 * @param options {object}
 * @param options.session {Session | null}   the live session
 * @param options.generators {Array<CollectionGenerator | undefined>}   the
 *   collections' stamps; a list with no app stamp leaves the lookup off
 * @param [options.directory] {object}   the directory listing, when the
 *   caller has already read it (`{ connections, spaceUrl }`); `null` when
 *   the caller's read failed, which leaves the lookup empty
 * @returns {ReadonlyMap<string, CollectionCreator>}   keyed by `generator.id`
 *   DID; empty while loading, when the lookup is off, and after a failed read
 */
export function useCollectionCreators({
  session,
  generators,
  directory
}: {
  session: Session | null | undefined
  generators: Array<CollectionGenerator | undefined>
  directory?: { connections: ReadConnection[]; spaceUrl?: string } | null
}): ReadonlyMap<string, CollectionCreator> {
  // A value key over the app stamps' ids, so a caller rebuilding the same
  // list each render does not re-run the lookup.
  const generatorsKey = [...new Set(appGeneratorIds(generators))]
    .sort()
    .join(' ')
  const active =
    generatorsKey !== '' && Boolean(session?.storage?.hasRemoteStorage)
  const { data: ownDirectory, error } = useAsyncLoad(
    async () => (session ? readDirectoryListing({ session }) : null),
    [session],
    {
      enabled: active && directory === undefined,
      onError: err => {
        log.warn("Could not look up the collections' creators", { err })
      }
    }
  )
  const read = directory === undefined ? ownDirectory : directory
  return useMemo(() => {
    if (!active || error || !read) {
      return NO_CREATORS
    }
    return lookupCollectionCreators({
      connections: read.connections,
      spaceUrl: read.spaceUrl,
      generators
    })
    // `generatorsKey` stands in for `generators`: the lookup re-runs when
    // the app stamps' ids change, not when the caller rebuilds an equal list.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, error, read, generatorsKey])
}
