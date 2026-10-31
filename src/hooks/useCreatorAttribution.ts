/**
 * Both creator signals one storage-browser page shows for a collection or a
 * Resource. The controller-asserted one is the collection's `generator`
 * stamp, whose app creator `useCollectionCreators` names. The
 * server-observed one is the object's `createdBy`, which `resolveCreatedBy`
 * names against the DIDs the wallet itself invokes as (`walletOwnDids`) and
 * the party `lookupCreatedByParty` finds. The wallet check runs first, off
 * the memoized verified log: a `createdBy` the wallet invokes as (the common
 * case, every object the wallet itself wrote) reads the directory only when
 * an app stamp needs naming. Both lookups match in memory against one read
 * of the `connections` directory, with no GET at the id a DID derives to.
 * The load is non-blocking: a failed directory read is logged and names no
 * party, so the lines fall back to the stamped origin and the shortened DID
 * rather than the page failing.
 */
import { useMemo } from 'react'
import type { ReadConnection } from '@interop/wallet-core/connections'
import type { CollectionGenerator } from '@interop/pws-client'
import {
  appGeneratorIds,
  recordedCreatorOf,
  resolveCreatedBy,
  type CreatedByAttribution
} from '@/lib/collectionAttribution'
import {
  lookupCreatedByParty,
  type CollectionCreator,
  type CreatedByParty
} from '@/lib/connectedApps'
import { createLogger } from '@/lib/log'
import { readDirectoryListing, walletOwnDids } from '@/session/clients'
import type { Session } from '@/types/auth'
import { useAsyncLoad } from './useAsyncLoad'
import { useCollectionCreators } from './useCollectionCreators'

const log = createLogger('fw:ui:storage')

const NO_DIDS: ReadonlySet<string> = new Set()

/**
 * @param options {object}
 * @param options.session {Session | null}   the live session
 * @param [options.generator] {CollectionGenerator}   the collection's stamp
 *   (absent on a Resource page and on an unstamped collection)
 * @param [options.createdBy] {string}   the object's server-observed
 *   `createdBy`, absent when the server recorded none or it is unread
 * @param options.observedRead {boolean}   whether the object carrying
 *   `createdBy` has been read; false leaves the server-observed line
 *   unresolved rather than claiming the server recorded none
 * @returns {{ creator?: CollectionCreator; createdBy?: CreatedByAttribution }}
 *   the stamp's recorded app creator, and the server-observed creator once
 *   it resolves
 */
export function useCreatorAttribution({
  session,
  generator,
  createdBy,
  observedRead
}: {
  session: Session | null | undefined
  generator?: CollectionGenerator
  createdBy?: string
  observedRead: boolean
}): { creator?: CollectionCreator; createdBy?: CreatedByAttribution } {
  const appStampId = appGeneratorIds([generator])[0]
  const active =
    Boolean(session?.storage?.hasRemoteStorage) &&
    (appStampId !== undefined || createdBy !== undefined)
  const { data, loading } = useAsyncLoad(
    async (): Promise<{
      walletDids: ReadonlySet<string>
      directory: { connections: ReadConnection[]; spaceUrl?: string } | null
      party?: CreatedByParty
    } | null> => {
      if (!session) {
        return null
      }
      const walletDids =
        createdBy === undefined ? NO_DIDS : await walletOwnDids({ session })
      const foreignDid =
        createdBy !== undefined && !walletDids.has(createdBy)
          ? createdBy
          : undefined
      if (appStampId === undefined && foreignDid === undefined) {
        return { walletDids, directory: null }
      }
      const directory = await readDirectoryListing({ session }).catch(
        (err: unknown) => {
          log.warn("Could not look up the creators' names", { err })
          return null
        }
      )
      const party =
        directory && foreignDid !== undefined
          ? await lookupCreatedByParty({
              storage: session.storage,
              connections: directory.connections,
              spaceUrl: directory.spaceUrl,
              did: foreignDid
            })
          : undefined
      return { walletDids, directory, party }
    },
    [session, appStampId, createdBy],
    { enabled: active }
  )
  // The stamp lookup reads the directory this hook read (or none, while it
  // loads or when the read failed), so the page pays for one listing.
  const creators = useCollectionCreators({
    session,
    generators: [generator],
    directory: data?.directory ?? null
  })
  const creator = recordedCreatorOf({ generator, creators })
  const observed = useMemo(() => {
    if (!observedRead) {
      return undefined
    }
    if (!active) {
      // Nothing to look up: no `createdBy` recorded, or no remote storage to
      // read the directory from.
      return resolveCreatedBy({ createdBy, walletDids: NO_DIDS })
    }
    if (loading || !data) {
      return undefined
    }
    return resolveCreatedBy({
      createdBy,
      walletDids: data.walletDids,
      ...(data.party && { party: data.party })
    })
  }, [observedRead, active, loading, data, createdBy])
  return {
    ...(creator && { creator }),
    ...(observed && { createdBy: observed })
  }
}
