/**
 * The consent screen's second grant-resolution pass, shared by the CHAPI get
 * popup and the interaction-URL request page: re-resolves the grants with
 * each existing private collection's attribution read in, so a row can say
 * whose collection a request names. The lean Space listing the first pass
 * consults carries no attribution, so that pass reports no
 * existing-collection reading, and the rows show none until this one lands.
 */

import type { Session } from '@/types/auth'
import { lookupCollectionCreators } from '@/lib/connectedApps'
import { createLogger } from '@/lib/log'
import {
  existingCollectionsFrom,
  resolveGrants,
  type CollectionAttribution,
  type ResolvedGrant
} from './processZcaps'

const log = createLogger('fw:request:attribution')

/**
 * Re-resolves the grants with each existing collection's attribution read in.
 * It reads each such collection's own metadata (`generator`,
 * `generatorOrigin`), in parallel, joins the creator's canonical `appUrl`
 * and display name from the wallet's records (`lookupCollectionCreators`),
 * and resolves again. Every read is best-effort: a failed metadata read
 * leaves that collection unattributed, and a failed records lookup leaves
 * every creator unresolved, so a collection this app did not create reads
 * as another application's and names its origin.
 *
 * @param options {object}
 * @param options.resolution {Parameters<typeof resolveGrants>[0]}   the
 *   first pass's inputs
 * @param options.grants {ResolvedGrant[]}   the first pass's result
 * @param options.storage {Session['storage']}
 * @returns {Promise<ResolvedGrant[] | undefined>}   undefined when no grant
 *   names an existing private collection, so nothing changes
 */
export async function attributeExistingCollections({
  resolution,
  grants,
  storage
}: {
  resolution: Parameters<typeof resolveGrants>[0]
  grants: ResolvedGrant[]
  storage: Session['storage']
}): Promise<ResolvedGrant[] | undefined> {
  const collectionIds = new Set(
    grants.flatMap(({ target }) =>
      target.targetClass === 'collection' &&
      target.collectionId &&
      resolution.collections.has(target.collectionId)
        ? [target.collectionId]
        : []
    )
  )
  if (collectionIds.size === 0) {
    return undefined
  }
  // A collection whose read fails, or that the store cannot see, is read as
  // unstamped rather than left unread, so its row still says it exists.
  const attributions = new Map<string, CollectionAttribution>()
  await Promise.all(
    [...collectionIds].map(async collectionId => {
      try {
        const attribution = await storage.collectionAttribution({
          collectionId
        })
        attributions.set(collectionId, attribution ?? {})
      } catch (err) {
        log.warn('Could not read the attribution of an existing collection', {
          collectionId,
          err
        })
        attributions.set(collectionId, {})
      }
    })
  )
  const generators = [...attributions.values()].flatMap(({ generator }) =>
    generator ? [generator] : []
  )
  let creators: ReadonlyMap<string, { name: string; appUrl: string }> =
    new Map()
  try {
    creators = await lookupCollectionCreators({ storage, generators })
  } catch (err) {
    log.warn("Could not look up the existing collections' creators", { err })
  }
  const collections = existingCollectionsFrom(
    [...resolution.collections].map(([id, { isPublic }]) => {
      const attribution = attributions.get(id)
      const creatorApp = attribution?.generator
        ? creators.get(attribution.generator)
        : undefined
      return {
        id,
        isPublic,
        attribution: attribution && { ...attribution, creatorApp }
      }
    })
  )
  return resolveGrants({ ...resolution, collections })
}
