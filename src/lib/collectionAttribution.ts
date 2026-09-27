/**
 * Attributing a stored collection to the application it was provisioned for,
 * for the storage browser's "Created by" line.
 *
 * The signal is the Collection Metadata object's `generator`, the app's
 * did:key stamped when App Connect provisioning created the collection. It is
 * answered by `lookupCollectionCreators`, the same reader the consent row
 * uses, so a disconnected creator is named the same way on every surface. A
 * collection carrying no `generator` is unattributed.
 */
import type { CollectionCreator } from '@/lib/connectedApps'
import type { StorageCollection } from '@/lib/storage'

/**
 * Maps each collection whose creator the wallet's records name onto that
 * creator. Collections with no attribution, and collections naming an app no
 * record knows, are absent from the map.
 *
 * @param options {object}
 * @param options.collections {StorageCollection[]}   the Space's listing
 * @param options.creators {ReadonlyMap<string, CollectionCreator>}
 *   `lookupCollectionCreators` output, keyed by `generator` DID
 * @returns {Map<string, CollectionCreator>}   keyed by collection id
 */
export function attributeCollectionsToApps({
  collections,
  creators
}: {
  collections: StorageCollection[]
  creators: ReadonlyMap<string, CollectionCreator>
}): Map<string, CollectionCreator> {
  const attribution = new Map<string, CollectionCreator>()
  for (const collection of collections) {
    const creator = collection.generator
      ? creators.get(collection.generator)
      : undefined
    if (creator) {
      attribution.set(collection.id, creator)
    }
  }
  return attribution
}
