/**
 * Attributing a stored collection to the application it was provisioned for,
 * for the storage browser's "Created by" line.
 *
 * The signal is the Collection Metadata object's `generator.id`, the app's
 * did:key stamped when App Connect provisioning created the collection. It is
 * answered by `lookupCollectionCreators`, the same reader the consent row
 * uses, so a disconnected creator is named the same way on every surface. A
 * collection carrying no `generator` is unattributed.
 */
import type { CollectionCreator } from '@/lib/connectedApps'
import type { StorageCollection } from '@/lib/storage'
import type { CollectionGenerator } from '@interop/was-client'

/**
 * Maps each collection whose creator the wallet's records name onto that
 * creator. Collections with no attribution, and collections naming an app no
 * record knows, are absent from the map.
 *
 * @param options {object}
 * @param options.collections {StorageCollection[]}   the Space's listing
 * @param options.creators {ReadonlyMap<string, CollectionCreator>}
 *   `lookupCollectionCreators` output, keyed by `generator.id` DID
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
      ? creators.get(collection.generator.id)
      : undefined
    if (creator) {
      attribution.set(collection.id, creator)
    }
  }
  return attribution
}

/**
 * The name every surface shows for the application that created a
 * collection: the collection's own `generator.name`, else the name the
 * wallet's records hold for the creator, else the stamped `generator.origin`.
 *
 * @param options {object}
 * @param [options.generator] {CollectionGenerator}   the collection's stamp
 * @param [options.recordName] {string}   the name the wallet's records hold
 *   for the creator, if any
 * @returns {string | undefined}   undefined when nothing names the creator
 */
export function collectionCreatorLabel({
  generator,
  recordName
}: {
  generator?: CollectionGenerator
  recordName?: string
}): string | undefined {
  return generator?.name ?? recordName ?? generator?.origin
}
