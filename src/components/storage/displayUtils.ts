import type { TFunction } from 'i18next'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import {
  ID_COLLECTION,
  KNOWN_EXTENSIONS,
  COMMON_CONTENT_TYPES,
  UNLOCK_METHODS_COLLECTION,
  WALLET_STANDARD_COLLECTIONS
} from '@/app.config'

// The Storage page's collection categories: the user's credential collections
// first, then collections registered by connected applications/sites, then the
// wallet's own plumbing (activity log, identity, unlock methods).
const CONTENTS_COLLECTION_IDS = ['private-credentials', 'public-credentials']
const SYSTEM_COLLECTION_IDS = [
  ...WALLET_STANDARD_COLLECTIONS.map(({ id }) => id).filter(
    id => !CONTENTS_COLLECTION_IDS.includes(id)
  ),
  ID_COLLECTION.id,
  UNLOCK_METHODS_COLLECTION.id
]

/**
 * Splits the listed collections into the Storage page's three display groups.
 * Group-internal order is the declaration order above for the known wallet
 * collections, and display-name order for application collections (anything
 * whose id the wallet does not recognize is, by definition, externally
 * registered).
 *
 * @param options {object}
 * @param options.collections {StorageCollection[]}
 * @returns {{contents, app, system}} The three groups, each possibly empty.
 */
export function groupCollections({
  collections
}: {
  collections: StorageCollection[]
}): {
  contents: StorageCollection[]
  app: StorageCollection[]
  system: StorageCollection[]
} {
  const byId = new Map(
    collections.map(collection => [collection.id, collection])
  )
  const known = (ids: string[]) =>
    ids.flatMap(id => {
      const collection = byId.get(id)
      return collection ? [collection] : []
    })
  const app = collections
    .filter(
      ({ id }) =>
        !CONTENTS_COLLECTION_IDS.includes(id) &&
        !SYSTEM_COLLECTION_IDS.includes(id)
    )
    .sort((left, right) =>
      getCollectionDisplayName(left).localeCompare(
        getCollectionDisplayName(right)
      )
    )
  return {
    contents: known(CONTENTS_COLLECTION_IDS),
    app,
    system: known(SYSTEM_COLLECTION_IDS)
  }
}

export function getCollectionDisplayName(
  collection: StorageCollection
): string {
  if (collection.name && collection.name.trim().length > 0) {
    return collection.name
  }
  return collection.id
}

export function getResourceDisplayName(resource: StorageResource): string {
  const raw =
    resource.name && resource.name.trim().length > 0
      ? resource.name
      : resource.id
  return raw.replace(KNOWN_EXTENSIONS, '')
}

/**
 * Resolves a "Type" label for a resource. Prefers structured `type` fields,
 * then a readable shorthand derived from `contentType`.
 */
export function getResourceTypeLabel(
  resource: StorageResource,
  t: TFunction
): string {
  if (resource.type && resource.type.length > 0) {
    // Prefer the most specific structured type
    return resource.type[resource.type.length - 1]
  }
  if (!resource.contentType) {
    return t('common.na')
  }
  const ct = resource.contentType.toLowerCase().trim()
  if (COMMON_CONTENT_TYPES[ct]) {
    return COMMON_CONTENT_TYPES[ct]
  }
  // Fallback
  const slashIdx = ct.indexOf('/')
  if (slashIdx > -1) {
    return ct.slice(slashIdx + 1).toUpperCase()
  }
  return resource.contentType
}

/**
 * Returns the best available "modified" timestamp for a resource, in ISO form.
 */
export function getResourceModifiedIso(
  resource: StorageResource
): string | undefined {
  return resource.modified ?? resource.updated ?? resource.created
}
