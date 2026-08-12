import type { TFunction } from 'i18next'
import { CONTACTS_COLLECTION } from '@interop/social-core'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import {
  KNOWN_EXTENSIONS,
  COMMON_CONTENT_TYPES,
  SYSTEM_COLLECTIONS,
  WALLET_STANDARD_COLLECTIONS
} from '@/app.config'

// The Storage page's collection categories: the user's credential and contact
// collections first, then collections registered by connected
// applications/sites, then the wallet's own plumbing (activity logs, identity,
// unlock methods).
const CONTENTS_COLLECTION_IDS = [
  'private-credentials',
  'public-credentials',
  CONTACTS_COLLECTION
]
const SYSTEM_COLLECTION_IDS = [
  ...WALLET_STANDARD_COLLECTIONS.map(({ id }) => id).filter(
    id => !CONTENTS_COLLECTION_IDS.includes(id)
  ),
  ...SYSTEM_COLLECTIONS.map(({ id }) => id)
]

// The wallet's canonical (untranslated) names for the collections it
// provisions itself, used as the fallback for the localized
// `storage.collectionNames.<id>` keys. Preferred over the server-stored name
// so a rename here takes effect on existing spaces too (the stored name is
// set once at provisioning).
const CANONICAL_COLLECTION_NAMES = new Map<string, string>([
  ...WALLET_STANDARD_COLLECTIONS.map(
    ({ id, name }) => [id, name] as [string, string]
  ),
  ...SYSTEM_COLLECTIONS.map(({ id, name }) => [id, name] as [string, string])
])

/**
 * Splits the listed collections into the Storage page's three display groups,
 * each sorted alphabetically by display name (anything whose id the wallet
 * does not recognize is, by definition, externally registered and lands in the
 * application group).
 *
 * @param options {object}
 * @param options.collections {StorageCollection[]}
 * @param options.t {TFunction}
 * @returns {{contents, app, system}} The three groups, each possibly empty.
 */
export function groupCollections({
  collections,
  t
}: {
  collections: StorageCollection[]
  t: TFunction
}): {
  contents: StorageCollection[]
  app: StorageCollection[]
  system: StorageCollection[]
} {
  const byDisplayName = (left: StorageCollection, right: StorageCollection) =>
    getCollectionDisplayName({ collection: left, t }).localeCompare(
      getCollectionDisplayName({ collection: right, t })
    )
  const known = (ids: string[]) =>
    collections.filter(({ id }) => ids.includes(id)).sort(byDisplayName)
  const app = collections
    .filter(
      ({ id }) =>
        !CONTENTS_COLLECTION_IDS.includes(id) &&
        !SYSTEM_COLLECTION_IDS.includes(id)
    )
    .sort(byDisplayName)
  return {
    contents: known(CONTENTS_COLLECTION_IDS),
    app,
    system: known(SYSTEM_COLLECTION_IDS)
  }
}

/**
 * Resolves the display name for a collection, preferring the canonical
 * translated name for a wallet collection over its stored one.
 *
 * @param options {object}
 * @param options.collection {StorageCollection}
 * @param options.t {TFunction}
 * @returns {string}
 */
export function getCollectionDisplayName({
  collection,
  t
}: {
  collection: StorageCollection
  t: TFunction
}): string {
  const canonical = CANONICAL_COLLECTION_NAMES.get(collection.id)
  if (canonical) {
    return t(`storage.collectionNames.${collection.id}`, {
      defaultValue: canonical
    })
  }
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
export function getResourceTypeLabel({
  resource,
  t
}: {
  resource: StorageResource
  t: TFunction
}): string {
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
