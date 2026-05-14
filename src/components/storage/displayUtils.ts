import type { TFunction } from 'i18next'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import { KNOWN_EXTENSIONS, COMMON_CONTENT_TYPES } from '@/app.config'

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
