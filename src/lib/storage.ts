/**
 * WAS storage type definitions and backend catalogue used by the Settings UI.
 * StorageCollection and StorageResource mirror the JSON shapes returned by the
 * WAS server's list endpoints; see the WAS spec for the authoritative schema.
 */
export type StorageBackend = {
  id: string
  displayName: string
  description: string
  enabled?: boolean
  comingSoon?: boolean
}

export type StorageCollection = {
  id: string
  url: string
  name?: string
  type?: string[]
  totalItems?: number
  /**
   * The wire `CollectionSummary`'s inline `PublicCanRead` flag. Present on
   * every item when the server surfaces it; absent on a server that predates
   * the field (the client then probes the policy itself). UI code reads the
   * resolved `isPublic` instead.
   */
  public?: boolean
  isPublic?: boolean
  isEncrypted?: boolean
}

export type StorageCollectionList = {
  url: string
  totalItems: number
  items: StorageCollection[]
}

export type StorageResource = {
  id: string
  url: string
  name?: string
  contentType?: string
  type?: string[]
  created?: string
  modified?: string
  updated?: string
  size?: number
  isPublic?: boolean
}

export type StorageResourceList = {
  id?: string
  url: string
  name?: string
  type?: string[]
  totalItems: number
  items: StorageResource[]
}

export function getBackends(): StorageBackend[] {
  return [
    {
      id: 'default',
      displayName: 'Default Backend',
      description: 'Wallet Attached Storage',
      enabled: true
    },
    {
      id: 'google-drive',
      displayName: 'Google Drive',
      description: 'Coming soon',
      enabled: false,
      comingSoon: true
    }
  ]
}
