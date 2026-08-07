/**
 * WAS storage type definitions used by the Settings UI.
 * StorageCollection and StorageResource mirror the JSON shapes returned by the
 * WAS server's list endpoints; see the WAS spec for the authoritative schema.
 */
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
