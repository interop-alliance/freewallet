/**
 * WAS storage type definitions used by the Settings UI.
 * StorageCollection and StorageResource mirror the JSON shapes returned by the
 * WAS server's list endpoints; see the WAS spec for the authoritative schema.
 */
import type { CollectionGenerator } from '@interop/pws-client'

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
  /**
   * The application this collection was provisioned for (its DID, the Web
   * origin that DID was bound to, and its canonical app URL),
   * controller-asserted at App Connect provisioning time.
   */
  generator?: CollectionGenerator
  /**
   * The DID whose capability invocation created this collection, as the
   * server observed it on the first write: read-only, optional, and not
   * verified identity. Read off the same Collection Metadata object as
   * `generator`, so carrying it costs the listing nothing. The Storage
   * page's listing does not show it; the collection contents page does.
   */
  createdBy?: string
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
