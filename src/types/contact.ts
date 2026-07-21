/**
 * Contact-related types for the wallet UI. `ContactData` is the shared,
 * platform-neutral contact shape from `@interop/social-core` -- the same type
 * Freewallet mobile uses, so both replicas write byte-compatible payloads
 * into the encrypted `contacts` collection.
 */
export type { ContactData, ContactRevisionPayload } from '@interop/social-core'
import type { ContactData } from '@interop/social-core'

/**
 * A contact as returned by the storage layer: its stable row id (the WAS
 * resourceId of the `contacts` head document) alongside the decrypted data.
 */
export interface StoredContact {
  id: string
  contact: ContactData
  updatedAt: string
}
