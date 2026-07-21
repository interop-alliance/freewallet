/**
 * Contact-related types for the wallet UI. `ContactData` is the shared,
 * platform-neutral contact shape from `@interop/social-core` -- the same type
 * Freewallet mobile uses, so both replicas write byte-compatible payloads
 * into the encrypted `contacts` collection.
 */
export type { ContactData, ContactRevisionPayload } from '@interop/social-core'
import type { ContactData } from '@interop/social-core'

/**
 * A contact as returned by the storage layer. Two identifiers, deliberately
 * distinct (matching Freewallet mobile, which mints them separately): `id` is
 * the stable row id -- the WAS resourceId of the `contacts` head document, a
 * transport-level key used for row addressing (routes, update/delete) --
 * while `contactId` is the logical contact identity carried inside the head
 * payload (`head.contactId`, mobile's local `_id`), the key every
 * `contacts-history` revision refers to. Only `contactId` is meaningful
 * across replicas; conflating the two breaks history for mobile-authored
 * contacts, whose resourceId differs from their `contactId`.
 */
export interface StoredContact {
  id: string
  contactId: string
  contact: ContactData
  updatedAt: string
}
