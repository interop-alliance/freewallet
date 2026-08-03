/**
 * The "Shared collections" settings surface's glue: which of the wallet's own
 * collections can be shared, who currently reads them, and removing one
 * reader. The panel renders and confirms; the reads and the removal live here.
 */
import { WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import type { Session } from '@/types/auth'

/**
 * One reader a collection is shared with, as returned by
 * `StorageManager.listCollectionShares`.
 */
export interface CollectionShare {
  recipientId: string
  controller?: string
  expires?: string
  appName?: string
  appOrigin?: string
}

/**
 * The encrypted standard collections -- the only ones that can be shared,
 * since a share adds the reader to a key-epoch roster and there is no roster
 * where nothing is encrypted.
 */
export const SHAREABLE_COLLECTIONS = WALLET_STANDARD_COLLECTIONS.filter(
  ({ encryption }) => encryption
)

/**
 * Fetches every shareable collection's current reader roster, keyed by WAS
 * collection id.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<Record<string, CollectionShare[]>>}
 */
export async function listSharedCollections({
  session
}: {
  session: Session
}): Promise<Record<string, CollectionShare[]>> {
  const entries = await Promise.all(
    SHAREABLE_COLLECTIONS.map(
      async ({ id }) =>
        [
          id,
          await session.storage.listCollectionShares({ collectionId: id })
        ] as const
    )
  )
  return Object.fromEntries(entries) as Record<string, CollectionShare[]>
}

/**
 * Removes one reader's access to a shared collection. Both halves of the
 * grant go together: `unshareCollection` rotates the collection's key epoch
 * (so resources written afterwards are unreadable to the removed reader) and
 * revokes its storage authorization (so the server stops serving it
 * ciphertext). Neither half claws back data the reader already fetched.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.collectionId {string}
 * @param options.recipientId {string}
 * @returns {Promise<void>}
 */
export async function removeCollectionShare({
  session,
  collectionId,
  recipientId
}: {
  session: Session
  collectionId: string
  recipientId: string
}): Promise<void> {
  await session.storage.unshareCollection({
    profile: session.profile,
    user: session.user,
    collectionId,
    recipientId
  })
}
