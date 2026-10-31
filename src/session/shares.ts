/**
 * The shares surface's glue -- the Storage page's collection list and the
 * dialog behind each row's "Shared" chip: which of the wallet's own
 * collections can be shared, who currently reads them, and removing one
 * reader. The dialog renders and confirms; the reads and the removal live
 * here.
 */
import { ENCRYPTED_WALLET_COLLECTION_IDS } from '@/app.config'
import type { ConnectionEntry } from '@interop/wallet-core/connections'
import type { Session } from '@/types/auth'
import { grantRevocationEvents } from '@/session/applications'

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
 * Fetches every encrypted wallet collection's current reader roster, keyed
 * by PWS collection id, each reader named from the `connections` directory's
 * entries when the caller hands them in. The listing covers every collection
 * with a key-epoch roster, not only the ones a new share may name (the
 * roster's `shareable` flag), so a reader escrowed into a collection that is
 * no longer shareable stays visible and removable. The rosters are read
 * whether or not the directory could be: without its entries the readers are
 * listed unnamed, and a reader a torn unshare left off the current epoch is
 * not listed.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.connections] {ConnectionEntry[]}   the directory's
 *   entries, from the page's one listing read
 * @returns {Promise<Record<string, CollectionShare[]>>}
 */
export async function listSharedCollections({
  session,
  connections
}: {
  session: Session
  connections?: ConnectionEntry[]
}): Promise<Record<string, CollectionShare[]>> {
  const entries = await Promise.all(
    ENCRYPTED_WALLET_COLLECTION_IDS.map(
      async id =>
        [
          id,
          await session.storage.listCollectionShares({
            collectionId: id,
            ...(connections !== undefined ? { connections } : {})
          })
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
 * This is the grant revocation ceremony's unshare entry point, and it emits
 * the run's events.
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
  const events = grantRevocationEvents()
  await events.run(
    async () =>
      await session.storage.unshareCollection({
        profile: session.profile,
        user: session.user,
        collectionId,
        recipientId,
        onStage: (stage, detail) => events.stage(stage, detail)
      })
  )
}
