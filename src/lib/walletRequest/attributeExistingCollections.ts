/**
 * The consent screen's second grant-resolution pass, shared by the CHAPI get
 * popup and the interaction-URL request page: re-resolves the grants with
 * each existing private collection's attribution read in, so a row can say
 * whose collection a request names. The same metadata read says whether the
 * collection is encrypted, so a string target naming an encrypted collection
 * the grantee joins no roster of gets the ciphertext note. A string target
 * naming an encrypted collection also has the collection's current key epoch
 * read, so a grantee already listed there does not get that note. The lean
 * Space listing the first pass consults carries none of this, so the rows
 * show it only once this pass lands.
 */

import type { Session } from '@/types/auth'
import {
  lookupCollectionCreators,
  type CollectionCreator
} from '@/lib/connectedApps'
import { createLogger } from '@/lib/log'
import {
  existingCollectionsFrom,
  resolveGrants,
  type CollectionAttribution,
  type ResolvedGrant
} from './processZcaps'

const log = createLogger('fw:request:attribution')

/**
 * Re-resolves the grants with each existing collection's attribution read in.
 * It reads each such collection's own metadata (the `generator` object), in
 * parallel, joins the creator's display name and canonical `appUrl` from the
 * wallet's records (`lookupCollectionCreators`, keyed by `generator.id`), and
 * resolves again. The joined `appUrl` matters only for a collection stamped
 * without `generator.url`. A string target naming an encrypted collection also
 * gets that collection's current key-epoch recipients
 * (`listCollectionShares`, handed an empty history so it reads no activity).
 * A standard collection's is read at once, usually off the session's cached
 * descriptor. Any other's is read only once its metadata says it is
 * encrypted, so a plaintext collection costs no descriptor read. Every read
 * is best-effort: a failed metadata read leaves that collection
 * unattributed, a failed roster read lists no recipient (the ciphertext
 * note stays), and a failed records lookup leaves every creator unresolved,
 * so a collection this app did not create reads as another application's
 * and names its origin. A caller that has already
 * listed the app keys (the CHAPI get popup's App Connect match) hands the
 * listing in, so the lookup does not read `app-connections` a second time.
 *
 * @param options {object}
 * @param options.resolution {Parameters<typeof resolveGrants>[0]}   the
 *   first pass's inputs
 * @param options.grants {ResolvedGrant[]}   the first pass's result
 * @param options.storage {Session['storage']}
 * @param [options.appKeys] {Awaited<ReturnType<Session['storage']['listAppKeys']>>}
 *   the app-key listing, when the caller already holds one
 * @returns {Promise<ResolvedGrant[] | undefined>}   undefined when no grant
 *   names an existing private collection or a string target's encrypted
 *   collection, so nothing changes
 */
export async function attributeExistingCollections({
  resolution,
  grants,
  storage,
  appKeys
}: {
  resolution: Parameters<typeof resolveGrants>[0]
  grants: ResolvedGrant[]
  storage: Session['storage']
  appKeys?: Awaited<ReturnType<Session['storage']['listAppKeys']>>
}): Promise<ResolvedGrant[] | undefined> {
  const collectionIds = new Set(
    grants.flatMap(({ target }) =>
      target.targetClass === 'collection' &&
      target.collectionId &&
      resolution.collections.has(target.collectionId)
        ? [target.collectionId]
        : []
    )
  )
  // The collections a string target names, whose current key epoch may
  // already list the grantee. `encrypted` on the first pass marks a standard
  // encrypted collection, known without a metadata read.
  const rosterIds = new Map<string, { knownEncrypted: boolean }>()
  for (const { descriptor, target } of grants) {
    if (
      typeof descriptor.invocationTarget === 'string' &&
      descriptor.controller &&
      target.collectionId &&
      resolution.collections.has(target.collectionId)
    ) {
      rosterIds.set(target.collectionId, {
        knownEncrypted:
          target.encrypted ||
          !!rosterIds.get(target.collectionId)?.knownEncrypted
      })
    }
  }
  const knownEncryptedIds = [...rosterIds].flatMap(
    ([collectionId, { knownEncrypted }]) =>
      knownEncrypted ? [collectionId] : []
  )
  if (collectionIds.size === 0 && knownEncryptedIds.length === 0) {
    return undefined
  }
  const rosters = new Map<string, ReadonlySet<string>>()

  /**
   * Reads one collection's current key-epoch recipients into `rosters`.
   *
   * @param collectionId {string}
   * @returns {Promise<void>}
   */
  async function readRoster(collectionId: string): Promise<void> {
    try {
      // An empty history keeps the reader off the activity scan, whose
      // labels this pass does not use.
      const shares = await storage.listCollectionShares({
        collectionId,
        items: []
      })
      rosters.set(
        collectionId,
        new Set(shares.map(({ recipientId }) => recipientId))
      )
    } catch (err) {
      log.warn('Could not read the key epoch of an existing collection', {
        collectionId,
        err
      })
    }
  }

  // A collection whose read fails, or that the store cannot see, is read as
  // unstamped rather than left unread, so its row still says it exists.
  const reads = new Map<
    string,
    { attribution: CollectionAttribution; encrypted: boolean }
  >()
  await Promise.all([
    ...[...collectionIds].map(async collectionId => {
      let encrypted = false
      try {
        const read = await storage.collectionAttribution({ collectionId })
        encrypted = !!read?.encrypted
        reads.set(collectionId, {
          attribution: { generator: read?.generator },
          encrypted
        })
      } catch (err) {
        log.warn('Could not read the attribution of an existing collection', {
          collectionId,
          err
        })
        reads.set(collectionId, { attribution: {}, encrypted: false })
      }
      if (
        encrypted &&
        rosterIds.has(collectionId) &&
        !rosterIds.get(collectionId)?.knownEncrypted
      ) {
        await readRoster(collectionId)
      }
    }),
    ...knownEncryptedIds.map(readRoster)
  ])
  // A stamp carrying both `url` and `name` answers the consent row on its
  // own, so only the others are joined against the wallet's records.
  const generators = [...reads.values()].flatMap(
    ({ attribution: { generator } }) =>
      generator && (generator.url === undefined || generator.name === undefined)
        ? [generator.id]
        : []
  )
  let creators: ReadonlyMap<string, CollectionCreator> = new Map()
  try {
    creators = await lookupCollectionCreators({ storage, generators, appKeys })
  } catch (err) {
    log.warn("Could not look up the existing collections' creators", { err })
  }
  const collections = existingCollectionsFrom(
    [...resolution.collections].map(([id, { isPublic }]) => {
      const read = reads.get(id)
      const recipientIds = rosters.get(id)
      if (!read) {
        return { id, isPublic, recipientIds }
      }
      const { generator } = read.attribution
      const creatorApp = generator ? creators.get(generator.id) : undefined
      return {
        id,
        isPublic,
        attribution: { ...read.attribution, creatorApp },
        encrypted: read.encrypted,
        recipientIds
      }
    })
  )
  return resolveGrants({ ...resolution, collections })
}
