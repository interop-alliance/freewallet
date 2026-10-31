/**
 * Attributing a stored collection to the requester (an app, service, or
 * agent) it was provisioned for, for the storage browser's "Created by" line.
 *
 * The signal is the Collection Metadata object's `generator`. App Connect
 * provisioning stamps the app's did:key as `id` beside the Web origin it was
 * bound to (`origin`). That app stamp is answered by
 * `lookupCollectionCreators`, the same reader the consent row uses, so a
 * disconnected creator is named the same way on every surface. An
 * interaction-URL grant stamps the agent's did:key as `id` with no `origin`,
 * and at most its self-declared `name`. An agent holds no app key and writes
 * no App Connect Grant, so its stamp is never looked up. It is named by
 * `generator.name`, else by a shortened `generator.id`. A collection carrying
 * no `generator` is unattributed.
 *
 * A collection and a Resource also carry a second creator signal, the
 * server-observed `createdBy`: the DID whose capability invocation created
 * it, recorded by the server on the first write, read-only, and optional.
 * The two differ by design under delegated provisioning, where the wallet
 * creates an app's collection, so the surfaces show them as two labeled
 * lines rather than one. `resolveCreatedBy` names the `createdBy` DID: the
 * wallet itself for any DID the wallet invokes as, a party's name off its
 * `connections` entry, else the shortened DID. Neither signal is verified
 * identity.
 */
import type { CollectionCreator, CreatedByParty } from '@/lib/connectedApps'
import type { StorageCollection } from '@/lib/storage'
import type { CollectionGenerator } from '@interop/pws-client'

/**
 * The head and tail a shortened DID keeps around `...`: the method prefix
 * plus enough of the key to tell two apart.
 */
const SHORT_DID_HEAD_CHARS = 16
const SHORT_DID_TAIL_CHARS = 6

/**
 * Whether a `generator` stamp names an application the wallet's records can
 * know: one carrying an `origin`, which App Connect provisioning always
 * stamps. A stamp without one names an interaction-URL agent, which holds no
 * app key and has no App Connect Grant to look up.
 *
 * @param [generator] {CollectionGenerator}
 * @returns {boolean}
 */
function isAppGenerator(
  generator?: CollectionGenerator
): generator is CollectionGenerator & { origin: string } {
  return generator?.origin !== undefined
}

/**
 * The `generator.id` DIDs the wallet's records can answer, out of a set of
 * stamps: the app stamps' alone, the agent stamps and the unstamped dropped.
 *
 * @param generators {Iterable<CollectionGenerator | undefined>}
 * @returns {string[]}
 */
export function appGeneratorIds(
  generators: Iterable<CollectionGenerator | undefined>
): string[] {
  return [...generators].flatMap(generator =>
    isAppGenerator(generator) ? [generator.id] : []
  )
}

/**
 * The creator the wallet's records hold for a collection's stamp: the
 * `lookupCollectionCreators` entry under an app stamp's `generator.id`. An
 * agent's stamp gets none, even when a record shares its DID.
 *
 * @param options {object}
 * @param [options.generator] {CollectionGenerator}   the collection's stamp
 * @param options.creators {ReadonlyMap<string, CollectionCreator>}
 *   `lookupCollectionCreators` output, keyed by `generator.id` DID
 * @returns {CollectionCreator | undefined}
 */
export function recordedCreatorOf({
  generator,
  creators
}: {
  generator?: CollectionGenerator
  creators: ReadonlyMap<string, CollectionCreator>
}): CollectionCreator | undefined {
  return isAppGenerator(generator) ? creators.get(generator.id) : undefined
}

/**
 * A DID shortened for display: its head and tail around `...`. A DID no
 * longer than the shortened form is returned as it is.
 *
 * @param did {string}
 * @returns {string}
 */
function shortDid(did: string): string {
  if (did.length <= SHORT_DID_HEAD_CHARS + SHORT_DID_TAIL_CHARS + 3) {
    return did
  }
  return `${did.slice(0, SHORT_DID_HEAD_CHARS)}...${did.slice(-SHORT_DID_TAIL_CHARS)}`
}

/**
 * Maps each collection whose creator the wallet's records name onto that
 * creator. Collections with no attribution, collections stamped for an agent
 * (no `generator.origin`), and collections naming an app no record knows are
 * absent from the map.
 *
 * @param options {object}
 * @param options.collections {StorageCollection[]}   the Space's listing
 * @param options.creators {ReadonlyMap<string, CollectionCreator>}
 *   `lookupCollectionCreators` output, keyed by `generator.id` DID
 * @returns {Map<string, CollectionCreator>}   keyed by collection id
 */
export function attributeCollectionsToApps({
  collections,
  creators
}: {
  collections: StorageCollection[]
  creators: ReadonlyMap<string, CollectionCreator>
}): Map<string, CollectionCreator> {
  const attribution = new Map<string, CollectionCreator>()
  for (const collection of collections) {
    const creator = recordedCreatorOf({
      generator: collection.generator,
      creators
    })
    if (creator) {
      attribution.set(collection.id, creator)
    }
  }
  return attribution
}

/**
 * The name every surface shows for the party that created a collection. An
 * app stamp names it by the collection's own `generator.name`, else the name
 * the wallet's records hold for the creator, else the stamped
 * `generator.origin`. An agent stamp (no `origin`) names it by
 * `generator.name`, else by the shortened `generator.id`, and ignores
 * `recordName`, since no record describes an agent.
 *
 * @param options {object}
 * @param [options.generator] {CollectionGenerator}   the collection's stamp
 * @param [options.recordName] {string}   the name the wallet's records hold
 *   for the creator, if any
 * @returns {string | undefined}   undefined when nothing names the creator
 */
export function collectionCreatorLabel({
  generator,
  recordName
}: {
  generator?: CollectionGenerator
  recordName?: string
}): string | undefined {
  if (generator && !isAppGenerator(generator)) {
    return generator.name ?? shortDid(generator.id)
  }
  return generator?.name ?? recordName ?? generator?.origin
}

/**
 * What a surface shows for a `createdBy` DID: `not-recorded` when the server
 * recorded none, `wallet` when the DID is one the wallet invokes as, `party`
 * when a `connections` entry names it (linked while `resourceId` is set),
 * and `unknown` with the shortened DID as its name otherwise.
 */
export type CreatedByAttribution =
  | { kind: 'not-recorded' }
  | { kind: 'wallet' }
  | { kind: 'party'; name: string; resourceId?: string }
  | { kind: 'unknown'; name: string }

/**
 * Names the server-observed creator of a collection or a Resource. The
 * wallet arm comes first: the account's did:webvh, every wallet client's
 * did:key the account document lists or ever listed, and the client-annex
 * DID a transient session invokes as all read as the wallet itself, so the
 * common case does not show as a foreign creator. A party the directory
 * names (an app, an agent, a share recipient) is shown by its entry's name.
 * Any other DID is shown shortened.
 *
 * @param options {object}
 * @param [options.createdBy] {string}   the object's `createdBy`, absent
 *   when the server recorded none
 * @param options.walletDids {ReadonlySet<string>}   the DIDs the wallet
 *   invokes as (`walletOwnDids`)
 * @param [options.party] {CreatedByParty}   `lookupCreatedByParty`'s answer
 *   for `createdBy`, when the directory names it
 * @returns {CreatedByAttribution}
 */
export function resolveCreatedBy({
  createdBy,
  walletDids,
  party
}: {
  createdBy?: string
  walletDids: ReadonlySet<string>
  party?: CreatedByParty
}): CreatedByAttribution {
  if (createdBy === undefined || createdBy === '') {
    return { kind: 'not-recorded' }
  }
  if (walletDids.has(createdBy)) {
    return { kind: 'wallet' }
  }
  if (party) {
    return { kind: 'party', ...party }
  }
  return { kind: 'unknown', name: shortDid(createdBy) }
}
