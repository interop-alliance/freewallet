/**
 * Zcap request processing for App Connect and the interaction-URL page:
 * resolves each requested
 * capability's abstract `invocationTarget` descriptor onto the user's own WAS
 * Space, delegates a capability to the relying party's DID, and provisions
 * any missing RP collection. Every delegation is signed before any collection
 * is provisioned, so the caller can persist the signed grants before a
 * provisioning step escrows the grantee into a key epoch. All delegations are rooted at the user's Space root
 * capability (`urn:zcap:root:<spaceUrl>`); targets outside the Space are
 * unsatisfiable by construction.
 *
 * Attenuation is a table, not a switch: every resolved target falls into one
 * target class, and each class has an action ceiling (`ACTION_CEILINGS`) that
 * the requested actions are intersected against. The requested actions are
 * first normalized against the closed WAS action vocabulary, so a token the
 * spec does not define never reaches an `allowedAction` the user's root key
 * signs. The classes:
 *
 * - a protected wallet collection -- the standard collections
 *   (`private-credentials`, `public-credentials`, `wallet-activity`) plus the
 *   account's grantable system collection (`id`) -- read-only: an RP may read
 *   but not rewrite or delete the user's own credentials or published
 *   identity;
 * - a share -- read-only (see below);
 * - a public collection -- the full vocabulary, the same as a private RP
 *   collection: published content is still the RP's own data, and
 *   un-publishing (`DELETE`) or revising (`PUT`) it is as much data management
 *   as publishing it. Retraction removes the stored copy, not copies already
 *   fetched -- the nature of publication, not a reason to forbid it. The
 *   consent warning and the shorter write TTL are what bound it;
 * - an RP-provisioned private collection -- the full vocabulary, subject to the
 *   consent screen and the shorter write TTL. It is provisioned encrypted,
 *   with the user as recipient zero and the grantee's identity key-agreement
 *   key (derived from its `did:key` controller) escrowed beside it, so a
 *   controller that derivation cannot handle makes the grant unsatisfiable.
 *
 * Only two request paths reach this module: App Connect and the
 * interaction-URL agent path. Each lists its grantees and can revoke them, so
 * either may provision. A plain CHAPI request carrying a capability query is
 * refused before consent (`precheckGetRequest`) and never resolves here.
 *
 * The class is resolved from the target itself, so it applies whether the
 * target arrives as a descriptor object or as a plain URL string under the
 * Space (the collection id is derived from the first path segment after the
 * Space URL either way) -- a string target cannot bypass it. No target reaches
 * the whole Space: the `https://w3id.org/byoe#space` descriptor type is
 * reserved and a string naming the Space itself is unsatisfiable, as the App
 * Connect spec requires. A string target never provisions, so it must name a
 * collection that stood before the request, not one an earlier
 * descriptor in the same request provisions. Resolution also
 * consults the existing collections' state (`collections`, a snapshot the
 * caller fetches from the user's Space), so a target naming a collection that
 * is ALREADY world-readable is classed public-collection whichever form it
 * arrives in (flagged for the consent warning, never re-provisioned). A
 * request whose
 * actions are all dropped or all above its class's ceiling renders the grant
 * unsatisfiable rather than empty: an empty `allowedAction` array means "every
 * action" in the zcap model.
 *
 * A `https://w3id.org/byoe#public-collection` grant provisions a plaintext collection with a
 * collection-level world-readable (PublicCanRead) policy, set by the wallet at
 * provisioning time. Public covers only unauthenticated reads; writes stay
 * capability-only, so the grant still delegates the usual collection-scoped
 * zcap (with the ordinary write TTL). A public grant on a protected wallet
 * collection is unsatisfiable, unconditionally. A public collection is only
 * ever CREATED public, never converted: a `https://w3id.org/byoe#public-collection` grant
 * naming an existing collection that is not already public is unsatisfiable
 * (otherwise one consent approval could flip another app's private -- possibly
 * encrypted -- collection world-readable), while the idempotent re-grant on an
 * already-public collection stays satisfiable and provisions nothing. The rule
 * holds within a single request too: resolution (`resolveGrants`, which the
 * consent preview and the approval share) records each collection the
 * request will provision, so a descriptor naming it later in the same
 * request resolves against it as an existing collection.
 *
 * A `https://w3id.org/byoe#shared-wallet-collection` grant is the share flow: it asks not just to
 * fetch one of the wallet's own encrypted collections but to DECRYPT it. It
 * leaves the ordinary delegation loop entirely. Its read-only pull zcap is
 * signed with the other grants (`StorageManager.delegateShareGrant`), and
 * once the grants are recorded `StorageManager.shareCollection` escrows the
 * key-epoch roster entry and records the share. The
 * recipient key is never carried in the request: it is derived from the
 * grantee's `did:key` controller (`x25519RecipientFromDidKey`), so a request
 * cannot pair one entity's DID with another's decryption key. Only the
 * encrypted standard collections can be shared (sharing is meaningless where
 * no epoch roster exists), and only read-only.
 *
 * Resolution (`resolveGrants`) is pure and drives the consent preview; the
 * delegation step (`processZcaps`) runs only on the consent-approved path.
 * Write grants (any action beyond GET/HEAD) are delegated for a shorter TTL
 * than read-only grants.
 */
import type { Session } from '@/types/auth'
import {
  APP_CONNECTIONS_COLLECTION,
  KEY_MAP_COLLECTION,
  UNLOCK_METHODS_COLLECTION
} from '@interop/wallet-core/space'
import {
  clampGrantExpires,
  GENERATION_DELEGATION_TTL_MS
} from '@interop/wallet-core/clientAnnex'
import { standingZcapStale } from '@interop/wallet-core/webvh'
import { renewTransientGenerationDelegation } from '@/session/annexReach'
import { peekVerifiedAccountLog } from '@/session/verifiedLog'
import { collectionCreatorLabel } from '@/lib/collectionAttribution'
import {
  RP_ZCAP_TTL_MS,
  RP_ZCAP_WRITE_TTL_MS,
  SHARE_ZCAP_TTL_MS,
  isProtectedCollection,
  WALLET_STANDARD_COLLECTIONS
} from '@/app.config'
import {
  isEd25519DidKey,
  x25519RecipientFromDidKey
} from '@interop/was-client/edv'
import {
  collectionPath,
  isReservedCollectionId,
  parseSpaceTarget,
  resourcePath,
  rootCapabilityId,
  toUrl
} from '@interop/was-client/paths'
import type { IDID } from '@interop/data-integrity-core'
import type { CollectionGenerator, IDelegatedZcap } from '@interop/was-client'
import type { ICapabilityQueryDetail, IZcap } from './types'

/**
 * Default actions for a grant whose `allowedAction` is absent: read-only.
 * Never inherit-all (an empty `allowedActions` array means "all actions").
 */
const DEFAULT_ACTIONS = ['GET', 'HEAD']

/**
 * The actions that count as reading. Which target classes are held to them is
 * the ceilings table's business (`ACTION_CEILINGS`); this constant only defines
 * where reading ends and writing begins, for `includesWrite` -- the flag that
 * drives the consent write warning and the shorter write-grant TTL.
 */
const READ_ONLY_ACTIONS = ['GET', 'HEAD']

/**
 * The closed WAS action vocabulary. The set is not the wallet's to invent: the
 * WAS spec fixes it to the uppercase HTTP method names, enumerating `GET`,
 * `POST`, `PUT`, and `DELETE`.
 *
 * `HEAD` is the one deliberate addition, as a tolerated read alias rather than
 * an action of its own: the spec authorizes a `HEAD` request as a `GET`, but
 * the wallet has always minted `HEAD` alongside `GET` in every read grant
 * (`READ_ONLY_ACTIONS`), and the server tolerates it. Keeping it is a superset
 * of what a reader needs and nothing more; dropping it would invalidate every
 * read grant the wallet has issued for no security gain. It is capped exactly
 * like `GET` -- it appears only in ceilings that already permit reads.
 *
 * Anything outside this set is dropped by `normalizeActions`.
 */
const WAS_ACTIONS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'] as const

type WasAction = (typeof WAS_ACTIONS)[number]

/**
 * The class of target a grant resolves onto. Every satisfiable target has
 * exactly one, and it is what `ACTION_CEILINGS` keys on.
 */
type TargetClass =
  'protected-collection' | 'share' | 'public-collection' | 'collection'

/**
 * The most any grant on a target of each class may be delegated. Requested
 * actions are intersected against the row; nothing else is ever granted, no
 * matter what the request asks for.
 */
const ACTION_CEILINGS: Record<TargetClass, readonly WasAction[]> = {
  // The user's own credentials, activity log, and published DID artifacts:
  // readable by an RP, not writable by one.
  'protected-collection': ['GET', 'HEAD'],
  // A share hands over decryption as well as fetch; it is never a write grant.
  share: ['GET', 'HEAD'],
  // The full vocabulary, the same as a private RP collection (per the App
  // Connect spec's descriptor registry): published content is still the RP's
  // own data, and un-publishing is as much data management as publishing.
  // Retraction removes the stored copy, not copies already fetched -- the
  // nature of publication, not a reason to forbid it.
  'public-collection': ['GET', 'HEAD', 'POST', 'PUT', 'DELETE'],
  // An RP-provisioned private collection is the RP's own data: the full
  // vocabulary, bounded by the consent screen and the shorter write TTL.
  collection: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE']
}

/**
 * Whether an action set includes anything beyond read-only (GET/HEAD): a
 * write-bearing grant, used to pick the shorter TTL and warn on consent.
 *
 * @param allowedActions {string[]}
 * @returns {boolean}
 */
function includesWrite(allowedActions: string[]): boolean {
  return allowedActions.some(
    action => !READ_ONLY_ACTIONS.includes(action.toUpperCase())
  )
}

/**
 * The collections no grant may ever name, whatever the descriptor form and
 * whatever actions it asks for. `app-connections` holds one app-key credential
 * per connected app, each carrying that app's private seed in
 * `credentialSubject.seed`. `resolveInvocationTarget` checks the resolved
 * collection id against this list once, after every descriptor form, so a
 * grant naming one of these collections is unsatisfiable rather than merely
 * read-only. That also keeps `app-connections` out of `provisionFor`'s
 * recipient roster, since an unsatisfiable grant never reaches provisioning.
 * Confidentiality of the seeds rests elsewhere, on the epoch roster: the rows
 * are EDV envelopes, and a grantee is not an epoch recipient, so it decrypts
 * nothing.
 *
 * `key-map` is plaintext on the server. Its user key roster
 * (`user-key.jsonl`) carries a passphrase credential's derived key-agreement
 * key beside a wrap of the user key, so a read of it is an offline
 * passphrase-guessing oracle. It also holds the KMS key map and the
 * user-typed client labels. `unlock-methods` is the account's credential
 * registry. Neither is any third party's business to read.
 *
 * Deliberately an explicit membership list rather than a roster-derived rule.
 * The roster's `shareable: false` cannot stand in for it -- `public-credentials`
 * is also `shareable: false` and is a perfectly ordinary grant target -- and
 * `encryption && !shareable` would be a coincidence of today's roster rather
 * than a statement about what the collection holds.
 */
const NEVER_GRANTABLE_COLLECTION_IDS: readonly string[] = [
  APP_CONNECTIONS_COLLECTION,
  KEY_MAP_COLLECTION.id,
  UNLOCK_METHODS_COLLECTION.id
]

/**
 * Whether a collection id names a collection no grant may target
 * ({@link NEVER_GRANTABLE_COLLECTION_IDS}).
 *
 * @param collectionId {string | undefined}
 * @returns {boolean}
 */
function isNeverGrantableCollection(collectionId: string | undefined): boolean {
  return !!collectionId && NEVER_GRANTABLE_COLLECTION_IDS.includes(collectionId)
}

/**
 * Collection id naming rule (D2): lowercase alphanumerics and hyphens, not
 * starting with a hyphen, up to 64 characters. This is the one part of
 * {@link isCollectionName} was-client does not decide. The reserved segments
 * are its registry's, and a plain-URL target's shape is its
 * `parseSpaceTarget` grammar's.
 */
const COLLECTION_NAME_RE = /^[a-z0-9][a-z0-9-]{0,63}$/

/**
 * The existing collections in the user's Space, keyed by collection id,
 * carrying the state grant resolution consults: whether each is already
 * world-readable. An absent key means the collection does not exist yet.
 * Resolution takes this as a required input rather than looking it up itself
 * (it stays pure and synchronous); callers build the snapshot with
 * {@link existingCollectionsFrom} over
 * `StorageManager.listCollectionPublicStates()`.
 */
export type ExistingCollections = ReadonlyMap<
  string,
  {
    isPublic: boolean
    // The collection's app attribution once it has been read off its own
    // metadata. Absent while unread, so resolution reports no
    // existing-collection reading for it yet.
    attribution?: CollectionAttribution
    // Whether the collection carries an `encryption` descriptor, read off the
    // same metadata as the attribution. Absent while unread.
    encrypted?: boolean
    // The key-agreement key ids in the collection's current key epoch, read
    // in for a string target naming an encrypted collection. Absent while
    // unread, so no grantee counts as a current recipient yet.
    recipientIds?: ReadonlySet<string>
  }
>

/**
 * The collections earlier descriptors in the same request provision, keyed
 * by collection id, with the public state each is provisioned in. It holds
 * only names absent from the pre-request snapshot. {@link resolveGrants}
 * builds it in request order, for the consent preview and the approval
 * alike, so both resolve every row against the same view.
 */
type ProvisionedByRequest = ReadonlyMap<string, { isPublic: boolean }>

/**
 * A collection's app attribution as grant resolution reads it: the
 * `generator` object App Connect provisioning stamps on the Collection
 * Metadata object at creation (`id`, the did:key of the application the
 * collection was provisioned for; `origin`, the Web origin that DID was bound
 * to; `url`, the app's canonical app URL; `name`, its display name), plus
 * the creating app as the wallet's own records know it, joined onto
 * `generator.id` by the caller (`lookupCollectionCreators` in
 * `lib/connectedApps.ts`). The join is the fallback for a collection stamped
 * without `generator.url` or `generator.name`: it supplies the creator's app
 * URL and display name there. An empty object is a collection read and found
 * unstamped.
 */
export interface CollectionAttribution {
  generator?: CollectionGenerator
  creatorApp?: { name: string; appUrl: string }
}

/**
 * Builds the {@link ExistingCollections} snapshot from a collection listing
 * (`StorageManager.listCollectionPublicStates()` or anything shaped like it).
 * The listing carries no attribution; a caller that has read it supplies it
 * per collection.
 *
 * @param collections {Array<{ id: string, isPublic?: boolean, attribution?:
 *   CollectionAttribution, encrypted?: boolean, recipientIds?:
 *   ReadonlySet<string> }>}
 * @returns {ExistingCollections}
 */
export function existingCollectionsFrom(
  collections: Array<{
    id: string
    isPublic?: boolean
    attribution?: CollectionAttribution
    encrypted?: boolean
    recipientIds?: ReadonlySet<string>
  }>
): ExistingCollections {
  return new Map(
    collections.map(
      ({ id, isPublic, attribution, encrypted, recipientIds }) => [
        id,
        { isPublic: !!isPublic, attribution, encrypted, recipientIds }
      ]
    )
  )
}

/**
 * Whether a grantee's key-agreement key sits in a collection's current key
 * epoch, per the recipient ids read in for it. A controller the recipient
 * derivation cannot handle was never escrowed, so it is no recipient.
 *
 * @param options {object}
 * @param [options.controller] {string}   the grantee did:key
 * @param [options.recipientIds] {ReadonlySet<string>}
 * @returns {boolean}
 */
function isCurrentRecipient({
  controller,
  recipientIds
}: {
  controller?: string
  recipientIds?: ReadonlySet<string>
}): boolean {
  if (!controller || !recipientIds) {
    return false
  }
  try {
    return recipientIds.has(x25519RecipientFromDidKey({ did: controller }).id!)
  } catch {
    return false
  }
}

/**
 * How an existing private collection stands in relation to the requester,
 * reported on a satisfiable target naming one so the consent row can say the
 * collection already exists and who created it. The signal is the attribution
 * App Connect provisioning stamps on the Collection Metadata object at
 * creation (`generator`), read against the requester's did:key and its
 * canonical `appUrl`. A collection that
 * already stands admits the requester into every key epoch it has, so the
 * row states it before approval.
 */
export interface ExistingCollectionReading {
  // Who provisioned the collection: `this-app` (the requester's own did:key),
  // `this-application` (a key the same application held earlier -- the site
  // reconnecting after a disconnect minted a new one), `other` (a different
  // application), or `unattributed` (nothing stamped: a collection an
  // interaction-URL grant provisioned, which records no origin).
  creator: 'this-app' | 'this-application' | 'other' | 'unattributed'
  generator?: CollectionGenerator
  // The creating app's display name: the collection's own `generator.name`,
  // else the name the wallet's own records hold for the creator.
  creatorName?: string
}

/**
 * The {@link ExistingCollectionReading} for a collection target, or undefined
 * when the target names nothing that already stands as a private
 * app-provisioned collection: a new name, a public collection (which carries
 * no key epochs to admit anyone into), a protected wallet collection, or a
 * collection whose attribution has not been read yet.
 *
 * The same-application test compares canonical app URLs, since the wallet
 * tells apps apart by `appUrl` and several may share one origin. The
 * creator's app URL is the collection's own `generator.url` when it carries
 * one. Only a collection stamped without it falls back to the app URL the
 * wallet's records join onto `generator.id`. A requester that carries an
 * `appUrl` (an App Connect request) reads `this-application` only when the
 * creator's app URL is known and equal; a creator whose app URL is not known
 * reads `other`, the cautious side. A requester
 * with no `appUrl` (an interaction-URL agent) is never the same application
 * as a collection's creator, so it reads `other` unless it is `this-app`.
 *
 * @param options {object}
 * @param options.collectionId {string}
 * @param options.collections {ExistingCollections}
 * @param options.requester {{ controller?: string; appUrl?: string }}
 * @returns {ExistingCollectionReading | undefined}
 */
function existingCollectionReading({
  collectionId,
  collections,
  requester
}: {
  collectionId: string
  collections: ExistingCollections
  requester: { controller?: string; appUrl?: string }
}): ExistingCollectionReading | undefined {
  const existing = collections.get(collectionId)
  if (!existing?.attribution || existing.isPublic) {
    return undefined
  }
  if (isProtectedCollection(collectionId)) {
    return undefined
  }
  const { generator, creatorApp } = existing.attribution
  if (!generator) {
    return { creator: 'unattributed' }
  }
  if (requester.controller && generator.id === requester.controller) {
    return { creator: 'this-app', generator }
  }
  const creatorAppUrl = generator.url ?? creatorApp?.appUrl
  const sameApplication =
    !!requester.appUrl && creatorAppUrl === requester.appUrl
  return {
    creator: sameApplication ? 'this-application' : 'other',
    generator,
    creatorName: collectionCreatorLabel({
      generator,
      recordName: creatorApp?.name
    })
  }
}

/**
 * The target class and public flag for a target resolving onto a named
 * collection -- shared by the string-URL and `https://w3id.org/byoe#private-collection` forms so the
 * ceiling parity holds whichever way the target arrives: protected wallet
 * collections first (their read-only ceiling is the strictest), then a
 * collection the Space already serves world-readable (the public-collection
 * class -- the same full-vocabulary ceiling, but named so the consent warning
 * fires and the collection is never re-provisioned, however the request
 * spelled the target), and only then the full RP-collection class.
 *
 * @param options {object}
 * @param options.collectionId {string}
 * @param options.collections {ExistingCollections}
 * @returns {TargetClass}
 */
function collectionClassFor({
  collectionId,
  collections
}: {
  collectionId: string
  collections: ExistingCollections
}): TargetClass {
  if (isProtectedCollection(collectionId)) {
    return 'protected-collection'
  }
  if (collections.get(collectionId)?.isPublic) {
    return 'public-collection'
  }
  return 'collection'
}

/**
 * A requested capability's `invocationTarget` resolved against the user's own
 * Space. An absent `targetClass` means the descriptor cannot be fulfilled (a
 * foreign URL, an invalid collection name, or an unknown descriptor type); it
 * is skipped at delegation time and shown as "cannot fulfill" on consent.
 *
 * The class is the one discriminator: a share is `'share'`, a world-readable
 * collection `'public-collection'`. Only
 * `encrypted` and `needsProvisioning` vary independently of it.
 */
interface ResolvedTarget {
  // Which action ceiling applies (`ACTION_CEILINGS`), and which kind of target
  // this is. Absent only when the target is unsatisfiable, i.e. when no grant
  // will be made at all.
  targetClass?: TargetClass
  // The concrete WAS URL to delegate against (absent when unsatisfiable).
  invocationTarget?: string
  // A named RP collection that does not exist yet and must be provisioned.
  needsProvisioning: boolean
  // The WAS collection id, when the target is a (standard or RP) collection.
  collectionId?: string
  // An encrypted collection the grantee does not join the key roster of, so
  // the RP will only see ciphertext: a standard EDV collection, or an
  // existing encrypted collection a string target names, whose current key
  // epoch does not already list the grantee.
  encrypted: boolean
  // Present when the target names a private collection that already stands
  // (see {@link ExistingCollectionReading}); absent on a new name, a public
  // or protected collection, or an unsatisfiable target.
  existing?: ExistingCollectionReading
}

/**
 * Whether a resolved target can be delegated at all -- it resolved onto a
 * class, so it has a ceiling and a URL.
 *
 * @param target {ResolvedTarget}
 * @returns {boolean}
 */
export function isSatisfiable(target: ResolvedTarget): boolean {
  return target.targetClass !== undefined
}

/**
 * A requested capability paired with its resolved target and the normalized,
 * security-capped actions it would be granted. Drives both the consent preview
 * and the delegation step.
 */
export interface ResolvedGrant {
  descriptor: ICapabilityQueryDetail
  target: ResolvedTarget
  allowedActions: string[]
  // The capped actions include a write (anything beyond GET/HEAD): drives the
  // consent write warning and the shorter write-grant TTL.
  write: boolean
}

/**
 * Raised when a zcap request arrives but the session has no remote WAS Space to
 * delegate against (a guest, or a no-WAS build). The page maps this to the
 * `zcapUnavailable` block reason.
 */
export class ZcapUnavailableError extends Error {
  constructor(message = 'This wallet has no remote storage to delegate.') {
    super(message)
    this.name = 'ZcapUnavailableError'
  }
}

/**
 * Thrown when a transient session's generation delegation -- the parent every
 * grant it mints chains under -- is expired, inside its renewal window, or
 * carries no parseable expiry. A grant clamped under such a parent would
 * either verify nowhere or lapse within days, so the mint refuses outright.
 * The renew-precedes-mint stage runs first (the ladder-signed renewal over
 * the standing members the transient login stamps), so this refusal is
 * reached only when the session holds nothing to renew with, or the renewal
 * itself failed. `composeAndDeliverResponse` maps it, like any unmapped
 * error, onto the generic `processFailed` reason -- acceptable for now.
 */
export class GenerationDelegationStaleError extends Error {
  constructor() {
    super(
      'The generation delegation this session holds is expired or inside its ' +
        'renewal window; refusing to mint a grant under it.'
    )
    this.name = 'GenerationDelegationStaleError'
  }
}

/**
 * Whether a session can back a zcap request at all: it must have a remote WAS
 * Space (both a remote store and a resolved `spaceUrl`) to delegate against.
 * This is the exact condition `processZcaps` enforces before delegating (it
 * throws `ZcapUnavailableError` otherwise), exposed so a caller can surface the
 * same block earlier -- before showing consent -- without re-deriving (and
 * under-specifying) the guard.
 *
 * @param session {Session}
 * @returns {boolean}
 */
export function hasZcapStorage(session: Session): boolean {
  return !!session.storage.hasRemoteStorage && !!session.storage.spaceUrl
}

/**
 * Whether a generation delegation can no longer parent a grant: past its
 * expiry, inside its renewal window, or signed by a key the account document
 * no longer lists under `capabilityDelegation` (signer rot). The rule is
 * wallet-core's composed `standingZcapStale`, the same axes the readiness
 * stage and the annex's own renewal test, so this caller cannot drift onto a
 * staleness rule of its own.
 *
 * The signer axis reads the document this session has ALREADY verified
 * (the verified-log memo, peeked rather than fetched). A cold memo skips
 * that axis, matching the annex's own opt-out when no document is in hand;
 * the renewal stage then verifies the log for itself. Mid-visit rot has one
 * source: a credential retirement landing elsewhere while this visit stands
 * on a delegation that credential's ladder VM signed. Without this axis the
 * grant would mint under a parent whose delegation link no longer verifies,
 * behind a consent screen that read correct.
 *
 * A delegated zcap always carries `expires`; the union type's root half does
 * not, and a root could never sit here.
 *
 * @param options {object}
 * @param options.delegation {IZcap}
 * @param options.session {Session}
 * @param options.now {number}   epoch milliseconds
 * @returns {boolean}
 */
function delegationStale({
  delegation,
  session,
  now
}: {
  delegation: IZcap
  session: Session
  now: number
}): boolean {
  const doc = peekVerifiedAccountLog({ profile: session.profile })?.doc
  return standingZcapStale({
    zcap: delegation,
    ...(doc !== undefined ? { doc } : {}),
    now
  })
}

const DAY_MS = 24 * 60 * 60 * 1000

/**
 * The lifetimes the consent screen should show, in days: what the mint will
 * actually produce rather than the configured TTL constants. Under the Space
 * root the two are the same. Under a generation delegation each grant is
 * clamped to the parent's own `expires`, which for a 365-day share grant bites
 * essentially always -- the parent's TTL is a year too, and part of it has
 * already elapsed -- so a static number would overstate the share row by
 * however much of that year is gone.
 *
 * A parent inside its renewal window is derived against a FRESH generation
 * delegation, because that is what the mint will hold: `processZcaps` renews
 * before it delegates, and the renewed parent's own TTL is the bound that
 * survives.
 *
 * The three configured TTLs are read from the app config, which is what every
 * caller mints with; `processZcaps`'s per-call TTL overrides exist for tests
 * and are not reflected here.
 *
 * @param options {object}
 * @param [options.session] {Session}   absent before the consent screen has a
 *   session, where the configured TTLs are all there is to state
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {{ ttlDays: number, writeTtlDays: number, shareTtlDays: number }}
 */
export function grantTtlDays({
  session,
  now = Date.now()
}: {
  session?: Session
  now?: number
}): { ttlDays: number; writeTtlDays: number; shareTtlDays: number } {
  const delegation = session?.profile.invocationCapability

  /**
   * One grant class's shown lifetime.
   *
   * @param ttlMs {number}
   * @returns {number}
   */
  function daysFor(ttlMs: number): number {
    if (!delegation || !session) {
      return Math.max(1, Math.round(ttlMs / DAY_MS))
    }
    const expires = delegationStale({ delegation, session, now })
      ? now + Math.min(ttlMs, GENERATION_DELEGATION_TTL_MS)
      : clampGrantExpires({ ttlMs, delegation, now }).getTime()
    // A grant is only ever minted under a parent outside its renewal window,
    // so the clamped remainder is a month or more; the floor guards the
    // display (and a sub-day TTL configured through the environment) rather
    // than a state the mint can reach.
    return Math.max(1, Math.round((expires - now) / DAY_MS))
  }

  return {
    ttlDays: daysFor(RP_ZCAP_TTL_MS),
    writeTtlDays: daysFor(RP_ZCAP_WRITE_TTL_MS),
    shareTtlDays: daysFor(SHARE_ZCAP_TTL_MS)
  }
}

const UNSATISFIABLE: ResolvedTarget = Object.freeze({
  needsProvisioning: false,
  encrypted: false
})

// The satisfiable counterpart: the flags every resolved target states, spread
// into each literal below so only the members that differ are written out.
// Each literal supplies its own `targetClass`, which is what makes it
// satisfiable.
const SATISFIABLE_DEFAULTS: Omit<ResolvedTarget, 'targetClass'> = Object.freeze(
  {
    needsProvisioning: false,
    encrypted: false
  }
)

/**
 * The standard-collection entry a name refers to, when it is one.
 *
 * @param [name] {string}
 * @returns {(typeof WALLET_STANDARD_COLLECTIONS)[number] | undefined}
 */
function standardCollection(
  name: string | undefined
): (typeof WALLET_STANDARD_COLLECTIONS)[number] | undefined {
  return WALLET_STANDARD_COLLECTIONS.find(entry => entry.id === name)
}

/**
 * Whether a descriptor's `name` can be a collection id at all: the naming rule
 * plus the spec's Reserved Path Segment Registry, asked of was-client's own
 * predicate so this module and the path builders agree by construction.
 *
 * A reserved segment (`meta`, `policy`, `query`, `export`, `import`,
 * `backends`, `collections`, `linkset`, `quotas`) satisfies the naming rule
 * while addressing a server facet rather than a Collection. Two things ride on
 * refusing it here. was-client's `collectionPath` throws a `ValidationError`
 * on one, so admitting it would throw out of resolution instead of refusing
 * the grant, and `${spaceUrl}/meta` is the Space Metadata object, which a
 * full-vocabulary collection grant would hand an RP write access to -- the
 * Space's `controller` included.
 *
 * @param [name] {string}
 * @returns {boolean}
 */
function isCollectionName(name: string | undefined): name is string {
  return (
    !!name && COLLECTION_NAME_RE.test(name) && !isReservedCollectionId(name)
  )
}

/**
 * Where the user's Space lives, structurally: the storage server's base URL
 * and the Space id. Every target this module builds is formed from the pair
 * through was-client's path builders, since a target must match the server's
 * `allowedTarget` byte for byte and the trailing-slash and percent-encoding
 * rules are the builders' to own. `StorageManager.spaceLocation` hands a
 * session's pair to the callers.
 */
export interface SpaceLocation {
  serverUrl: string
  spaceId: string
}

/**
 * The canonical URL of one Collection in the user's Space. `collectionId` has
 * already passed {@link isCollectionName}, so the reserved segments the path
 * builder refuses never reach it.
 *
 * @param options {object}
 * @param options.space {SpaceLocation}
 * @param options.collectionId {string}
 * @returns {string}
 */
function collectionTargetIn({
  space,
  collectionId
}: {
  space: SpaceLocation
  collectionId: string
}): string {
  return toUrl({
    serverUrl: space.serverUrl,
    path: collectionPath(space.spaceId, collectionId)
  })
}

/**
 * Classifies a plain-URL invocation target against the user's Space with
 * was-client's own grammar (`parseSpaceTarget`): a Collection in the Space,
 * or a Resource in one, with the ids the builders re-emit from. `undefined` is
 * anything else -- the Space itself (no grant reaches the whole Space), a
 * foreign origin or another Space, a reserved sub-endpoint such as `meta` or `policy` at any depth, a path
 * deeper than a Resource -- so a string target can name nothing the typed
 * descriptors cannot. A container classifies the same whichever way it
 * arrived, with or without the trailing slash.
 *
 * Two refusals stay here, ahead of the grammar. `new URL` resolves dot
 * segments, so `${spaceUrl}../other-space/x` lands outside this Space and the
 * Space-id check refuses it. A query or a fragment is refused outright rather
 * than silently dropped: a WAS URL has neither, and showing the user one
 * target while delegating another is not consent.
 *
 * @param options {object}
 * @param options.target {string}
 * @param options.space {SpaceLocation}
 * @returns {{ collectionId: string, resourceId?: string } | undefined}
 */
function classifySpaceTarget({
  target,
  space
}: {
  target: string
  space: SpaceLocation
}): { collectionId: string; resourceId?: string } | undefined {
  let url: URL
  try {
    url = new URL(target)
  } catch {
    return undefined
  }
  if (url.search || url.hash) {
    return undefined
  }
  const parsed = parseSpaceTarget({
    serverUrl: space.serverUrl,
    target: url.href
  })
  if (!parsed || parsed.spaceId !== space.spaceId) {
    return undefined
  }
  if (parsed.kind === 'collection') {
    return { collectionId: parsed.collectionId }
  }
  if (parsed.kind === 'resource') {
    return { collectionId: parsed.collectionId, resourceId: parsed.resourceId }
  }
  return undefined
}

/**
 * Resolves an abstract `invocationTarget` descriptor against the user's Space:
 *
 * - a plain URL string inside the Space -- classified with was-client's
 *   grammar (`classifySpaceTarget`) and re-emitted through its path builders,
 *   so a URL under a standard collection (or at a Resource inside one) is
 *   flagged `collectionId` / `encrypted` and gets the same cap as its
 *   descriptor form -- including the public-collection class when the named
 *   collection is already world-readable. A string target never provisions,
 *   per the App Connect spec, so one naming a collection absent from
 *   `collections` (or a Resource inside one) is unsatisfiable: a grantee
 *   cannot create a collection through its first write. A collection an
 *   earlier descriptor in the same request provisions (`provisioned`) does
 *   not count. An existing encrypted collection is flagged `encrypted` unless
 *   its current key epoch already lists the grantee. A container target is
 *   normalized to its canonical trailing-slash form whichever way it
 *   arrived. Any other string -- the Space URL itself, a foreign origin, a
 *   path that escapes the Space, a target carrying a query or fragment, a
 *   reserved sub-endpoint, a path deeper than a Resource, a collection
 *   segment that is not a valid collection id, a never-grantable
 *   collection -- is unsatisfiable;
 * - `{ type: 'https://w3id.org/byoe#private-collection', name }` -- the
 *   Collection's canonical URL in the Space (`collectionPath`) after
 *   validating `name`, flagged `needsProvisioning` unless it is a standard
 *   collection (and `encrypted` for the two EDV collections). Like the string
 *   form, classed public-collection when the collection already is -- with
 *   nothing to provision, exactly as if it had been asked for as a
 *   `https://w3id.org/byoe#public-collection` re-grant;
 * - `{ type: 'https://w3id.org/byoe#public-collection', name }` -- like `https://w3id.org/byoe#private-collection`
 *   but classed public-collection: provisioned plaintext with a world-readable
 *   (PublicCanRead) policy. Unsatisfiable on a protected wallet collection --
 *   an RP must never be able to flip the user's own collections public -- and
 *   unsatisfiable on any existing collection that is not already public: a
 *   public collection is only ever created public, never converted. The
 *   idempotent re-grant on an already-public collection stays satisfiable,
 *   with nothing to provision;
 * - `{ type: 'https://w3id.org/byoe#shared-wallet-collection', name }` -- like `https://w3id.org/byoe#private-collection`
 *   but classed share: the grantee also joins the collection's key-epoch
 *   roster, so it can decrypt what it fetches. `name` must be one of the
 *   SHAREABLE standard collections; anything else (a plaintext collection, an
 *   RP collection, a never-grantable collection) is unsatisfiable -- a share
 *   is only meaningful where an epoch roster exists;
 * - anything else -- unsatisfiable, including the reserved
 *   `https://w3id.org/byoe#space` type: no grant reaches the whole Space.
 *
 * Whatever the form, a target resolving onto a never-grantable collection
 * ({@link NEVER_GRANTABLE_COLLECTION_IDS}) is unsatisfiable.
 *
 * @param options {object}
 * @param options.descriptor {string | { type: string; name?: string }}
 * @param options.space {SpaceLocation}   the user's Space, structurally
 * @param options.collections {ExistingCollections}   the Space's existing
 *   collections as they stood before the request, their public state, and
 *   their attribution
 * @param [options.provisioned] {ProvisionedByRequest}   the collections
 *   earlier descriptors in the same request provision. A descriptor form
 *   resolves against them as existing collections; a string target ignores
 *   them.
 * @param options.requester {{ controller?: string; appUrl?: string }}   the
 *   grantee did:key and the app's canonical URL, read to class an existing
 *   collection's creator (`existing` on the result) and to check the
 *   grantee against a current key epoch
 * @returns {ResolvedTarget}
 */
export function resolveInvocationTarget(options: {
  descriptor: string | { type?: string; name?: string }
  space: SpaceLocation
  collections: ExistingCollections
  provisioned?: ProvisionedByRequest
  requester: { controller?: string; appUrl?: string }
}): ResolvedTarget {
  const target = resolveTargetForm(options)
  // One check covers every form: a target that resolves onto a
  // never-grantable collection (or a Resource inside one) is refused, however
  // the request named it.
  if (isNeverGrantableCollection(target.collectionId)) {
    return UNSATISFIABLE
  }
  return target
}

/**
 * The collections a descriptor form resolves against: the pre-request
 * snapshot, plus each collection an earlier descriptor in the same request
 * provisions, with the public state it is provisioned in.
 *
 * @param options {object}
 * @param options.snapshot {ExistingCollections}
 * @param [options.provisioned] {ProvisionedByRequest}
 * @returns {ExistingCollections}
 */
function withProvisioned({
  snapshot,
  provisioned
}: {
  snapshot: ExistingCollections
  provisioned?: ProvisionedByRequest
}): ExistingCollections {
  if (!provisioned || provisioned.size === 0) {
    return snapshot
  }
  const view = new Map(snapshot)
  for (const [collectionId, { isPublic }] of provisioned) {
    if (!view.has(collectionId)) {
      view.set(collectionId, { isPublic })
    }
  }
  return view
}

/**
 * Resolves one descriptor form for {@link resolveInvocationTarget}, before the
 * never-grantable check that applies to every form.
 *
 * @param options {object}
 * @param options.descriptor {string | { type: string; name?: string }}
 * @param options.space {SpaceLocation}
 * @param options.collections {ExistingCollections}
 * @param [options.provisioned] {ProvisionedByRequest}
 * @param options.requester {{ controller?: string; appUrl?: string }}
 * @returns {ResolvedTarget}
 */
function resolveTargetForm({
  descriptor,
  space,
  collections: snapshot,
  provisioned,
  requester
}: {
  descriptor: string | { type?: string; name?: string }
  space: SpaceLocation
  collections: ExistingCollections
  provisioned?: ProvisionedByRequest
  requester: { controller?: string; appUrl?: string }
}): ResolvedTarget {
  if (typeof descriptor === 'string') {
    const collections = snapshot
    const parsed = classifySpaceTarget({ target: descriptor, space })
    if (!parsed) {
      return UNSATISFIABLE
    }
    const { collectionId, resourceId } = parsed
    // A segment that cannot be a collection id names nothing the Space can
    // hold, so there is nothing to delegate against.
    if (!isCollectionName(collectionId)) {
      return UNSATISFIABLE
    }
    // A string target never provisions, per the App Connect spec. One
    // naming a collection that does not exist yet is refused, so the
    // grantee's first write cannot create it. It resolves against the
    // pre-request snapshot alone, so a collection an earlier descriptor in
    // the same request provisions does not count.
    const existingEntry = collections.get(collectionId)
    if (!existingEntry) {
      return UNSATISFIABLE
    }
    // A URL naming an existing collection (or a Resource inside one) is
    // capped like its `https://w3id.org/byoe#private-collection` descriptor
    // form. The target is re-emitted through the builders, so the grant names
    // the canonical form whatever bytes the RP sent. It admits the grantee to
    // no key roster. An encrypted collection therefore reads as ciphertext to
    // it, unless its current key epoch already lists the grantee. A standard
    // collection is known encrypted by its roster entry, any other by its own
    // metadata once the attribution pass has read it. The same pass reads the
    // current epoch's recipients.
    const encryptedCollection =
      !!standardCollection(collectionId)?.encryption ||
      !!existingEntry.encrypted
    return {
      ...SATISFIABLE_DEFAULTS,
      invocationTarget:
        resourceId === undefined
          ? collectionTargetIn({ space, collectionId })
          : toUrl({
              serverUrl: space.serverUrl,
              path: resourcePath(space.spaceId, collectionId, resourceId)
            }),
      collectionId,
      encrypted:
        encryptedCollection &&
        !isCurrentRecipient({
          controller: requester.controller,
          recipientIds: existingEntry.recipientIds
        }),
      targetClass: collectionClassFor({ collectionId, collections }),
      existing: existingCollectionReading({
        collectionId,
        collections,
        requester
      })
    }
  }

  // A descriptor form counts a collection an earlier descriptor in the same
  // request provisions as existing, so the create-only rule and the
  // public-collection class see it.
  const collections = withProvisioned({ snapshot, provisioned })

  if (descriptor?.type === 'https://w3id.org/byoe#private-collection') {
    const { name } = descriptor
    if (!isCollectionName(name)) {
      return UNSATISFIABLE
    }
    const standard = standardCollection(name)
    const collectionClass = collectionClassFor({
      collectionId: name,
      collections
    })
    return {
      ...SATISFIABLE_DEFAULTS,
      invocationTarget: collectionTargetIn({ space, collectionId: name }),
      // A protected collection -- a standard one or the `id` system
      // collection -- is provisioned and maintained by the
      // wallet itself, never here. An existing private RP collection still
      // flags provisioning: the provisioning step is idempotent and is what
      // re-admits a reconnecting grantee to an existing collection's
      // recipient roster. The same step admits a DIFFERENT grantee naming the
      // collection, into every key epoch it has; that is the decided policy,
      // and `existing` below is what lets the consent row say so before
      // approval. An existing PUBLIC collection never flags provisioning: it
      // is classed public-collection whichever form the target arrives in,
      // and re-provisioning it here would re-run the public-policy setup on a
      // live collection, or set up a recipient roster on a world-readable
      // plaintext collection.
      needsProvisioning:
        !isProtectedCollection(name) && collectionClass !== 'public-collection',
      collectionId: name,
      encrypted: !!standard?.encryption,
      targetClass: collectionClass,
      existing: existingCollectionReading({
        collectionId: name,
        collections,
        requester
      })
    }
  }

  if (descriptor?.type === 'https://w3id.org/byoe#public-collection') {
    const { name } = descriptor
    if (!isCollectionName(name)) {
      return UNSATISFIABLE
    }
    // A public grant on a protected wallet collection is refused
    // unconditionally: an RP must never be able to make the user's own
    // credentials, activity log, or published identity world-readable.
    if (isProtectedCollection(name)) {
      return UNSATISFIABLE
    }
    // A public collection is only ever created public, never converted: a
    // grant naming an existing collection that is not already world-readable
    // is refused, or one consent approval could flip another app's private
    // (possibly encrypted) collection public.
    const existing = collections.get(name)
    if (existing && !existing.isPublic) {
      return UNSATISFIABLE
    }
    // Public implies plaintext: the collection is provisioned without an
    // encryption descriptor, so a ciphertext note never applies. An
    // already-public collection has nothing to provision -- the idempotent
    // re-grant only delegates.
    return {
      ...SATISFIABLE_DEFAULTS,
      invocationTarget: collectionTargetIn({ space, collectionId: name }),
      needsProvisioning: !existing,
      collectionId: name,
      targetClass: 'public-collection'
    }
  }

  if (descriptor?.type === 'https://w3id.org/byoe#shared-wallet-collection') {
    const { name } = descriptor
    // Both conditions, deliberately. Encryption is necessary -- a share
    // escrows the reader into a key-epoch roster, and there is no roster
    // where nothing is encrypted -- but not sufficient: `app-connections`
    // carries epochs and is never shareable, since its rows are the connected
    // apps' private seeds, and so does `wallet-activity`, whose rows carry the
    // account's delegated capabilities verbatim. Everything else -- a plaintext collection, an RP
    // collection, a made-up name -- has no roster to escrow a reader into.
    const shared = standardCollection(name)
    if (!shared?.encryption || !shared.shareable) {
      return UNSATISFIABLE
    }
    return {
      ...SATISFIABLE_DEFAULTS,
      invocationTarget: collectionTargetIn({ space, collectionId: shared.id }),
      collectionId: shared.id,
      encrypted: true,
      targetClass: 'share'
    }
  }

  return UNSATISFIABLE
}

/**
 * Normalizes a query's `allowedAction` into a deduplicated set of WAS actions:
 * an absent value defaults to read-only (`['GET', 'HEAD']`), never inherit-all,
 * and every requested token is uppercased and intersected against the closed
 * WAS vocabulary. A token the vocabulary does not define -- an unknown verb, a
 * non-string, an action the server may grow support for later -- is dropped
 * here rather than passed through into an `allowedAction` the user's root key
 * signs, which is the same fail-closed treatment an unknown `descriptor.type`
 * gets.
 *
 * @param allowedAction {string | object | Array<string | object> | undefined}
 * @returns {string[]}
 */
function normalizeActions(
  allowedAction: string | object | Array<string | object> | undefined
): string[] {
  if (allowedAction === undefined) {
    return [...DEFAULT_ACTIONS]
  }
  const actions = Array.isArray(allowedAction) ? allowedAction : [allowedAction]
  const normalized: string[] = []
  for (const action of actions) {
    if (typeof action !== 'string') {
      continue
    }
    const token = action.trim().toUpperCase()
    if (
      (WAS_ACTIONS as readonly string[]).includes(token) &&
      !normalized.includes(token)
    ) {
      normalized.push(token)
    }
  }
  return normalized
}

/**
 * Intersects requested actions with the ceiling for the target's class. The
 * result is ordered by the ceiling, so an equivalent request always yields the
 * same `allowedAction` array regardless of the order it asked in.
 *
 * @param options {object}
 * @param [options.targetClass] {TargetClass}   absent for an unsatisfiable
 *   target, which is granted nothing
 * @param options.requested {string[]}   already normalized by `normalizeActions`
 * @returns {string[]}
 */
function capActions({
  targetClass,
  requested
}: {
  targetClass?: TargetClass
  requested: string[]
}): string[] {
  if (!targetClass) {
    return []
  }
  return ACTION_CEILINGS[targetClass].filter(action =>
    requested.includes(action)
  )
}

/**
 * Resolves a single requested capability into a `ResolvedGrant`: its target
 * plus the normalized, security-capped actions. The requested actions are
 * intersected against the ceiling for the target's class (`ACTION_CEILINGS`),
 * so a grant never carries more than its class permits and a request that asks
 * for nothing the class permits is unsatisfiable. The resulting `write` flag
 * records whether the capped actions still include a write.
 *
 * @param options {object}
 * @param options.descriptor {ICapabilityQueryDetail}
 * @param options.space {SpaceLocation}
 * @param options.collections {ExistingCollections}
 * @param [options.provisioned] {ProvisionedByRequest}   the collections
 *   earlier descriptors in the same request provision (see
 *   {@link resolveGrants})
 * @param [options.allowMissingController] {boolean}   App Connect
 *   consent-preview only: the app-key DID may not exist yet, so an absent
 *   controller is not yet a failure there
 * @param [options.appUrl] {string}   the requesting app's canonical URL, on
 *   the App Connect path; read only to class an existing collection's creator
 * @returns {ResolvedGrant}
 */
export function resolveGrant({
  descriptor,
  space,
  collections,
  provisioned,
  allowMissingController = false,
  appUrl
}: {
  descriptor: ICapabilityQueryDetail
  space: SpaceLocation
  collections: ExistingCollections
  provisioned?: ProvisionedByRequest
  allowMissingController?: boolean
  appUrl?: string
}): ResolvedGrant {
  let target = resolveInvocationTarget({
    descriptor: descriptor.invocationTarget,
    space,
    collections,
    provisioned,
    requester: { controller: descriptor.controller, appUrl }
  })
  // A grant with no recipient cannot be delegated: the wire type requires a
  // `controller` but an actual request body can omit it, which would render a
  // consent row with no recipient and delegate to nobody. Refuse it visibly
  // (unsatisfiable) instead. The App Connect consent preview resolves with an
  // empty controller on first run (the app-key DID does not exist yet) and
  // opts out; the approved path fills the real subject DID before resolving
  // again, without the opt-out.
  if (!descriptor.controller && !allowMissingController) {
    target = UNSATISFIABLE
  }
  // A share's recipient key is DERIVED from the grantee's controller DID, and
  // so is the escrowed key of a private collection this grant provisions.
  // Only a descriptor provisions; a string target never does. Every such
  // collection is provisioned encrypted, so a controller the derivation
  // cannot handle cannot be granted either. Run the real derivation rather
  // than a shape check. A well-formed-looking but malformed did:key (a
  // truncated identifier, a non-curve point) would otherwise preview as
  // satisfiable and then throw mid-response, after earlier grants in the same
  // request had already been delegated. An absent controller was already
  // handled above (unsatisfiable, or the App Connect preview's opt-out).
  const derivesRecipient =
    target.targetClass === 'share' ||
    (target.targetClass === 'collection' && target.needsProvisioning)
  if (derivesRecipient && descriptor.controller) {
    try {
      x25519RecipientFromDidKey({ did: descriptor.controller })
    } catch {
      target = UNSATISFIABLE
    }
  }
  const allowedActions = capActions({
    targetClass: target.targetClass,
    requested: normalizeActions(descriptor.allowedAction)
  })
  // Nothing survived the ceiling: the request asked only for actions its target
  // class forbids (or only for tokens outside the WAS vocabulary). Refuse the
  // grant visibly instead of delegating an empty `allowedAction` array, which
  // means "every action" in the zcap model.
  if (isSatisfiable(target) && allowedActions.length === 0) {
    target = UNSATISFIABLE
  }
  return {
    descriptor,
    target,
    allowedActions,
    write: includesWrite(allowedActions)
  }
}

/**
 * Resolves every requested capability against the user's Space, in request
 * order. The consent preview and the approval (`processZcaps`) both resolve
 * through here, so a row cannot preview one way and delegate another. Pure
 * -- no provisioning or delegation; the caller supplies the pre-request
 * existing-collections snapshot ({@link existingCollectionsFrom}), which
 * stays unchanged.
 *
 * Each row that provisions a new collection is recorded, with the public
 * state it provisions, and later descriptor forms resolve against it as an
 * existing collection. So `#public-collection 'x'` then
 * `#private-collection 'x'` resolves the second row public-collection (the
 * world-readable collection the first creates, with the consent warning),
 * and the reverse order refuses the `#public-collection` row under the
 * create-only rule. A string target sees only the snapshot, so it never
 * names a collection the request itself creates.
 *
 * @param options {object}
 * @param options.zcapRequests {ICapabilityQueryDetail[]}
 * @param options.space {SpaceLocation}
 * @param options.collections {ExistingCollections}
 * @param [options.allowMissingController] {boolean}   App Connect
 *   consent-preview only (see {@link resolveGrant})
 * @param [options.appUrl] {string}   the app's canonical URL (see
 *   {@link resolveGrant})
 * @returns {ResolvedGrant[]}
 */
export function resolveGrants({
  zcapRequests,
  space,
  collections,
  allowMissingController,
  appUrl
}: {
  zcapRequests: ICapabilityQueryDetail[]
  space: SpaceLocation
  collections: ExistingCollections
  allowMissingController?: boolean
  appUrl?: string
}): ResolvedGrant[] {
  const provisioned = new Map<string, { isPublic: boolean }>()
  return zcapRequests.map(descriptor => {
    const grant = resolveGrant({
      descriptor,
      space,
      collections,
      provisioned,
      allowMissingController,
      appUrl
    })
    const { target } = grant
    if (
      target.needsProvisioning &&
      target.collectionId &&
      !collections.has(target.collectionId) &&
      !provisioned.has(target.collectionId)
    ) {
      provisioned.set(target.collectionId, {
        isPublic: target.targetClass === 'public-collection'
      })
    }
    return grant
  })
}

/**
 * Delegates capabilities to the relying parties named in the requests, on the
 * consent-approved path. Signs each satisfiable grant rooted at the user's
 * Space root capability first, then awaits `beforeProvision` with the signed
 * grants, then escrows the shares and provisions the RP collections the
 * grants need. Both escrow the grantee into key epochs, so the caller's
 * record of the grants must exist before they run. Requires a session with a
 * remote Space. Unsatisfiable grants are skipped (they never reach a
 * delegation). Returns the delegated capabilities, in request order.
 *
 * @param options {object}
 * @param options.zcapRequests {ICapabilityQueryDetail[]}
 * @param options.session {Session}
 * @param [options.ttlMs] {number}   read-only grant lifetime; defaults to
 *   RP_ZCAP_TTL_MS
 * @param [options.writeTtlMs] {number}   write grant lifetime; defaults to
 *   RP_ZCAP_WRITE_TTL_MS (shorter than the read TTL)
 * @param [options.shareTtlMs] {number}   share grant lifetime; defaults to
 *   SHARE_ZCAP_TTL_MS (deliberately long -- the settings panel, not expiry, is
 *   the removal mechanism for a share)
 * @param [options.app] {{ name: string, origin: string, appUrl: string }}
 *   present only on the App Connect path: the name and origin are recorded on
 *   each share activity so the settings panel can name the app instead of
 *   showing a bare did:key, and all three are stamped as the attribution of
 *   each collection this call creates.
 * @param [options.beforeProvision] {Function}   `(zcaps) => Promise<void>`,
 *   awaited with every signed grant once signing is done and before any
 *   share is escrowed or collection provisioned; called only when some grant
 *   needs one. A throw ends the request with nothing escrowed.
 * @returns {Promise<IZcap[]>}
 */
export async function processZcaps({
  zcapRequests,
  session,
  ttlMs = RP_ZCAP_TTL_MS,
  writeTtlMs = RP_ZCAP_WRITE_TTL_MS,
  shareTtlMs = SHARE_ZCAP_TTL_MS,
  app,
  beforeProvision
}: {
  zcapRequests: ICapabilityQueryDetail[]
  session: Session
  ttlMs?: number
  writeTtlMs?: number
  shareTtlMs?: number
  app?: { name: string; origin: string; appUrl: string }
  beforeProvision?: (zcaps: IZcap[]) => Promise<void>
}): Promise<IZcap[]> {
  if (zcapRequests.length === 0) {
    return []
  }
  if (!hasZcapStorage(session)) {
    throw new ZcapUnavailableError()
  }

  // `hasZcapStorage` above guarantees a remote backend, so the Space's
  // structural coordinates and its URL both stand. Every collection target
  // below is built from the coordinates through was-client's path builders;
  // the Space URL is the store's own, the one its root capability id names.
  const space = session.storage.spaceLocation!
  const spaceUrl = session.storage.spaceUrl!
  const now = Date.now()
  const { zcapClient } = session.profile
  // A transient session holds its Space authority as a delegated zcap (the
  // generation delegation), so its grants chain under THAT, signed by the
  // annex key the delegation names -- a grant delegated off the root by a
  // key the account document never lists would verify nowhere. A remembered
  // session delegates off the root as before.
  //
  // The annex key signs that child delegation under its annex verification
  // method (`<clientAnnexDid>#<multibase>`), so the loop's correctness rests
  // on a published relation: the server checks a delegation proof under the
  // `CapabilityDelegation` purpose against the resolved annex document, and
  // the transient VM is published there under `capabilityDelegation` beside
  // `capabilityInvocation` (wallet-core's `enrollClientAnnexTransientClient`).
  // Publishing it under invocation alone -- what a wallet-core before 0.58.0
  // did -- leaves every grant this loop mints refused at the server, which
  // masks the refusal as a 404.
  let invocationCapability = session.profile.invocationCapability

  if (
    invocationCapability &&
    delegationStale({ delegation: invocationCapability, session, now })
  ) {
    // The blocking renewal stage, ahead of every remote call below: a grant
    // minted under a lapsing parent would either verify nowhere or lapse
    // within days, and the collection listing that follows rides this very
    // delegation, so an already-expired one must be replaced before it is
    // invoked. The delegation is renewed in place -- ladder-signed, from the
    // standing members the transient login stamped -- and the live session,
    // the remote store included, adopts the fresh one. The refusal stands
    // only when there is nothing to renew with, or the renewal did not
    // produce a current delegation.
    const renewed = await renewTransientGenerationDelegation({ session })
    if (!renewed || delegationStale({ delegation: renewed, session, now })) {
      throw new GenerationDelegationStaleError()
    }
    invocationCapability = renewed
  }

  // The existing collections' public state, fetched fresh at delegation time
  // (the consent preview resolves against its own snapshot): resolution
  // refuses a public grant that would convert an existing collection, and
  // classes any target naming an already-public collection public-collection.
  // A failed listing fails the request rather than resolving against
  // assumed-absent collections. The snapshot stays as fetched. The rows
  // resolve through `resolveGrants`, the consent preview's own resolver, which
  // tracks the collections the request itself provisions beside it.
  const collections = existingCollectionsFrom(
    await session.storage.listCollectionPublicStates()
  )
  const spaceRootCapability = rootCapabilityId(spaceUrl)
  const parentCapability = invocationCapability ?? spaceRootCapability

  /**
   * A grant's expiry for a requested TTL: the full TTL under the root, and
   * under a generation delegation the TTL clamped to the parent's own
   * `expires` (the library refuses a child outliving its parent).
   *
   * @param ttlMs {number}
   * @returns {Date}
   */
  function grantExpires(ttlMs: number): Date {
    if (invocationCapability) {
      return clampGrantExpires({
        ttlMs,
        delegation: invocationCapability,
        now
      })
    }
    return new Date(now + ttlMs)
  }

  /**
   * The grantee's X25519 recipient key, derived from the did:key the wallet is
   * delegating to -- the one recipient derivation in the system, for an app, an
   * agent, and a person alike. Throws when the controller has no Ed25519 twin
   * to derive from (`resolveGrant` already rejected a named controller that
   * cannot; this covers the App Connect path, which fills the controller after
   * resolution).
   *
   * @param options {object}
   * @param [options.controller] {string}
   * @param options.requirement {string}   what needs the recipient key, for
   *   the refusal message
   * @returns {ReturnType<typeof x25519RecipientFromDidKey>}
   */
  function recipientFor({
    controller,
    requirement
  }: {
    controller?: string
    requirement: string
  }) {
    if (!controller || !isEd25519DidKey(controller)) {
      throw new Error(
        `${requirement} requires an Ed25519 did:key controller to derive the ` +
          'recipient key from.'
      )
    }
    return x25519RecipientFromDidKey({ did: controller })
  }

  /**
   * Provisions a collection a grant needs before the grantee can use it,
   * on either request path (App Connect or the interaction-URL agent path).
   * A PRIVATE collection is always
   * provisioned encrypted: the user's vault KAK is recipient zero and the
   * grantee's identity KAK is escrowed beside it. A public-collection grant
   * provisions plaintext with the collection-level PublicCanRead policy, which
   * the wallet (holding the Space root) sets because the RP's delegated zcap
   * could not.
   *
   * On the App Connect path a collection this call creates also carries its
   * attribution, the `generator` object: the grantee did:key as `id`, the
   * requesting origin as `origin`, the app's canonical app URL as `url` (when it has no query or
   * fragment, which the server refuses there), and
   * the app's display name as `name` when it gave one. So the storage browser
   * can name the application a collection belongs to, and a reconnecting app
   * is told apart from another app on its origin. A
   * collection that already stands keeps whatever attribution it has, since
   * was-client's ensure stamps it on the guarded create only: the re-admit pass that adds a second
   * app to an existing private collection cannot rename its creator. An
   * interaction-URL agent grant stamps nothing -- there is no attested origin
   * to record.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.isPublic {boolean}
   * @param [options.controller] {string}   the grantee did:key, for the
   *   attribution
   * @param [options.recipient] {ReturnType<typeof x25519RecipientFromDidKey>}
   *   the grantee's recipient key, derived in the signing pass; required for
   *   a private collection
   * @returns {Promise<void>}
   */
  async function provisionFor({
    collectionId,
    isPublic,
    controller,
    recipient
  }: {
    collectionId: string
    isPublic: boolean
    controller?: string
    recipient?: ReturnType<typeof x25519RecipientFromDidKey>
  }): Promise<void> {
    // `generator` is typed as a DID downstream, and the controller arrives
    // here as a plain request string. `isEd25519DidKey` is the check that
    // earns the `IDID` -- it proves the `did:key:` prefix the type asserts --
    // and a controller that fails it was never a stampable app identity, so
    // it stamps nothing rather than recording a non-DID as the creator.
    const attribution =
      app && isEd25519DidKey(controller)
        ? {
            generator: {
              id: controller as IDID,
              origin: app.origin,
              url: app.appUrl,
              ...(app.name && { name: app.name })
            }
          }
        : {}
    if (!isPublic) {
      if (!recipient) {
        throw new Error(
          'Provisioning an encrypted collection requires the grantee recipient key.'
        )
      }
      await session.storage.provisionEncryptedCollection({
        collectionId,
        recipient,
        ...attribution
      })
      return
    }
    await session.storage.ensureCollection({
      id: collectionId,
      isPublic,
      ...attribution
    })
  }

  // Pass 1 signs each resolved row's delegation. Signing is local and inert
  // (the target need not exist yet), so nothing reaches the server here. A
  // share's escrow and a target that needs provisioning are only recorded, with
  // its recipient key derived up front so an underivable grantee refuses the
  // request before anything is persisted. The record holds one entry per
  // collection and grantee, so two rows naming one new collection provision
  // it once. A second grantee on the same collection keeps its own entry,
  // since its key needs its own escrow.
  const zcaps: IZcap[] = []
  const pending = new Map<
    string,
    {
      collectionId: string
      isPublic: boolean
      controller?: string
      recipient?: ReturnType<typeof x25519RecipientFromDidKey>
    }
  >()
  const pendingShares: Array<{
    collectionId: string
    recipient: ReturnType<typeof x25519RecipientFromDidKey>
    zcap: IDelegatedZcap
  }> = []
  for (const { descriptor, target, allowedActions, write } of resolveGrants({
    zcapRequests,
    space,
    collections
  })) {
    if (!isSatisfiable(target) || !target.invocationTarget) {
      continue
    }
    if (target.targetClass === 'share' && target.collectionId) {
      // A share leaves the plain delegation loop. Its pull axis (a read-only
      // zcap) is signed here, and its read axis (an epoch roster entry) is
      // escrowed in pass 2, after the hook has recorded the signed zcap.
      // `shareCollection` then records its own `CollectionShare` activity.
      const recipient = recipientFor({
        controller: descriptor.controller,
        requirement: 'A shared-collection grant'
      })
      const zcap = await session.storage.delegateShareGrant({
        profile: session.profile,
        collectionId: target.collectionId,
        controller: descriptor.controller!,
        expires: grantExpires(shareTtlMs)
      })
      pendingShares.push({ collectionId: target.collectionId, recipient, zcap })
      zcaps.push(zcap as IZcap)
      continue
    }
    // Collection ids never contain a space, so the key is unambiguous.
    const pendingKey = `${target.collectionId} ${descriptor.controller ?? ''}`
    if (
      target.needsProvisioning &&
      target.collectionId &&
      !pending.has(pendingKey)
    ) {
      const isPublic = target.targetClass === 'public-collection'
      pending.set(pendingKey, {
        collectionId: target.collectionId,
        isPublic,
        controller: descriptor.controller,
        ...(!isPublic && {
          recipient: recipientFor({
            controller: descriptor.controller,
            requirement: 'Provisioning an encrypted collection'
          })
        })
      })
    }
    // Write grants live for the shorter write TTL; read-only grants for the
    // longer read TTL.
    const expires = grantExpires(write ? writeTtlMs : ttlMs)
    const zcap = await zcapClient.delegate({
      capability: parentCapability,
      invocationTarget: target.invocationTarget,
      controller: descriptor.controller,
      allowedActions,
      expires
    })
    zcaps.push(zcap as IZcap)
  }

  if (pending.size === 0 && pendingShares.length === 0) {
    return zcaps
  }
  // Persist before escrow: a share and a private collection's provisioning
  // both add the grantee to key epochs, and revocation finds that grantee
  // only through a stored record of the signed grants. The hook writes that
  // record. A hook that throws ends the request here, with nothing escrowed.
  await beforeProvision?.(zcaps)

  // Pass 2 escrows the shares, then provisions, each in request order.
  for (const { collectionId, recipient, zcap } of pendingShares) {
    await session.storage.shareCollection({
      profile: session.profile,
      user: session.user,
      collectionId,
      recipient,
      zcap,
      // The share activity records the app's name and origin alone.
      ...(app && { app: { name: app.name, origin: app.origin } })
    })
  }
  for (const entry of pending.values()) {
    await provisionFor(entry)
  }
  return zcaps
}
