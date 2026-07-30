/**
 * Zcap request processing for "Login with Wallet": resolves each requested
 * capability's abstract `invocationTarget` descriptor onto the user's own WAS
 * Space, provisions any missing RP collection, and delegates a capability to
 * the relying party's DID. All delegations are rooted at the user's Space root
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
 * - whole Space -- read-only (a Space-wide write would permit rewriting the
 *   Space Description, i.e. controller takeover);
 * - a protected wallet collection -- the standard collections
 *   (`private-credentials`, `public-credentials`, `wallet-activity`), the `id`
 *   collection holding the user's published DID artifacts, and the `key-map`
 *   collection holding the private key-id map -- read-only: an RP may read but
 *   never rewrite or delete the user's own credentials, published identity, or
 *   key map;
 * - a share -- read-only (see below);
 * - a public collection -- add-only: reads plus `POST`, never `PUT` or
 *   `DELETE`. A write to a plaintext world-readable target is not data
 *   management but publication under the user's identity, and irreversible in
 *   practice, so an RP may add to what it published but never rewrite or
 *   retract it;
 * - an RP-provisioned private collection -- the full vocabulary, subject to the
 *   consent screen and the shorter write TTL.
 *
 * The class is resolved from the target itself, so it applies whether the
 * target arrives as a descriptor object or as a plain URL string under the
 * Space (the collection id is derived from the first path segment after the
 * Space URL either way) -- a string target cannot bypass it. A request whose
 * actions are all dropped or all above its class's ceiling renders the grant
 * unsatisfiable rather than empty: an empty `allowedAction` array means "every
 * action" in the zcap model.
 *
 * A `urn:was:public-collection` grant provisions a plaintext collection with a
 * collection-level world-readable (PublicCanRead) policy, set by the wallet at
 * provisioning time. Public covers only unauthenticated reads; writes stay
 * capability-only, so the grant still delegates the usual collection-scoped
 * zcap (with the ordinary write TTL). A public grant on a protected wallet
 * collection is unsatisfiable, unconditionally.
 *
 * A `urn:was:shared-collection` grant is the share flow: it asks not just to
 * fetch one of the wallet's own encrypted collections but to DECRYPT it. It
 * leaves the ordinary delegation loop entirely and routes to
 * `StorageManager.shareCollection`, which grants both axes -- the read-only
 * pull zcap and the key-epoch roster entry -- in one indivisible call. The
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
import { generateZcapUri } from '@interop/ezcap'
import type { Session } from '@/types/auth'
import {
  ID_COLLECTION,
  KEY_MAP_COLLECTION,
  RP_ZCAP_TTL_MS,
  RP_ZCAP_WRITE_TTL_MS,
  SHARE_ZCAP_TTL_MS,
  WALLET_STANDARD_COLLECTIONS
} from '@/app.config'
import { deriveAppCollectionRecipient } from '@/lib/appCollectionRecipient'
import {
  isEd25519DidKey,
  x25519RecipientFromDidKey
} from '@/lib/didKeyRecipient'
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
export type TargetClass =
  | 'space'
  | 'protected-collection'
  | 'share'
  | 'public-collection'
  | 'collection'

/**
 * The most any grant on a target of each class may be delegated. Requested
 * actions are intersected against the row; nothing else is ever granted, no
 * matter what the request asks for.
 */
const ACTION_CEILINGS: Record<TargetClass, readonly WasAction[]> = {
  // A Space-wide write would permit rewriting the Space Description, i.e.
  // controller takeover.
  space: ['GET', 'HEAD'],
  // The user's own credentials, activity log, published DID artifacts, and
  // private key-id map: readable by an RP, never writable by one.
  'protected-collection': ['GET', 'HEAD'],
  // A share hands over decryption as well as fetch; it is never a write grant.
  share: ['GET', 'HEAD'],
  // Add-only. The collection is plaintext and world-readable, so a write there
  // is publication under the user's identity and irreversible in practice
  // (retracting removes the link, not the copies already fetched): an app may
  // add to what it published, but never rewrite or retract it.
  'public-collection': ['GET', 'HEAD', 'POST'],
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
 * Whether a resolved collection id names a protected wallet collection --
 * a standard collection (`private-credentials`, `public-credentials`,
 * `wallet-activity`), the `id` collection holding the user's published DID
 * artifacts, or the `key-map` collection holding the private key-id map --
 * which an RP may read but never write.
 *
 * @param collectionId {string | undefined}
 * @returns {boolean}
 */
function isProtectedCollection(collectionId: string | undefined): boolean {
  return (
    !!collectionId &&
    (collectionId === ID_COLLECTION.id ||
      collectionId === KEY_MAP_COLLECTION.id ||
      WALLET_STANDARD_COLLECTIONS.some(entry => entry.id === collectionId))
  )
}

/**
 * Collection id naming rule (D2): lowercase alphanumerics and hyphens, not
 * starting with a hyphen, up to 64 characters.
 */
const COLLECTION_NAME_RE = /^[a-z0-9][a-z0-9-]{0,63}$/

/**
 * A requested capability's `invocationTarget` resolved against the user's own
 * Space. `satisfiable: false` means the descriptor cannot be fulfilled (a
 * foreign URL, an invalid collection name, or an unknown descriptor type); it
 * is skipped at delegation time and shown as "cannot fulfill" on consent.
 */
export interface ResolvedTarget {
  satisfiable: boolean
  // The concrete WAS URL to delegate against (absent when unsatisfiable).
  invocationTarget?: string
  // The grant targets the whole Space (capped to read-only).
  wholeSpace: boolean
  // A named RP collection that does not exist yet and must be provisioned.
  needsProvisioning: boolean
  // The WAS collection id, when the target is a (standard or RP) collection.
  collectionId?: string
  // A standard EDV-encrypted collection: the RP will only see ciphertext.
  encrypted: boolean
  // A `urn:was:public-collection` grant: provisioned plaintext with a
  // collection-level PublicCanRead policy, so anyone on the web can read it.
  isPublic: boolean
  // A `urn:was:shared-collection` grant: the grantee joins the collection's
  // key-epoch roster and can DECRYPT it, not merely fetch ciphertext. Always an
  // encrypted standard collection, always read-only.
  isShare: boolean
  // Which action ceiling applies (`ACTION_CEILINGS`). Absent only when the
  // target is unsatisfiable, i.e. when no grant will be made at all.
  targetClass?: TargetClass
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

const UNSATISFIABLE: ResolvedTarget = Object.freeze({
  satisfiable: false,
  wholeSpace: false,
  needsProvisioning: false,
  encrypted: false,
  isPublic: false,
  isShare: false
})

/**
 * Parses a plain-URL invocation target against the Space URL, returning the
 * normalized target and the path segment naming its collection (empty for the
 * Space itself), or `undefined` if the URL is not inside the Space.
 *
 * String matching alone is not enough to decide "inside the Space", which is
 * what the collection ceilings hang off: `${spaceUrl}/private-credentials?x=1`
 * and `${spaceUrl}/private-credentials#frag` both start with `${spaceUrl}/`
 * while their first segment is not the collection id the server would route
 * them to, and `${spaceUrl}/../other-space/x` starts with it while pointing
 * outside the Space entirely. So parse: `new URL` resolves dot segments, and
 * the query and fragment come off the path before the segment is taken. A
 * target carrying a query or a fragment is refused outright rather than
 * silently rewritten -- a WAS resource URL has neither, and dropping part of a
 * target the user is about to consent to would show them something other than
 * what gets delegated.
 *
 * @param options {object}
 * @param options.target {string}
 * @param options.spaceUrl {string}
 * @returns {{ url: string, segment: string } | undefined}
 */
function parseSpaceUrl({
  target,
  spaceUrl
}: {
  target: string
  spaceUrl: string
}): { url: string; segment: string } | undefined {
  let url: URL
  let space: URL
  try {
    url = new URL(target)
    space = new URL(spaceUrl)
  } catch {
    return undefined
  }
  if (url.search || url.hash || url.origin !== space.origin) {
    return undefined
  }
  const spacePath = space.pathname.replace(/\/+$/, '')
  const path = url.pathname.replace(/\/+$/, '')
  if (path === spacePath) {
    return { url: `${url.origin}${path}`, segment: '' }
  }
  if (!path.startsWith(`${spacePath}/`)) {
    return undefined
  }
  return {
    url: `${url.origin}${path}`,
    segment: path.slice(spacePath.length + 1).split('/')[0]
  }
}

/**
 * Resolves an abstract `invocationTarget` descriptor against the user's Space:
 *
 * - a plain URL string inside the Space -- parsed and normalized against
 *   `spaceUrl` (`parseSpaceUrl`), with the collection id taken from the first
 *   path segment after the Space URL, so a URL under a standard collection (or
 *   at a resource inside one) is flagged `collectionId` / `encrypted` and gets
 *   the same cap as its descriptor form. The Space URL itself, with or without
 *   a trailing slash, is a whole-Space grant. Any other string -- a foreign
 *   origin, a path that escapes the Space, a target carrying a query or
 *   fragment, a first segment that is not a valid collection id --
 *   unsatisfiable;
 * - `{ type: 'urn:was:collection', name }` -- `${spaceUrl}/${name}` after
 *   validating `name`, flagged `needsProvisioning` unless it is a standard
 *   collection (and `encrypted` for the two EDV collections);
 * - `{ type: 'urn:was:public-collection', name }` -- like `urn:was:collection`
 *   but flagged `isPublic`: provisioned plaintext with a world-readable
 *   (PublicCanRead) policy. Unsatisfiable on a protected wallet collection --
 *   an RP must never be able to flip the user's own collections public;
 * - `{ type: 'urn:was:shared-collection', name }` -- like `urn:was:collection`
 *   but flagged `isShare`: the grantee also joins the collection's key-epoch
 *   roster, so it can decrypt what it fetches. `name` must be one of the
 *   ENCRYPTED standard collections; anything else (a plaintext collection, an
 *   RP collection, the whole Space) is unsatisfiable -- a share is only
 *   meaningful where an epoch roster exists;
 * - `{ type: 'urn:was:space' }` -- `spaceUrl`, flagged `wholeSpace`;
 * - anything else -- unsatisfiable.
 *
 * @param options {object}
 * @param options.descriptor {string | { type: string; name?: string }}
 * @param options.spaceUrl {string}
 * @returns {ResolvedTarget}
 */
export function resolveInvocationTarget({
  descriptor,
  spaceUrl
}: {
  descriptor: string | { type?: string; name?: string }
  spaceUrl: string
}): ResolvedTarget {
  if (typeof descriptor === 'string') {
    const parsed = parseSpaceUrl({ target: descriptor, spaceUrl })
    if (!parsed) {
      return UNSATISFIABLE
    }
    const { url, segment } = parsed
    // No collection segment: the target is the Space itself (with or without a
    // trailing slash), which is a whole-Space grant.
    if (!segment) {
      return {
        satisfiable: true,
        invocationTarget: url,
        wholeSpace: true,
        needsProvisioning: false,
        encrypted: false,
        isPublic: false,
        isShare: false,
        targetClass: 'space'
      }
    }
    // A segment that cannot be a collection id names nothing the Space can
    // hold, so there is nothing to delegate against.
    if (!COLLECTION_NAME_RE.test(segment)) {
      return UNSATISFIABLE
    }
    // The collection id is the first path segment after the Space URL, so a
    // URL under a standard collection (or at a resource inside one) is capped
    // exactly like its `urn:was:collection` descriptor form.
    const standard = WALLET_STANDARD_COLLECTIONS.find(
      entry => entry.id === segment
    )
    return {
      satisfiable: true,
      invocationTarget: url,
      wholeSpace: false,
      needsProvisioning: false,
      collectionId: segment,
      encrypted: !!standard?.encryption,
      isPublic: false,
      isShare: false,
      targetClass: isProtectedCollection(segment)
        ? 'protected-collection'
        : 'collection'
    }
  }

  if (descriptor?.type === 'urn:was:space') {
    return {
      satisfiable: true,
      invocationTarget: spaceUrl,
      wholeSpace: true,
      needsProvisioning: false,
      encrypted: false,
      isPublic: false,
      isShare: false,
      targetClass: 'space'
    }
  }

  if (descriptor?.type === 'urn:was:collection') {
    const { name } = descriptor
    if (!name || !COLLECTION_NAME_RE.test(name)) {
      return UNSATISFIABLE
    }
    const standard = WALLET_STANDARD_COLLECTIONS.find(
      entry => entry.id === name
    )
    return {
      satisfiable: true,
      invocationTarget: `${spaceUrl}/${name}`,
      wholeSpace: false,
      // The `id` and `key-map` collections are provisioned at login, like the
      // standard ones.
      needsProvisioning:
        !standard &&
        name !== ID_COLLECTION.id &&
        name !== KEY_MAP_COLLECTION.id,
      collectionId: name,
      encrypted: !!standard?.encryption,
      isPublic: false,
      isShare: false,
      targetClass: isProtectedCollection(name)
        ? 'protected-collection'
        : 'collection'
    }
  }

  if (descriptor?.type === 'urn:was:public-collection') {
    const { name } = descriptor
    if (!name || !COLLECTION_NAME_RE.test(name)) {
      return UNSATISFIABLE
    }
    // A public grant on a protected wallet collection is refused
    // unconditionally: an RP must never be able to make the user's own
    // credentials, activity log, or published identity world-readable.
    if (isProtectedCollection(name)) {
      return UNSATISFIABLE
    }
    return {
      satisfiable: true,
      invocationTarget: `${spaceUrl}/${name}`,
      wholeSpace: false,
      needsProvisioning: true,
      collectionId: name,
      // Public implies plaintext: the collection is provisioned without an
      // encryption marker, so a ciphertext note never applies.
      encrypted: false,
      isPublic: true,
      isShare: false,
      targetClass: 'public-collection'
    }
  }

  if (descriptor?.type === 'urn:was:shared-collection') {
    const { name } = descriptor
    const standard = WALLET_STANDARD_COLLECTIONS.find(
      entry => entry.id === name
    )
    // Only the encrypted standard collections have a key-epoch roster to
    // escrow a reader into; everything else (a plaintext collection, an RP
    // collection, a made-up name) cannot be shared.
    if (!standard?.encryption) {
      return UNSATISFIABLE
    }
    return {
      satisfiable: true,
      invocationTarget: `${spaceUrl}/${name}`,
      wholeSpace: false,
      needsProvisioning: false,
      collectionId: name,
      encrypted: true,
      isPublic: false,
      isShare: true,
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
 * @param options.spaceUrl {string}
 * @returns {ResolvedGrant}
 */
export function resolveGrant({
  descriptor,
  spaceUrl
}: {
  descriptor: ICapabilityQueryDetail
  spaceUrl: string
}): ResolvedGrant {
  let target = resolveInvocationTarget({
    descriptor: descriptor.invocationTarget,
    spaceUrl
  })
  // A share's recipient key is DERIVED from the grantee's controller DID, so a
  // controller the derivation cannot handle cannot be a share recipient. Run
  // the real derivation rather than a shape check: a well-formed-looking but
  // malformed did:key (a truncated identifier, a non-curve point) would
  // otherwise preview as satisfiable and then throw mid-response, after earlier
  // grants in the same request had already been delegated. App Connect resolves
  // with an empty controller at preview time (the app-key DID may not exist
  // yet) and fills the real one before delegating, so an absent controller is
  // not yet a failure.
  if (target.isShare && descriptor.controller) {
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
  if (target.satisfiable && allowedActions.length === 0) {
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
 * Resolves every requested capability against the user's Space, for the consent
 * preview. Pure -- no provisioning or delegation.
 *
 * @param options {object}
 * @param options.zcapRequests {ICapabilityQueryDetail[]}
 * @param options.spaceUrl {string}
 * @returns {ResolvedGrant[]}
 */
export function resolveGrants({
  zcapRequests,
  spaceUrl
}: {
  zcapRequests: ICapabilityQueryDetail[]
  spaceUrl: string
}): ResolvedGrant[] {
  return zcapRequests.map(descriptor => resolveGrant({ descriptor, spaceUrl }))
}

/**
 * Delegates capabilities to the relying parties named in the requests, on the
 * consent-approved path. Provisions any missing RP collection first, then
 * delegates each satisfiable grant rooted at the user's Space root capability.
 * Requires a session with a remote Space. Unsatisfiable grants are skipped
 * (they never reach a delegation). Returns the delegated capabilities, in
 * request order.
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
 * @param [options.appProvisioning] {{ seed: Uint8Array }}   present only on the
 *   App Connect path: the app-key seed from which each newly-provisioned PRIVATE
 *   collection is set up multi-recipient (vault KAK plus the app's deterministic
 *   per-collection key) instead of plaintext. Public collections and
 *   non-App-Connect flows provision plaintext as before.
 * @param [options.app] {{ name: string, origin: string }}   present only on the
 *   App Connect path: recorded on each share activity so the settings panel can
 *   name the app instead of showing a bare did:key.
 * @returns {Promise<IZcap[]>}
 */
export async function processZcaps({
  zcapRequests,
  session,
  ttlMs = RP_ZCAP_TTL_MS,
  writeTtlMs = RP_ZCAP_WRITE_TTL_MS,
  shareTtlMs = SHARE_ZCAP_TTL_MS,
  appProvisioning,
  app
}: {
  zcapRequests: ICapabilityQueryDetail[]
  session: Session
  ttlMs?: number
  writeTtlMs?: number
  shareTtlMs?: number
  appProvisioning?: { seed: Uint8Array }
  app?: { name: string; origin: string }
}): Promise<IZcap[]> {
  if (!hasZcapStorage(session)) {
    throw new ZcapUnavailableError()
  }

  // `hasZcapStorage` above guarantees a resolved `spaceUrl`.
  const spaceUrl = session.storage.spaceUrl!
  const spaceRootCapability = await generateZcapUri({ url: spaceUrl })
  const now = Date.now()
  const { zcapClient } = session.profile

  const zcaps: IZcap[] = []
  for (const descriptor of zcapRequests) {
    const { target, allowedActions, write } = resolveGrant({
      descriptor,
      spaceUrl
    })
    if (!target.satisfiable || !target.invocationTarget) {
      continue
    }
    if (target.isShare && target.collectionId) {
      // A share leaves the plain delegation loop: `shareCollection` grants the
      // pull axis (a read-only zcap) and the read axis (an epoch roster entry)
      // in one call, so the two can never come apart. `resolveGrant` already
      // rejected a controller whose recipient key cannot be derived when one
      // was named; this guard covers the App Connect path, which fills the
      // controller after resolution.
      if (!isEd25519DidKey(descriptor.controller)) {
        throw new Error(
          'A shared-collection grant requires an Ed25519 did:key controller ' +
            'to derive the recipient key from.'
        )
      }
      const { zcap } = await session.storage.shareCollection({
        profile: session.profile,
        user: session.user,
        collectionId: target.collectionId,
        recipient: x25519RecipientFromDidKey({ did: descriptor.controller }),
        controller: descriptor.controller,
        expires: new Date(now + shareTtlMs),
        app
      })
      zcaps.push(zcap as IZcap)
      continue
    }
    if (target.needsProvisioning && target.collectionId) {
      if (appProvisioning && !target.isPublic) {
        // App Connect PRIVATE collection: provision multi-recipient EDV, with
        // the user's vault KAK as recipient zero and the app's deterministic
        // per-collection key alongside it, so both can read what the app writes.
        const appRecipient = await deriveAppCollectionRecipient({
          seed: appProvisioning.seed,
          collectionId: target.collectionId
        })
        await session.storage.provisionAppCollection({
          collectionId: target.collectionId,
          appRecipient
        })
      } else {
        // A public-collection grant provisions plaintext plus a collection-level
        // PublicCanRead policy; the wallet (holding the space root) sets the
        // policy -- the RP's delegated zcap could not. A non-App-Connect grant
        // provisions a plaintext RP collection.
        await session.storage.ensureCollection({
          id: target.collectionId,
          isPublic: target.isPublic
        })
      }
    }
    // Write grants live for the shorter write TTL; read-only grants for the
    // longer read TTL.
    const expires = new Date(now + (write ? writeTtlMs : ttlMs))
    const zcap = await zcapClient.delegate({
      capability: spaceRootCapability,
      invocationTarget: target.invocationTarget,
      controller: descriptor.controller,
      allowedActions,
      expires
    })
    zcaps.push(zcap as IZcap)
  }
  return zcaps
}
