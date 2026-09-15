/**
 * WASRemoteStore: the remote WAS (Wallet Attached Storage) backend, attached
 * when VITE_WAS_SERVER_URL (the server's Spaces Repository URL) is set.
 * Since the local BrowserStore became the always-active replica, this class
 * no longer serves credential / history / public-link reads and writes for
 * the main app -- those replicate in the background through the sync
 * controller. What remains here is the Space
 * lifecycle (create / exists / wipe), the storage-browser read-through over
 * arbitrary Collections and Resources, export / import, and quotas.
 *
 * One exception is a replica-less session (the default transient session,
 * and the CHAPI popup, whose local IndexedDB is a third-party partitioned
 * bucket no sync controller drives): its remote-direct backend (see
 * `StorageManager`) reads and writes the standard synced collections here
 * directly, listing them by paging the `changes` feed
 * (`listSyncedDocuments`) and reading and writing single resources through
 * `getSyncedResource` / `putSyncedResource` -- reproducing verbatim what
 * background replication would have pushed.
 *
 * All WAS operations go through `@interop/was-client`'s `WasClient` and its
 * lazy navigational handles (`space` / `collection` / `resource`) rather than
 * hand-built ezcap requests. The `WasClient` wraps the ezcap `ZcapClient` that
 * carries the user's invocation signer.
 */
import type { ZcapClient } from '@interop/ezcap'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import type { IDID } from '@interop/data-integrity-core'
import {
  readEtag,
  WasClient,
  type Collection,
  type CollectionEncryption,
  type IZcap,
  type Resource,
  type ServiceDescription,
  type Space,
  type SpaceMetadata
} from '@interop/was-client'
import {
  collectionPath,
  resourcePath,
  spacePath,
  toUrl
} from '@interop/was-client/paths'
import { createEdvEncryption } from '@interop/was-client/edv'
import { publicCredentialUrl as buildPublicCredentialUrl } from '@interop/wallet-core/space'
import {
  wasClientLabelsStore,
  type ClientLabelsStore
} from '@interop/wallet-core/keys'
import {
  isWebvhDid,
  wasWebvhIdStore,
  type WebvhIdStore
} from '@interop/wallet-core/webvh'
import type { SessionCore, User } from '@/types/auth'
import {
  DID_DOCUMENT_RESOURCE,
  DID_KEYS_RESOURCE,
  ID_COLLECTION,
  KEY_MAP_COLLECTION,
  UNLOCK_METHODS_COLLECTION,
  UNLOCK_METHODS_RESOURCE,
  WALLET_STANDARD_COLLECTIONS,
  WAS_SYNC_BATCH_SIZE
} from '@/app.config'
import type { Json } from '@interop/was-sync'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import type { SpaceQuotaReport } from '@/types/storageQuota'
import {
  type FetchedCollectionResource,
  isTextLikeContentType
} from '@/lib/storageResource'
import type { ImportSpaceSummary } from '@/stores/storageManager'
import {
  deriveSpaceId,
  ensureSpaceAndCollection,
  errorStatus,
  KEY_EPOCH_HEADER
} from '@interop/was-client/sync'
import { provisionWalletSpace } from '@interop/wallet-core/space'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  ensureWalletSpaceEpochs,
  type UserKey
} from '@interop/wallet-core/keys'
import { createLogger } from '@/lib/log'
import { wasServiceDescription } from '@/lib/wasService'

const log = createLogger('fw:storage:remote')

/**
 * The `changes` page size a synced-collection listing requests when no
 * `VITE_WAS_SYNC_BATCH_SIZE` is configured: the spec's recommended server
 * default, so the request and the server's own maximum agree.
 */
const SYNCED_LISTING_PAGE_SIZE = 100

/**
 * Map from logical collection name to its WAS base URL.
 * Expected keys: 'privateCredentials' | 'publicCredentials' | 'walletActivity'
 */
export type ICollectionsSet = Map<string, string>

/**
 * @see https://digitalcredentials.github.io/wallet-attached-storage-spec/
 * @see https://github.com/interop-alliance/zcap-developer-guide
 */
/**
 * Mints a fresh Space id for a new account: an independent random
 * identifier (32 bytes, base64url), carried in the account pointer from
 * then on. Deliberately not a derivation of any controller: the account's
 * controller is promoted to a did:webvh whose id embeds this Space id, so a
 * controller-derived id would be circular. Unlock Spaces keep their
 * `hash(unlock did:key)` addressing -- that derivation is a discovery
 * convention, not an identity.
 *
 * The mint itself is the shared one from `@interop/wallet-core/genesis`, so
 * both wallet apps mint the same shape; re-exported under this name because
 * the app imports it from here.
 */
export { mintSpaceId } from '@interop/wallet-core/genesis'

/**
 * The one narrowing of a Space controller onto the DID type was-client's
 * Space Description carries. Every controller this store is handed is a
 * did:key or a did:webvh, but the pointer and key-agent ids it arrives
 * through are typed as plain strings upstream.
 *
 * @param controller {string}
 * @returns {IDID}
 */
function controllerDid(controller: string): IDID {
  if (!controller.startsWith('did:')) {
    throw new Error(`Space controller is not a DID: ${controller}`)
  }
  return controller as IDID
}

export class WASRemoteStore {
  public storageServerUrl: string
  // The server's service description, discovered once per page load by
  // `@/lib/wasService` and handed in: every client this store builds takes
  // it, so none discovers on its own. Absent only when the server could not
  // be reached at login -- an offline remembered login still builds the
  // store, so its local replica keeps serving, and the clients it builds
  // discover for themselves at their first request (and fail there, exactly
  // as an unreachable server always did).
  #discovered?: ServiceDescription
  public was: WasClient
  public spaceId: string
  public controller: IDID

  public spaceUrl: string
  public collections?: ICollectionsSet
  // The invocation capability every request rides when one was supplied (a
  // delegated Space-subtree zcap -- the transient session's generation
  // delegation). Absent, every request invokes the root capability, exactly
  // as before the option existed.
  #capability?: IZcap
  // The session's chain-head pins: the `id`-collection store built here
  // carries them under the account log's slot, so every did:webvh ceremony
  // read and publish through it is checked against the pin and advances it.
  #pinStore: ResourceLogPinStore

  /**
   * The server's discovered service description.
   *
   * @returns {ServiceDescription}
   * @throws {Error}   when discovery never succeeded (the server was
   *   unreachable when this session started), so a caller that needs it gets
   *   a named refusal rather than an undefined threaded onward
   */
  get serviceDescription(): ServiceDescription {
    if (!this.#discovered) {
      throw new Error(
        'The WAS server was unreachable when this session started, so no ' +
          'service description was discovered.'
      )
    }
    return this.#discovered
  }

  constructor({
    storageServerUrl,
    serviceDescription,
    zcapClient,
    spaceId,
    controller,
    capability,
    pinStore
  }: {
    storageServerUrl: string
    serviceDescription?: ServiceDescription
    zcapClient: ZcapClient
    spaceId: string
    controller: string
    capability?: IZcap
    pinStore: ResourceLogPinStore
  }) {
    this.storageServerUrl = storageServerUrl
    this.#discovered = serviceDescription
    this.#pinStore = pinStore
    this.was = this.#clientFor({ zcapClient })
    this.spaceId = spaceId
    this.controller = controllerDid(controller)
    this.#capability = capability
    // Through the path builders rather than by hand: the Space URL is a zcap
    // `invocationTarget`, which the server matches by exact bytes, and the
    // canonical container form (a trailing slash) and the sub-path join are
    // was-client's rules to own.
    this.spaceUrl = toUrl({
      serverUrl: storageServerUrl,
      path: spacePath(spaceId)
    })
  }

  /**
   * Swaps the bound invocation capability for a freshly minted one -- the
   * transient session's generation-delegation renewal, whose replacement
   * must reach the requests this store makes for the rest of the session.
   * Every request site reads the field at call time, so the swap takes
   * effect immediately; nothing already in flight is retried.
   *
   * @param options {object}
   * @param options.capability {IZcap}   the fresh delegation
   * @returns {void}
   */
  adoptInvocationCapability({ capability }: { capability: IZcap }): void {
    this.#capability = capability
  }

  /**
   * The `Space` handle every navigational request in this store rides -- the
   * one place `this.was.space(...)` is called, so no request path can miss
   * the bound invocation capability. With no capability bound the handle
   * invokes the root capability, byte-identical to the direct call.
   *
   * @param [spaceId] {string}   defaults to this store's Space
   * @returns {Space}
   */
  #space(spaceId: string = this.spaceId): Space {
    return this.was.space(spaceId, { capability: this.#capability })
  }

  /**
   * Resolves the actual WAS collection id for one of the wallet's standard
   * logical collection keys.
   *
   * @param logicalKey {string} e.g. 'privateCredentials' | 'walletActivity'.
   * @returns {string}
   */
  #collectionId(logicalKey: string): string {
    const def = WALLET_STANDARD_COLLECTIONS.find(
      entry => entry.key === logicalKey
    )
    if (!def) {
      throw new Error(`Unknown logical collection "${logicalKey}".`)
    }
    return def.id
  }

  /**
   * Parses a WAS resource/collection URL (absolute or relative to the storage
   * server) into its `spaceId` / `collectionId` / `resourceId` components.
   *
   * @param url {string}
   * @returns {{ spaceId: string, collectionId?: string, resourceId?: string }}
   */
  #parsePath(url: string): {
    spaceId: string
    collectionId?: string
    resourceId?: string
  } {
    const { pathname } = new URL(url, this.storageServerUrl)
    const [root, spaceId, collectionId, resourceId] = pathname
      .split('/')
      .filter(Boolean)
    if (root !== 'space' || !spaceId) {
      throw new Error(`Not a WAS resource URL: "${url}".`)
    }
    return { spaceId, collectionId, resourceId }
  }

  /**
   * Returns a `Collection` handle addressed by an arbitrary WAS collection URL
   * (used by the storage browser, which works over collections beyond the
   * standard set).
   *
   * @param url {string}
   * @returns {Collection}
   */
  #collectionFromUrl(url: string): Collection {
    const { spaceId, collectionId } = this.#parsePath(url)
    if (!collectionId) {
      throw new Error(`Not a WAS collection URL: "${url}".`)
    }
    return this.#space(spaceId).collection(collectionId)
  }

  /**
   * Returns a `Resource` handle addressed by an arbitrary WAS resource URL.
   *
   * The handle forces the `plaintext` encryption override, so a `get()` returns
   * the raw stored body (the EDV envelope for an encryption-marked collection)
   * rather than running the codec. The override is load-bearing: this store's
   * `WasClient` is built with a fail-closed encryption provider (its
   * `resolveKeys` always returns `null`), so without it a read of a marked
   * collection's resource would throw during codec resolution before the GET.
   * That matches the storage browser's contract -- it renders raw bodies
   * verbatim and never touches keys. The delete path never runs the codec, so
   * the override is a no-op there.
   *
   * @param url {string}
   * @returns {Resource}
   */
  #resourceFromUrl(url: string): Resource {
    const { spaceId, collectionId, resourceId } = this.#parsePath(url)
    if (!collectionId || !resourceId) {
      throw new Error(`Not a WAS resource URL: "${url}".`)
    }
    return this.#space(spaceId)
      .collection(collectionId)
      .resource(resourceId, { encryption: 'plaintext' })
  }

  /**
   * Returns the base URL of an initialized collection by its logical name,
   * throwing a clear error if collections haven't been initialized yet.
   *
   * @param collectionId {string} Logical collection key, e.g.
   *   'privateCredentials' | 'publicCredentials' | 'walletActivity'.
   * @returns {string}
   */
  collectionUrl(collectionId: string): string {
    const collectionUrl = this.collections?.get(collectionId)
    if (!collectionUrl) {
      throw new Error(
        `Collection "${collectionId}" is not initialized. ` +
          'Call ensureUserCollections() first.'
      )
    }
    return collectionUrl
  }

  /**
   * Reads a standard collection's `encryption` descriptor (the widened
   * `CollectionEncryption` with its `epochs` / `currentEpoch` roster), or
   * `undefined` when the collection is plaintext or has no descriptor. Network
   * errors throw through: callers treat a descriptor fetch as best-effort and fall
   * back to a cached copy.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id (e.g.
   *   `private-credentials`)
   * @returns {Promise<CollectionEncryption | undefined>}
   */
  async collectionEncryption({
    collectionId
  }: {
    collectionId: string
  }): Promise<CollectionEncryption | undefined> {
    const metadata = await this.collectionMetadata({ collectionId })
    return metadata?.encryption ?? undefined
  }

  /**
   * Reads one Collection Metadata object -- the Collection's configuration
   * (`encryption` among it) and its user-writable `custom`, which WAS v0.5
   * serves as one object at one path under one `metaVersion` validator. The
   * read is `describe()`, which never resolves the codec, so `custom` comes
   * back exactly as stored: on an encrypted collection that is the opaque
   * envelope carrying the persisted blinded-index schema, the shape
   * `createEdvDocCipher`'s `meta` input and `applyMeta` take. No keys are
   * needed for the fetch.
   *
   * Returns `undefined` when the collection is missing or not visible
   * (was-client resolves `null` for both). Network errors throw through:
   * callers treat the fetch as best-effort and fall back to a cached copy.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id
   * @returns {Promise<{ encryption?: CollectionEncryption, custom?: unknown } | undefined>}
   */
  async collectionMetadata({
    collectionId
  }: {
    collectionId: string
  }): Promise<
    { encryption?: CollectionEncryption; custom?: unknown } | undefined
  > {
    const metadata = await this.#space().collection(collectionId).describe()
    return metadata ?? undefined
  }

  /**
   * A collection's stored `custom` value raw -- the same Collection Metadata
   * object {@link collectionMetadata} reads, narrowed to the member the index
   * schema rides in. The envelope is decrypted later, by the cipher it is
   * handed. Returns `undefined` when the collection is missing or no `custom`
   * value is stored (was-client's read drops a cleared `custom`, so absence
   * has one shape here).
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id
   * @returns {Promise<{ custom?: unknown } | undefined>}
   */
  async collectionMeta({
    collectionId
  }: {
    collectionId: string
  }): Promise<{ custom?: unknown } | undefined> {
    const custom = (await this.collectionMetadata({ collectionId }))?.custom
    return custom === undefined ? undefined : { custom }
  }

  /**
   * The `Collection` handle for a standard collection, invoked with the root
   * capability -- used by the recipient operations (`initRecipients` /
   * `addRecipient` / `removeRecipient`), which rewrite the Collection
   * Description.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @returns {Collection}
   */
  collectionHandle({ collectionId }: { collectionId: string }): Collection {
    return this.#space().collection(collectionId)
  }

  /**
   * The `Space` handle (root capability), needed by `removeRecipient` to revoke
   * a reader's pull-axis zcap(s) via `space.revoke()`.
   *
   * @returns {Space}
   */
  spaceHandle(): Space {
    return this.#space()
  }

  async userExists() {
    // describe() returns null on a 404 (not-found or unauthorized).
    return (await this.#space().describe()) !== null
  }

  async ensureUserCollections({ user: _user }: { user: User }) {
    // The full wallet-Space layout -- the synced feeds plus the non-synced
    // `id` / `key-map` system collections -- is provisioned by the shared
    // one-shot `provisionWalletSpace`: the roster, the per-collection config
    // (display name, encryption declaration, public-read grant), the
    // app-neutral Space name, and the name-only retry for an encrypted
    // collection whose descriptor already carries key epochs all live in
    // `@interop/wallet-core/space`, so a Space provisioned here is identical
    // to one provisioned by the mobile wallet. Only the synced feeds get an
    // entry in the local collection map (`id` / `key-map` have no RxDB `key`,
    // no local replica).
    await provisionWalletSpace({
      was: this.was,
      spaceId: this.spaceId,
      controllerDid: this.controller
    })

    this.bindCollectionMap()
  }

  /**
   * Binds the local collection map (logical name to WAS base URL) for the
   * synced feeds. Split out of `ensureUserCollections` so a caller that
   * provisioned the Space through the shared account-genesis ceremony -- which
   * runs the same `provisionWalletSpace` -- still gets the map without
   * provisioning twice.
   *
   * @returns {void}
   */
  bindCollectionMap(): void {
    const collections: ICollectionsSet = new Map()
    for (const { key, id } of WALLET_STANDARD_COLLECTIONS) {
      collections.set(key, this.collectionTargetUrl(id))
    }
    this.collections = collections
  }

  /**
   * The EDV-bearing second step of the shared provisioning two-step: installs
   * key epoch[0] on every encrypted collection of the wallet-Space roster
   * (contacts included), wrapped to the account's user key. Create-if-absent
   * through the descriptor-store seam, adopting (never overwriting) a roster
   * another provisioner already landed -- so re-running after a tear
   * converges, and exactly one epoch[0] ever exists per collection. Run right
   * after `ensureUserCollections`, before any encrypted collection's first
   * content push: every encrypted collection carries its key epochs from
   * birth, and ciphers refuse fail-closed without them.
   *
   * @param options {object}
   * @param options.userKey {UserKey}   the account's user key, epoch[0]'s one
   *   initial recipient
   * @param options.storeFor {Function}   `(collectionId) =>
   *   EncryptionDescriptorStore` -- each collection's log-governed
   *   descriptor store, through which epoch[0] lands as the governing log's
   *   genesis
   * @returns {Promise<void>}
   */
  async ensureSpaceEpochs({
    userKey,
    storeFor
  }: {
    userKey: UserKey
    storeFor: (collectionId: string) => EncryptionDescriptorStore
  }): Promise<void> {
    await ensureWalletSpaceEpochs({
      storeFor,
      spaceId: this.spaceId,
      userKey
    })
  }

  /**
   * Promotes (or confirms) the Space's controller -- the last step of the
   * promotion-by-ordering sequence: the Space was created under the first
   * client's did:key, the did:webvh log has been published into the
   * world-readable `id` collection, and this PUT names the did:webvh as the
   * controller, authorized by the stored controller (whichever it currently
   * is -- the call is idempotent). Supplies the full description (name and
   * controller) so nothing is merged from an unreadable current one, and
   * updates the in-memory controller so later collection upserts name the
   * promoted controller rather than demoting the Space.
   *
   * @param options {object}
   * @param options.controller {string}   the account's did:webvh DID
   * @param [options.current] {SpaceMetadata | null}   the caller's own
   *   just-made read of this same Space, with no Space Metadata object write
   *   in between; supplying it skips `configure`'s pre-merge re-describe.
   *   Omit it (rather than passing `null`) when no such read is in hand, so
   *   `configure` makes the read itself under this store's signing client.
   * @returns {Promise<void>}
   */
  async promoteSpaceController({
    controller,
    current
  }: {
    controller: string
    current?: SpaceMetadata | null
  }): Promise<void> {
    await this.#space().configure({
      name: 'Wallet Space',
      controller,
      ...(current !== undefined ? { current } : {})
    })
    this.controller = controllerDid(controller)
  }

  /**
   * Rebinds this store's signing client and controller -- the in-session
   * swap right after controller promotion: from here on every request is
   * signed with the promoted controller's keyId. Every handle this store
   * hands out goes through `this.was`, so replacing it is sufficient.
   *
   * @param options {object}
   * @param options.zcapClient {ZcapClient}   signs with the promoted keyId
   * @param options.controller {string}   the account's did:webvh DID
   * @returns {void}
   */
  rebindController({
    zcapClient,
    controller
  }: {
    zcapClient: ZcapClient
    controller: string
  }): void {
    this.was = this.#clientFor({ zcapClient })
    this.controller = controllerDid(controller)
  }

  /**
   * A client over this store's server for one signer: the discovered
   * service description threaded in, and no decrypt path (replication moves
   * opaque envelopes verbatim; read-time decrypt is a StorageManager
   * concern), so the keystore is a no-op.
   *
   * @param options {object}
   * @param options.zcapClient {ZcapClient}
   * @returns {WasClient}
   */
  #clientFor({ zcapClient }: { zcapClient: ZcapClient }): WasClient {
    return new WasClient({
      serverUrl: this.storageServerUrl,
      zcapClient,
      serviceDescription: this.#discovered,
      encryption: createEdvEncryption({ resolveKeys: async () => null })
    })
  }

  /**
   * Returns a `Resource` handle for the single `keys.json` resource in this
   * Space's `key-map` collection, invoked with the root capability.
   *
   * Read and written through the plaintext codec: `keys.json` is plain JSON,
   * and without the override the client describes the collection first, so a
   * 404 -- from a Space or collection that does not exist yet, which is what
   * the KMS-authentication stage's probe meets on a fresh signup -- would
   * make the client refuse to guess instead of reading as an absence.
   *
   * @returns {Resource}
   */
  #keyMapResource(): Resource {
    return this.#space()
      .collection(KEY_MAP_COLLECTION.id, { encryption: 'plaintext' })
      .resource(DID_KEYS_RESOURCE)
  }

  /**
   * Returns the store over the enrolled-client display labels
   * (`key-map/client-labels.json`) for the wallet-core label helpers, bound to
   * this store's current signing client.
   *
   * The labels read and write ride this store's bound invocation capability
   * when one is held, so a session whose only authority over the Space is a
   * delegated subtree zcap (the generation delegation a transient session
   * invokes under) can list, set, and drop labels. An enrolled client holds
   * none and root-invokes, as before. The capability is read here rather than
   * captured, so a mid-session renewal reaches the next store built.
   *
   * @returns {ClientLabelsStore}
   */
  clientLabelsStore(): ClientLabelsStore {
    return wasClientLabelsStore({
      was: this.was,
      spaceId: this.spaceId,
      ...(this.#capability ? { capability: this.#capability } : {})
    })
  }

  /**
   * Returns the `id`-collection store the did:webvh ceremonies (provisioning,
   * enrollment, revocation, recovery) read and write through, bound to this
   * store's current signing client -- rebound along with it after controller
   * promotion.
   *
   * @returns {WebvhIdStore}
   */
  webvhIdStore(): WebvhIdStore {
    return wasWebvhIdStore({
      was: this.was,
      spaceId: this.spaceId,
      pinStore: this.#pinStore
    })
  }

  /**
   * Reads the parsed key-id map (`key-map/keys.json`), or `undefined` when it
   * is missing (the DID provisioning existence probe). The key map is the
   * `key-map` collection's single resource, so there is no resource-id
   * parameter.
   *
   * @returns {Promise<unknown>}
   */
  async getKeyMap(): Promise<unknown> {
    const result = await this.#keyMapResource().get()
    return result === null ? undefined : result
  }

  /**
   * The absolute, world-readable URL the published DID document resolves to
   * (`https://<host>/space/<spaceId>/id/did.json`).
   *
   * @returns {string}
   */
  didDocumentUrl(): string {
    return toUrl({
      serverUrl: this.storageServerUrl,
      path: resourcePath(this.spaceId, ID_COLLECTION.id, DID_DOCUMENT_RESOURCE)
    })
  }

  /**
   * Provisions an arbitrary (RP-requested) collection in this user's Space:
   * always plaintext (no encryption descriptor) -- usable by a relying party
   * through its delegated zcap. By default it is not world-readable; with
   * `isPublic`, a collection-level `PublicCanRead` policy is set at
   * provisioning time, so anyone on the web can read it without
   * authorization (writes stay capability-only). Policy endpoints are
   * capability-only on the server, so only the wallet -- holding the space
   * root -- can set it.
   *
   * This is was-client's ensure with `encryption: 'plaintext'`: a guarded
   * create (`If-None-Match: *`) that leaves a standing collection untouched.
   * A standing collection may be log-governed (an App Connect provisioning
   * made it so), and its served `encryption` member is the server's own
   * projection, which a Description PUT may not carry
   * (`encryption-history-log-governed`); the ensure never re-sends it.
   *
   * `generator` and `generatorOrigin` are the collection's app attribution
   * (the DID of the application it is provisioned for, and the Web origin
   * that DID was bound to), stamped on the create.
   *
   * @param options {object}
   * @param options.id {string}   the WAS collection id (validated by the caller)
   * @param [options.name] {string}   display name; defaults to the id
   * @param [options.isPublic] {boolean}   grant collection-level world read
   * @param [options.generator] {IDID}   the DID of the application this
   *   collection is provisioned for
   * @param [options.generatorOrigin] {string}   the Web origin that DID was
   *   bound to at provisioning time
   * @returns {Promise<string>}   the collection's base URL
   */
  async ensureCollection({
    id,
    name,
    isPublic,
    generator,
    generatorOrigin
  }: {
    id: string
    name?: string
    isPublic?: boolean
    generator?: IDID
    generatorOrigin?: string
  }): Promise<string> {
    try {
      await this.#ensureCollectionInSpace({
        id,
        name,
        encryption: 'plaintext',
        isPublic,
        generator,
        generatorOrigin
      })
    } catch (err) {
      log.error('Error provisioning collection', { id, err })
      throw new Error(
        `Error provisioning collection "${id}" in space "${this.spaceId}".`,
        { cause: err }
      )
    }
    return this.collectionTargetUrl(id)
  }

  /**
   * Ensures an App Connect app-provisioned collection exists as a
   * log-governed encrypted collection: was-client's ensure with
   * `encryption: 'governed'`, a bare guarded create (`{ name }` under
   * `If-None-Match: *`), since the Description's `encryption` member is the
   * server's to derive from the collection's governing log, and the
   * declaration itself is that log's genesis (`ensureIndexedFirstEpoch`
   * through the collection's descriptor store, the caller's next step). A
   * collection already standing is left untouched, a lost create race reads
   * as the standing collection, and a collection already carrying a
   * client-written `encryption` member refuses rather than trip the server's
   * `encryption-immutable` refusal on the genesis.
   *
   * `generator` and `generatorOrigin` are the collection's app attribution,
   * stamped on the guarded create.
   *
   * @param options {object}
   * @param options.id {string}   the WAS collection id
   * @param [options.name] {string}   display name; defaults to the id
   * @param [options.generator] {IDID}   the DID of the application this
   *   collection is provisioned for
   * @param [options.generatorOrigin] {string}   the Web origin that DID was
   *   bound to at provisioning time
   * @returns {Promise<void>}
   */
  async ensureGovernedCollection({
    id,
    name,
    generator,
    generatorOrigin
  }: {
    id: string
    name?: string
    generator?: IDID
    generatorOrigin?: string
  }): Promise<void> {
    await this.#ensureCollectionInSpace({
      id,
      name,
      encryption: 'governed',
      generator,
      generatorOrigin
    })
  }

  /**
   * The one was-client ensure both provisioning paths ride. The Space half
   * is skipped by supplying the description of the Space this session
   * already runs in, since the bound invocation capability (a transient
   * session's generation delegation) may be scoped below the bare Space URL.
   * The attribution pair passes through as supplied: was-client stamps it on
   * the create only, leaves a standing collection's attribution alone, and
   * drops a lone `generatorOrigin` itself.
   *
   * @param options {object}
   * @param options.id {string}
   * @param [options.name] {string}   display name; defaults to the id
   * @param options.encryption {'plaintext' | 'governed'}
   * @param [options.isPublic] {boolean}
   * @param [options.generator] {IDID}
   * @param [options.generatorOrigin] {string}
   * @returns {Promise<void>}
   */
  async #ensureCollectionInSpace({
    id,
    name,
    encryption,
    isPublic,
    generator,
    generatorOrigin
  }: {
    id: string
    name?: string
    encryption: 'plaintext' | 'governed'
    isPublic?: boolean
    generator?: IDID
    generatorOrigin?: string
  }): Promise<void> {
    await ensureSpaceAndCollection({
      was: this.was,
      spaceId: this.spaceId,
      controllerDid: this.controller,
      collectionId: id,
      collectionName: name ?? id,
      encryption,
      isPublic,
      generator,
      generatorOrigin,
      spaceDescription: {
        id: this.spaceId,
        type: ['Space'],
        controller: this.controller
      },
      capability: this.#capability
    })
  }

  /**
   * Deletes an entire collection (and all resources within it) from this
   * user's Space. Idempotent.
   *
   * @param options {object}
   * @param options.id {string}   the WAS collection id
   * @returns {Promise<void>}
   */
  async deleteCollection({ id }: { id: string }): Promise<void> {
    try {
      await this.#space().collection(id).delete()
    } catch (err) {
      log.error('Error deleting collection', { id, err })
      throw new Error(
        `Error deleting collection "${id}" in space "${this.spaceId}".`,
        { cause: err }
      )
    }
  }

  /**
   * The canonical (trailing-slash) URL of one Collection in this user's
   * Space, keyed by WAS collection id: the target a grant on it names, and a
   * stable identifier for history entries.
   *
   * @param collectionId {string}
   * @returns {string}
   */
  collectionTargetUrl(collectionId: string): string {
    return toUrl({
      serverUrl: this.storageServerUrl,
      path: collectionPath(this.spaceId, collectionId)
    })
  }

  static async initClient({
    storageServerUrl,
    serviceDescription,
    user,
    session: { profile, persistence }
  }: {
    storageServerUrl: string
    // The description this session discovered, threaded in rather than
    // re-probed here: `@/lib/wasService` is the app's one discoverer.
    // Absent when the server was unreachable at login.
    serviceDescription?: ServiceDescription
    user: User
    // The profile the store signs as, and the session's persistence
    // strategy, for the chain-head pin store every account-log read in this
    // store is checked against.
    session: SessionCore
  }) {
    // The Space id is an independent identifier carried in the account
    // pointer (minted at provisioning); the legacy derivation from the
    // client did:key remains only as a fallback for sessions that predate
    // the pointer. The controller follows the pointer too: once the Space
    // has been promoted to the did:webvh, every upsert must name it -- a
    // re-provisioning that passed the client did:key would demote the Space.
    const clientDid = profile.keyAgent?.id || user.id
    const pointerDid = profile.accountPointer?.did
    const controller = isWebvhDid(pointerDid) ? pointerDid : clientDid
    const spaceId = profile.accountPointer?.spaceId ?? deriveSpaceId(clientDid)
    const remoteStore = new WASRemoteStore({
      storageServerUrl,
      serviceDescription,
      zcapClient: profile.zcapClient,
      spaceId,
      controller,
      // A session holding only a delegated Space-subtree zcap (the transient
      // session's generation delegation) rides it on every request.
      capability: profile.invocationCapability,
      pinStore: persistence.logPins
    })

    return { remoteStore }
  }

  async listCollectionResources({
    collectionUrl
  }: {
    collectionUrl: string
  }): Promise<Array<StorageResource>> {
    let listing
    let collectionIsPublic: boolean
    try {
      const collection = this.#collectionFromUrl(collectionUrl)
      // Two independent round trips over the same collection handle.
      ;[listing, collectionIsPublic] = await Promise.all([
        collection.list(),
        collection.isPublic()
      ])
    } catch (err) {
      log.error('Error listing collection resources', { err })
      throw new Error('Failed to list remote storage collection resources.', {
        cause: err
      })
    }

    const items = (listing?.items ?? []) as Array<StorageResource>
    if (collectionIsPublic) {
      return items.map(item => ({ ...item, isPublic: true }))
    }
    return items
  }

  async deleteCollectionResource({
    relativeUrl
  }: {
    relativeUrl: string
  }): Promise<void> {
    await this.#resourceFromUrl(relativeUrl).delete()
  }

  async fetchCollectionResource(
    resource: StorageResource
  ): Promise<FetchedCollectionResource> {
    const result = await this.#resourceFromUrl(resource.url).get()
    if (result === null) {
      throw new Error('Failed to fetch storage resource (not found).')
    }

    // get() returns a parsed object/array for JSON content-types, and a Blob
    // (carrying the server's content-type on `.type`) for everything else.
    if (!(result instanceof Blob)) {
      return { kind: 'json', data: result }
    }

    const contentType =
      result.type?.split(';')[0]?.trim() || 'application/octet-stream'

    if (isTextLikeContentType(contentType)) {
      return { kind: 'text', text: await result.text() }
    }

    // No usable content-type: sniff the body for JSON, then fall back to text
    // or binary.
    if (contentType === 'application/octet-stream') {
      const text = await result.text()
      try {
        const parsed = JSON.parse(text) as unknown
        if (parsed !== null && typeof parsed === 'object') {
          return { kind: 'json', data: parsed }
        }
      } catch {
        /* not JSON text */
      }
    }

    return { kind: 'binary', blob: result, contentType }
  }

  async listCollections(): Promise<Array<StorageCollection>> {
    const items = await this.#collectionSummaries()
    // The listing's `CollectionSummary` surfaces the `PublicCanRead` status
    // inline (`public`, present on every item when the server computes it), so
    // no per-collection policy probe is needed. A server that predates the
    // field omits it entirely; only then fall back to probing, fanned out
    // under the same Promise.all as the description reads so the probes
    // overlap instead of waiting one-by-one.
    return await Promise.all(
      items.map(async item => {
        const handle = this.#collectionFromUrl(item.url)
        const [isPublic, description] = await Promise.all([
          item.public !== undefined ? item.public : handle.isPublic(),
          handle.describe()
        ])
        return {
          ...item,
          isPublic,
          isEncrypted: Boolean(description?.encryption),
          generator: description?.generator,
          generatorOrigin: description?.generatorOrigin
        }
      })
    )
  }

  /**
   * Lean listing for grant resolution: the collection ids and their public
   * state only. One listing GET on a current server (the summary's inline
   * `public` flag answers the question); only a legacy server that omits the
   * flag pays a per-collection policy probe. No `describe()` reads at all --
   * the full {@link listCollections} pays one signed round trip per
   * collection for an `isEncrypted` flag grant resolution never consults.
   *
   * @returns {Promise<Array<{ id: string, isPublic: boolean }>>}
   */
  async listCollectionPublicStates(): Promise<
    Array<{ id: string; isPublic: boolean }>
  > {
    const items = await this.#collectionSummaries()
    return await Promise.all(
      items.map(async item => ({
        id: item.id,
        isPublic:
          item.public !== undefined
            ? item.public
            : await this.#collectionFromUrl(item.url).isPublic()
      }))
    )
  }

  /**
   * The raw `CollectionSummary` items of this Space's collection listing --
   * the shared fetch behind {@link listCollections} and
   * {@link listCollectionPublicStates}.
   *
   * @returns {Promise<Array<StorageCollection>>}
   */
  async #collectionSummaries(): Promise<Array<StorageCollection>> {
    let listing
    try {
      listing = await this.#space().collections()
    } catch (err) {
      log.error('Error listing collections', { err })
      throw new Error('Failed to list remote storage collections.', {
        cause: err
      })
    }
    return (listing?.items ?? []) as Array<StorageCollection>
  }

  /**
   * The absolute, world-readable URL of a credential's shared copy in the
   * `public-credentials` collection. A plain GET resolves it once a public
   * link has been created (locally) and replicated to this server.
   *
   * @param cid {string}
   * @returns {string}
   */
  publicCredentialUrl(cid: string): string {
    return buildPublicCredentialUrl({
      serverUrl: this.storageServerUrl,
      spaceId: this.spaceId,
      cid
    })
  }

  /**
   * Reads the live JSON documents of one of the wallet's standard synced
   * collections through was-client's `Collection.documents()`, the snapshot
   * walk over the `changes` feed background replication pulls, under the
   * bound invocation capability. One request per page rather than one per
   * resource, so a replica-less session lists a collection in a handful of
   * round trips. Bodies ship verbatim (the EDV envelope or a plaintext
   * document) and bypass the fail-closed codec; feed order is preserved, and
   * callers derive content ordering themselves. A missing collection (or one
   * this session cannot see; the server answers 404 for both) lists as empty.
   *
   * @param options {object}
   * @param options.logicalKey {string}   e.g. 'privateCredentials' | 'walletActivity'.
   * @returns {Promise<Array<{ id: string; data: Json }>>}
   */
  async listSyncedDocuments({
    logicalKey
  }: {
    logicalKey: string
  }): Promise<Array<{ id: string; data: Json }>> {
    const collectionId = this.#collectionId(logicalKey)
    let documents
    try {
      documents = await this.#space()
        .collection(collectionId)
        .documents({
          limit: WAS_SYNC_BATCH_SIZE ?? SYNCED_LISTING_PAGE_SIZE
        })
    } catch (err) {
      log.error('Error listing synced documents for collection', {
        collectionId,
        err
      })
      throw new Error(
        `Failed to list documents in collection "${collectionId}".`,
        { cause: err }
      )
    }
    return (documents ?? []).map(({ id, data }) => ({ id, data: data as Json }))
  }

  /**
   * Reads one resource of a standard synced collection as its raw stored body
   * (the EDV envelope or a plaintext document), bypassing the fail-closed
   * encryption codec via the raw `was.request()` escape hatch -- the same
   * verbatim-body contract the sync port uses. Returns `undefined` when the
   * resource is missing (WAS conflates 404 for missing/unauthorized).
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.resourceId {string}
   * @returns {Promise<Json | undefined>}
   */
  async getSyncedResource({
    logicalKey,
    resourceId
  }: {
    logicalKey: string
    resourceId: string
  }): Promise<Json | undefined> {
    const response = await this.#requestSyncedResource({
      logicalKey,
      resourceId
    })
    return response ? (response.data as Json) : undefined
  }

  /**
   * The GET both synced-resource reads share: the raw `was.request()` escape
   * hatch aimed at one resource of a standard synced collection, resolving to
   * the response, or to `undefined` on the 404 WAS conflates for
   * missing/unauthorized. The two public reads differ only in how much of the
   * response they surface.
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.resourceId {string}
   * @returns {Promise<Awaited<ReturnType<WasClient['request']>> | undefined>}
   */
  async #requestSyncedResource({
    logicalKey,
    resourceId
  }: {
    logicalKey: string
    resourceId: string
  }): Promise<Awaited<ReturnType<WasClient['request']>> | undefined> {
    const collectionId = this.#collectionId(logicalKey)
    try {
      return await this.was.request({
        path: resourcePath(this.spaceId, collectionId, resourceId),
        method: 'GET',
        capability: this.#capability
      })
    } catch (err) {
      if (errorStatus(err) === 404) {
        return undefined
      }
      throw err
    }
  }

  /**
   * Reads one resource of a standard synced collection like
   * {@link getSyncedResource}, but also surfaces the served strong `ETag`
   * validator (the server's quoted `"<version>"`), so a compare-and-swap
   * update or delete can carry `If-Match` naming exactly the read it was
   * based on. Returns `undefined` when the resource is missing.
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.resourceId {string}
   * @returns {Promise<{ data: Json; etag?: string } | undefined>}
   */
  async getSyncedResourceWithEtag({
    logicalKey,
    resourceId
  }: {
    logicalKey: string
    resourceId: string
  }): Promise<{ data: Json; etag?: string } | undefined> {
    const response = await this.#requestSyncedResource({
      logicalKey,
      resourceId
    })
    if (!response) {
      return undefined
    }
    const etag = readEtag(response)
    const data = response.data as Json
    return etag !== undefined ? { data, etag } : { data }
  }

  /**
   * Writes one resource into a standard synced collection: the caller-supplied
   * raw body under the caller-supplied id, via the raw `was.request()` escape
   * hatch so the body is stored verbatim (no re-encryption). This reproduces
   * exactly what background replication would have pushed, so the main app's
   * replication pulls it cleanly.
   *
   * Two conditional-write shapes:
   *
   * - Default (no `ifMatch`): created-if-absent (`If-None-Match: *`). A `412`
   *   means the identical row already exists (the content-derived id
   *   collided) and is reported as not-created rather than thrown.
   * - With `ifMatch` (the quoted ETag of the read the new body was built on):
   *   update-in-place, the same `If-Match` convention the replication push
   *   path sends. A `412` here is a lost race and PROPAGATES, so the caller's
   *   compare-and-swap loop can re-read and re-apply.
   *
   * When `epoch` is given, it is stamped as the `Key-Epoch` header exactly
   * as background replication does (the sync port's `putContent`), so a
   * remote-direct write records the key epoch its envelope was encrypted under.
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.resourceId {string}   the content-derived envelope-hash id
   *   (or a mutable collection's stable row id)
   * @param options.body {Json}   the raw EDV envelope (or plaintext document)
   * @param [options.epoch] {string}   the opaque key-epoch id the envelope was
   *   encrypted under; absent for a plaintext or pre-epoch write
   * @param [options.ifMatch] {string}   the quoted ETag an update-in-place
   *   must match; create-if-absent when omitted
   * @returns {Promise<{ created: boolean }>}
   */
  async putSyncedResource({
    logicalKey,
    resourceId,
    body,
    epoch,
    ifMatch
  }: {
    logicalKey: string
    resourceId: string
    body: Json
    epoch?: string
    ifMatch?: string
  }): Promise<{ created: boolean }> {
    const collectionId = this.#collectionId(logicalKey)
    const headers: Record<string, string> =
      ifMatch !== undefined ? { 'if-match': ifMatch } : { 'if-none-match': '*' }
    if (epoch !== undefined) {
      headers[KEY_EPOCH_HEADER] = epoch
    }
    try {
      await this.was.request({
        path: resourcePath(this.spaceId, collectionId, resourceId),
        method: 'PUT',
        json: body as object,
        headers,
        capability: this.#capability
      })
      return { created: true }
    } catch (err) {
      if (ifMatch === undefined && errorStatus(err) === 412) {
        return { created: false }
      }
      throw err
    }
  }

  /**
   * Deletes one resource of a standard synced collection, via the raw
   * `was.request()` escape hatch. A missing resource (`404`) is treated as
   * already-deleted (idempotent). With `ifMatch` (the quoted ETag of the read
   * that decided the delete) the removal is conditional, and a `412` -- a
   * concurrent rewrite -- propagates for the caller's compare-and-swap loop
   * to re-read and retry. Used by the remote-direct backend to remove a
   * credential, a revoked public link, or a contact head.
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.resourceId {string}
   * @param [options.ifMatch] {string}   the quoted ETag the stored resource
   *   must still carry; unconditional when omitted
   * @returns {Promise<void>}
   */
  async deleteSyncedResource({
    logicalKey,
    resourceId,
    ifMatch
  }: {
    logicalKey: string
    resourceId: string
    ifMatch?: string
  }): Promise<void> {
    const collectionId = this.#collectionId(logicalKey)
    try {
      await this.was.request({
        path: resourcePath(this.spaceId, collectionId, resourceId),
        method: 'DELETE',
        ...(ifMatch !== undefined ? { headers: { 'if-match': ifMatch } } : {}),
        capability: this.#capability
      })
    } catch (err) {
      if (errorStatus(err) === 404) {
        return
      }
      throw err
    }
  }

  /**
   * Deletes this store's whole remote Space.
   *
   * By default the request root-invokes through this store's bound
   * capability, which is what an enrolled client holds. The server's
   * exact-delete container rule admits a delegated capability only when the
   * invoked capability targets exactly the Space's canonical container URL
   * with `allowedAction` exactly `['DELETE']`. A transient session rides a
   * generation delegation carrying a wider action set, so it passes its own
   * single-verb DELETE capability and the signer that capability names as
   * its delegatee, and both travel together on this one request.
   *
   * The 404 is REPORTED rather than decided: the server masks an
   * authorization refusal as 404, so a caller that needs "already gone" must
   * establish it by its own prior discovery.
   *
   * @param [options] {object}
   * @param [options.capability] {IZcap}   an explicit DELETE capability on
   *   this Space's own URL
   * @param [options.zcapClient] {ZcapClient}   the client invoking it (the
   *   capability's delegatee), when it is not this store's own
   * @returns {Promise<{ outcome: 'deleted' | 'not-found' }>}
   */
  async wipeStorage({
    capability,
    zcapClient
  }: {
    capability?: IZcap
    zcapClient?: ZcapClient
  } = {}): Promise<{ outcome: 'deleted' | 'not-found' }> {
    try {
      const was = zcapClient ? this.#clientFor({ zcapClient }) : this.was
      const space = capability
        ? was.space(this.spaceId, { capability })
        : this.#space()
      const result = await space.deleteWithOutcome()
      log.info('Remote space deleted', { outcome: result.outcome })
      return result
    } catch (err) {
      log.error('Error deleting space', { err })
      throw new Error('Failed to delete remote space.', { cause: err })
    }
  }

  async getSpaceQuotas(): Promise<SpaceQuotaReport | null> {
    try {
      const response = await this.was.request({
        path: `/space/${this.spaceId}/quotas?include=collections`,
        method: 'GET',
        capability: this.#capability
      })

      return response.data as SpaceQuotaReport
    } catch (err) {
      const status = errorStatus(err)

      if (status === 404 || status === 501) {
        return null
      }

      log.error('Error fetching space quotas', { err })
      throw new Error('Failed to fetch storage quotas.', { cause: err })
    }
  }

  async exportSpace(): Promise<ReadableStream<Uint8Array>> {
    let response
    try {
      // Use the raw request escape hatch rather than `space.export()`: the
      // handle helper buffers the whole tar archive into memory, whereas the
      // raw `HttpResponse` exposes a `body` stream we can pipe straight to disk.
      response = await this.was.request({
        path: `/space/${this.spaceId}/export`,
        method: 'POST',
        headers: { accept: 'application/x-tar' },
        capability: this.#capability
      })
    } catch (err) {
      log.error('Error exporting space', { err })
      throw new Error('Failed to export remote space.', { cause: err })
    }

    if (!response.body) {
      throw new Error('Unexpected export response: no streamable body.')
    }

    return response.body
  }

  async importSpace({
    tarFile
  }: {
    tarFile: File
  }): Promise<ImportSpaceSummary> {
    const bytes = new Uint8Array(await tarFile.arrayBuffer())
    try {
      return await this.#space().import(bytes)
    } catch (err) {
      log.error('Error importing space', { err })
      throw new Error('Failed to import remote space.', { cause: err })
    }
  }
}

/**
 * The keyring v2 unlock Space (`src/session/keyring.ts`) is a second, minimal
 * WAS Space controlled by the passphrase-derived unlock identity -- completely
 * separate from the wallet data Space, so these are standalone functions rather
 * than `WASRemoteStore` methods (the store is bound to the data identity). Each
 * builds its own `WasClient` over the unlock agent's `zcapClient`, whose
 * invocation signer is the unlock root key (root invocation, no capability
 * attached -- the same invocation shape the data Space uses). The one resource is a
 * plaintext JSON document (its keyring payload is
 * already ciphertext), so no encryption provider is wired in -- and the
 * read/write handles pass the explicit `{ encryption: 'plaintext' }` override.
 * The override is load-bearing: without it, the client decides plaintext vs
 * encrypted by reading the collection description, and when the unlock Space
 * does not exist yet (every keyring lookup for a fresh passphrase) that read
 * 404s and the client refuses to guess, throwing an EncryptionError instead of
 * surfacing the miss as a 404-shaped `null`.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   built on the unlock agent's signer
 * @returns {Promise<WasClient>}
 */
async function unlockSpaceClient({
  storageServerUrl,
  zcapClient
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
}): Promise<WasClient> {
  return new WasClient({
    serverUrl: storageServerUrl,
    zcapClient,
    serviceDescription: await wasServiceDescription()
  })
}

/**
 * Reads the unlock-methods registry record from the data Space, or returns
 * `null` when it does not exist yet. A network / unreachable error propagates.
 * The served ETag rides beside the record so a later conditional PUT can name
 * the read it was based on -- `unlockSpaceClient` builds a fresh client per
 * call, so the validator must travel as a value, never as client state.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   the data identity's root client
 * @param options.spaceId {string}   the data Space id
 * @param [options.capability] {IZcap}   an invocation capability every request
 *   rides; the root capability is invoked otherwise
 * @returns {Promise<{ record: unknown, etag?: string } | null>}
 */
export async function getUnlockMethodsRecord({
  storageServerUrl,
  zcapClient,
  spaceId,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  capability?: IZcap
}): Promise<{ record: unknown; etag?: string } | null> {
  const was = await unlockSpaceClient({ storageServerUrl, zcapClient })
  const found = await was
    .space(spaceId, { capability })
    .collection(UNLOCK_METHODS_COLLECTION.id, { encryption: 'plaintext' })
    .resource(UNLOCK_METHODS_RESOURCE)
    .getWithEtag()
  if (!found) {
    return null
  }
  return { record: found.data, etag: found.etag }
}

/**
 * Writes (upserts) the unlock-methods registry record into the data Space as a
 * JSON document. `ifMatch` (the ETag from the read the record was built on)
 * makes the write an update-if-unchanged; `ifNoneMatch` a create-if-absent. A
 * failed precondition throws was-client's `PreconditionFailedError` (412).
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   the data identity's root client
 * @param options.spaceId {string}   the data Space id
 * @param options.record {object}   the wrapped registry record
 * @param [options.capability] {IZcap}   an invocation capability every request
 *   rides; the root capability is invoked otherwise
 * @param [options.ifMatch] {string}   write only if the stored ETag matches
 * @param [options.ifNoneMatch] {boolean}   write only if no record exists yet
 * @returns {Promise<{ etag?: string }>}   the stored record's new ETag
 */
export async function putUnlockMethodsRecord({
  storageServerUrl,
  zcapClient,
  spaceId,
  record,
  capability,
  ifMatch,
  ifNoneMatch
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  record: object
  capability?: IZcap
  ifMatch?: string
  ifNoneMatch?: boolean
}): Promise<{ etag?: string }> {
  const was = await unlockSpaceClient({ storageServerUrl, zcapClient })
  const body = new TextEncoder().encode(JSON.stringify(record))
  return await was
    .space(spaceId, { capability })
    .collection(UNLOCK_METHODS_COLLECTION.id, { encryption: 'plaintext' })
    .resource(UNLOCK_METHODS_RESOURCE)
    .put(body, {
      contentType: 'application/json',
      ...(ifMatch !== undefined ? { ifMatch } : {}),
      ...(ifNoneMatch ? { ifNoneMatch } : {})
    })
}
