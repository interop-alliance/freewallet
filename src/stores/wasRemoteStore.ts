/**
 * WASRemoteStore: the remote WAS (Wallet Attached Storage) backend, attached
 * when VITE_WAS_SERVER_URL is set. Since the local BrowserStore became the
 * always-active replica, this class no longer serves credential / history /
 * public-link reads and writes for the main app -- those replicate in the
 * background through the sync controller. What remains here is the Space
 * lifecycle (create / exists / wipe), the storage-browser read-through over
 * arbitrary Collections and Resources, export / import, and quotas.
 *
 * One exception is the CHAPI popup: its local IndexedDB is a third-party
 * partitioned bucket no sync controller drives, so a remote-direct popup
 * session (see `StorageManager`) reads and writes the standard synced
 * collections here directly, through `listSyncedResources` /
 * `getSyncedResource` / `putSyncedResource` -- reproducing verbatim what
 * background replication would have pushed.
 *
 * All WAS operations go through `@interop/was-client`'s `WasClient` and its
 * lazy navigational handles (`space` / `collection` / `resource`) rather than
 * hand-built ezcap requests. The `WasClient` wraps the ezcap `ZcapClient` that
 * carries the user's invocation signer.
 */
import type { ZcapClient } from '@interop/ezcap'
import {
  WasClient,
  type Collection,
  type CollectionEncryption,
  type Resource,
  type Space
} from '@interop/was-client'
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
import type { ControllerProfile, User } from '@/types/auth'
import {
  DID_DOCUMENT_RESOURCE,
  DID_KEYS_RESOURCE,
  ID_COLLECTION,
  KEY_MAP_COLLECTION,
  UNLOCK_METHODS_COLLECTION,
  UNLOCK_METHODS_RESOURCE,
  WALLET_STANDARD_COLLECTIONS
} from '@/app.config'
import type { Json } from '@/lib/sync/types.js'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import type { SpaceQuotaReport } from '@/types/storageQuota'
import {
  type FetchedCollectionResource,
  isTextLikeContentType
} from '@/lib/storageResource'
import type { ImportSpaceSummary } from '@/stores/storageManager'
import {
  deriveSpaceId,
  errorStatus,
  KEY_EPOCH_HEADER
} from '@interop/was-client/sync'
import { provisionWalletSpace } from '@interop/wallet-core/space'
import {
  ensureWalletSpaceEpochs,
  type UserKey
} from '@interop/wallet-core/keys'

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

export class WASRemoteStore {
  public storageServerUrl: string
  public was: WasClient
  public spaceId: string
  public controller: string

  public spaceUrl: string
  public collections?: ICollectionsSet

  constructor({
    storageServerUrl,
    zcapClient,
    spaceId,
    controller
  }: {
    storageServerUrl: string
    zcapClient: ZcapClient
    spaceId: string
    controller: string
  }) {
    this.storageServerUrl = storageServerUrl
    this.was = new WasClient({
      serverUrl: storageServerUrl,
      zcapClient,
      // No decrypt path lives here anymore (replication moves opaque envelopes
      // verbatim; read-time decrypt is a StorageManager concern), so the
      // keystore is a no-op.
      encryption: createEdvEncryption({ resolveKeys: async () => null })
    })
    this.spaceId = spaceId
    this.controller = controller
    this.spaceUrl = new URL(`/space/${spaceId}`, storageServerUrl).toString()
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
    return this.was.space(spaceId).collection(collectionId)
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
    return this.was
      .space(spaceId)
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
    const description = await this.was
      .space(this.spaceId)
      .collection(collectionId)
      .describe()
    return description?.encryption ?? undefined
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
    return this.was.space(this.spaceId).collection(collectionId)
  }

  /**
   * The `Space` handle (root capability), needed by `removeRecipient` to revoke
   * a reader's pull-axis zcap(s) via `space.revoke()`.
   *
   * @returns {Space}
   */
  spaceHandle(): Space {
    return this.was.space(this.spaceId)
  }

  async userExists() {
    // describe() returns null on a 404 (not-found or unauthorized).
    return (await this.was.space(this.spaceId).describe()) !== null
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
      collections.set(key, this.#collectionBaseUrl(id))
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
   * @returns {Promise<void>}
   */
  async ensureSpaceEpochs({ userKey }: { userKey: UserKey }): Promise<void> {
    await ensureWalletSpaceEpochs({
      was: this.was,
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
   * @returns {Promise<void>}
   */
  async promoteSpaceController({
    controller
  }: {
    controller: string
  }): Promise<void> {
    await this.was
      .space(this.spaceId)
      .configure({ name: 'Wallet Space', controller })
    this.controller = controller
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
    this.was = new WasClient({
      serverUrl: this.storageServerUrl,
      zcapClient,
      // Mirrors the constructor: no decrypt path lives here.
      encryption: createEdvEncryption({ resolveKeys: async () => null })
    })
    this.controller = controller
  }

  /**
   * Returns a `Resource` handle for the single `keys.json` resource in this
   * Space's `key-map` collection, invoked with the root capability.
   *
   * @returns {Resource}
   */
  #keyMapResource(): Resource {
    return this.was
      .space(this.spaceId)
      .collection(KEY_MAP_COLLECTION.id)
      .resource(DID_KEYS_RESOURCE)
  }

  /**
   * Returns the store over the enrolled-client display labels
   * (`key-map/client-labels.json`) for the wallet-core label helpers, bound to
   * this store's current signing client.
   *
   * @returns {ClientLabelsStore}
   */
  clientLabelsStore(): ClientLabelsStore {
    return wasClientLabelsStore({ was: this.was, spaceId: this.spaceId })
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
    return wasWebvhIdStore({ was: this.was, spaceId: this.spaceId })
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
    return new URL(
      `/space/${this.spaceId}/${ID_COLLECTION.id}/${DID_DOCUMENT_RESOURCE}`,
      this.storageServerUrl
    ).toString()
  }

  /**
   * Provisions an arbitrary (RP-requested) collection in this user's Space:
   * always plaintext (no encryption descriptor) -- usable by a relying party
   * through its delegated zcap. By default it is not world-readable; with
   * `isPublic`, a collection-level `PublicCanRead` policy is set at
   * provisioning time, so anyone on the web can read it without
   * authorization (writes stay capability-only). Policy endpoints are
   * capability-only on the server, so only the wallet -- holding the space
   * root -- can set it. This is the `ensureUserCollections` pattern minus the
   * encryption descriptor.
   *
   * @param options {object}
   * @param options.id {string}   the WAS collection id (validated by the caller)
   * @param [options.name] {string}   display name; defaults to the id
   * @param [options.isPublic] {boolean}   set a collection-level PublicCanRead
   *   policy after configuring
   * @returns {Promise<string>}   the collection's base URL
   */
  async ensureCollection({
    id,
    name,
    isPublic
  }: {
    id: string
    name?: string
    isPublic?: boolean
  }): Promise<string> {
    try {
      const collection = this.was.space(this.spaceId).collection(id)
      // `force`: this provisioning upsert runs with the root capability, so
      // a 404 from the pre-merge describe means the collection is absent.
      await collection.configure({
        name: name ?? id,
        force: true
      })
      if (isPublic) {
        await collection.setPublic()
      }
    } catch (err) {
      console.error(`Error provisioning collection "${id}":`, err)
      throw new Error(
        `Error provisioning collection "${id}" in space "${this.spaceId}".`,
        { cause: err }
      )
    }
    return this.#collectionBaseUrl(id)
  }

  /**
   * Ensures an App Connect app-provisioned collection exists AND is declared
   * encrypted with the `'edv'` scheme, without ever clobbering an existing
   * `encryption` descriptor (which may already carry a key-epoch roster). Reads the
   * description first: a missing collection or one with no encryption block is
   * configured with the bare `{ scheme: 'edv' }` descriptor (a fresh create or a
   * late in-place declaration); a collection that already carries an encryption
   * block is left untouched so its epochs survive. Returns the current
   * encryption descriptor after ensuring the declaration -- `undefined` when the
   * collection was just declared and has no epochs yet, or the existing descriptor
   * (possibly with epochs) otherwise -- so the caller can decide whether to
   * initialize or extend the recipient roster.
   *
   * @param options {object}
   * @param options.id {string}   the WAS collection id
   * @param [options.name] {string}   display name; defaults to the id
   * @returns {Promise<CollectionEncryption | undefined>}
   */
  async ensureEncryptedCollection({
    id,
    name
  }: {
    id: string
    name?: string
  }): Promise<CollectionEncryption | undefined> {
    const collection = this.was.space(this.spaceId).collection(id)
    let current
    try {
      current = await collection.describe()
    } catch (err) {
      console.error(`Error describing collection "${id}":`, err)
      throw new Error(
        `Error describing collection "${id}" in space "${this.spaceId}".`,
        { cause: err }
      )
    }
    // Declare `'edv'` only when there is no encryption block to lose: a fresh
    // create (current === null) or a plaintext collection getting a late
    // in-place declaration. Never re-send `encryption` when a descriptor already
    // exists -- `configure` merges the passed value forward, so a bare
    // `{ scheme: 'edv' }` would drop an existing epoch roster.
    if (!current || !current.encryption) {
      try {
        await collection.configure({
          name: name ?? current?.name ?? id,
          encryption: { scheme: 'edv' },
          force: true
        })
      } catch (err) {
        console.error(`Error declaring collection "${id}" encrypted:`, err)
        throw new Error(
          `Error declaring collection "${id}" encrypted in space ` +
            `"${this.spaceId}".`,
          { cause: err }
        )
      }
      return undefined
    }
    return current.encryption
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
      await this.was.space(this.spaceId).collection(id).delete()
    } catch (err) {
      console.error(`Error deleting collection "${id}":`, err)
      throw new Error(
        `Error deleting collection "${id}" in space "${this.spaceId}".`,
        { cause: err }
      )
    }
  }

  /**
   * Builds the trailing-slash base URL of a collection within this user's
   * space, suitable for use as a stable identifier (e.g. in history entries).
   *
   * @param collectionId {string}
   * @returns {string}
   */
  #collectionBaseUrl(collectionId: string): string {
    return new URL(
      `/space/${this.spaceId}/${collectionId}/`,
      this.storageServerUrl
    ).toString()
  }

  static async initClient({
    storageServerUrl,
    user,
    profile
  }: {
    storageServerUrl: string
    user: User
    profile: ControllerProfile
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
      zcapClient: profile.zcapClient,
      spaceId,
      controller
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
      console.error('Error listing collection resources:', err)
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
          isEncrypted: Boolean(description?.encryption)
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
      listing = await this.was.space(this.spaceId).collections()
    } catch (err) {
      console.error('Error listing collections:', err)
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
   * Lists the raw resource entries (id + absolute url) of one of the wallet's
   * standard synced collections, addressed straight from its collection id
   * rather than the `collections` map -- which a remote-direct popup session
   * never populates. Metadata only (no bodies), so it never touches the
   * fail-closed encryption codec. Server order is preserved as-is; callers that
   * need content ordering must derive it themselves (best-effort here).
   *
   * @param options {object}
   * @param options.logicalKey {string}   e.g. 'privateCredentials' | 'walletActivity'.
   * @returns {Promise<Array<{ id: string; url: string }>>}
   */
  async listSyncedResources({
    logicalKey
  }: {
    logicalKey: string
  }): Promise<Array<{ id: string; url: string }>> {
    const collectionId = this.#collectionId(logicalKey)
    let listing
    try {
      listing = await this.was
        .space(this.spaceId)
        .collection(collectionId)
        .list()
    } catch (err) {
      console.error(
        `Error listing synced resources for "${collectionId}":`,
        err
      )
      throw new Error(
        `Failed to list resources in collection "${collectionId}".`,
        { cause: err }
      )
    }
    const items = (listing?.items ?? []) as Array<{ id: string; url: string }>
    return items.map(({ id, url }) => ({ id, url }))
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
    const collectionId = this.#collectionId(logicalKey)
    try {
      const response = await this.was.request({
        path: `/space/${this.spaceId}/${collectionId}/${encodeURIComponent(
          resourceId
        )}`,
        method: 'GET'
      })
      return response.data as Json
    } catch (err) {
      if (errorStatus(err) === 404) {
        return undefined
      }
      throw err
    }
  }

  /**
   * Writes one resource into a standard synced collection: the caller-supplied
   * raw body under the caller-supplied id, created-if-absent
   * (`If-None-Match: *`), via the raw `was.request()` escape hatch so the body
   * is stored verbatim (no re-encryption). This reproduces exactly what
   * background replication would have pushed, so the main app's replication
   * pulls it cleanly. A `412` means the identical row already exists (the
   * content-derived id collided) and is reported as not-created rather than
   * thrown.
   *
   * When `epoch` is given, it is stamped as the `Key-Epoch` header exactly
   * as background replication does (the sync port's `putContent`), so a
   * remote-direct write records the key epoch its envelope was encrypted under.
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.resourceId {string}   the content-derived envelope-hash id
   * @param options.body {Json}   the raw EDV envelope (or plaintext document)
   * @param [options.epoch] {string}   the opaque key-epoch id the envelope was
   *   encrypted under; absent for a plaintext or pre-epoch write
   * @returns {Promise<{ created: boolean }>}
   */
  async putSyncedResource({
    logicalKey,
    resourceId,
    body,
    epoch
  }: {
    logicalKey: string
    resourceId: string
    body: Json
    epoch?: string
  }): Promise<{ created: boolean }> {
    const collectionId = this.#collectionId(logicalKey)
    const headers: Record<string, string> = { 'if-none-match': '*' }
    if (epoch !== undefined) {
      headers[KEY_EPOCH_HEADER] = epoch
    }
    try {
      await this.was.request({
        path: `/space/${this.spaceId}/${collectionId}/${encodeURIComponent(
          resourceId
        )}`,
        method: 'PUT',
        json: body as object,
        headers
      })
      return { created: true }
    } catch (err) {
      if (errorStatus(err) === 412) {
        return { created: false }
      }
      throw err
    }
  }

  /**
   * Deletes one resource of a standard synced collection, via the raw
   * `was.request()` escape hatch. A missing resource (`404`) is treated as
   * already-deleted (idempotent). Used by the remote-direct popup backend to
   * remove a credential or a revoked public link.
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.resourceId {string}
   * @returns {Promise<void>}
   */
  async deleteSyncedResource({
    logicalKey,
    resourceId
  }: {
    logicalKey: string
    resourceId: string
  }): Promise<void> {
    const collectionId = this.#collectionId(logicalKey)
    try {
      await this.was.request({
        path: `/space/${this.spaceId}/${collectionId}/${encodeURIComponent(
          resourceId
        )}`,
        method: 'DELETE'
      })
    } catch (err) {
      if (errorStatus(err) === 404) {
        return
      }
      throw err
    }
  }

  async wipeStorage() {
    try {
      await this.was.space(this.spaceId).delete()
    } catch (err) {
      console.error('Error deleting space:', err)
      throw new Error('Failed to delete remote space.', { cause: err })
    }
    console.log('Remote space deleted.')
  }

  async getSpaceQuotas(): Promise<SpaceQuotaReport | null> {
    try {
      const response = await this.was.request({
        path: `/space/${this.spaceId}/quotas?include=collections`,
        method: 'GET'
      })

      return response.data as SpaceQuotaReport
    } catch (err) {
      const status = errorStatus(err)

      if (status === 404 || status === 501) {
        return null
      }

      console.error('Error fetching space quotas:', err)
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
        headers: { accept: 'application/x-tar' }
      })
    } catch (err) {
      console.error('Error exporting space:', err)
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
      return await this.was.space(this.spaceId).import(bytes)
    } catch (err) {
      console.error('Error importing space:', err)
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
 * attached -- the same posture the data Space uses). The one resource is a
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
 * @returns {WasClient}
 */
function unlockSpaceClient({
  storageServerUrl,
  zcapClient
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
}): WasClient {
  return new WasClient({
    serverUrl: storageServerUrl,
    zcapClient
  })
}

/**
 * Ensures the `unlock-methods` collection exists in the user's DATA Space
 * (upsert -- idempotent), so the first registry PUT has somewhere to land. The
 * data Space itself already exists (provisioned at signup), so only the
 * collection is configured. Runs with the root capability, so `force` lets the
 * upsert treat a 404 from the pre-merge describe as genuinely absent. As with
 * the keyring, the collection is plaintext on the server (it stores a
 * JWE-wrapped record, opaque to the server).
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   the data identity's root client
 * @param options.spaceId {string}   the data Space id
 * @returns {Promise<void>}
 */
export async function ensureUnlockMethodsCollection({
  storageServerUrl,
  zcapClient,
  spaceId
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  await was
    .space(spaceId)
    .collection(UNLOCK_METHODS_COLLECTION.id)
    .configure({ name: UNLOCK_METHODS_COLLECTION.name, force: true })
}

/**
 * Reads the unlock-methods registry record from the data Space, or returns
 * `null` when it does not exist yet. A network / unreachable error propagates.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   the data identity's root client
 * @param options.spaceId {string}   the data Space id
 * @returns {Promise<unknown | null>}
 */
export async function getUnlockMethodsRecord({
  storageServerUrl,
  zcapClient,
  spaceId
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
}): Promise<unknown | null> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  return await was
    .space(spaceId)
    .collection(UNLOCK_METHODS_COLLECTION.id, { encryption: 'plaintext' })
    .resource(UNLOCK_METHODS_RESOURCE)
    .get()
}

/**
 * Writes (upserts) the unlock-methods registry record into the data Space as a
 * JSON document.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   the data identity's root client
 * @param options.spaceId {string}   the data Space id
 * @param options.record {object}   the wrapped registry record
 * @returns {Promise<void>}
 */
export async function putUnlockMethodsRecord({
  storageServerUrl,
  zcapClient,
  spaceId,
  record
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  record: object
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  const body = new TextEncoder().encode(JSON.stringify(record))
  await was
    .space(spaceId)
    .collection(UNLOCK_METHODS_COLLECTION.id, { encryption: 'plaintext' })
    .resource(UNLOCK_METHODS_RESOURCE)
    .put(body, { contentType: 'application/json' })
}
