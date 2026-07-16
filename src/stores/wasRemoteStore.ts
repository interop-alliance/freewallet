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
import type { IZcap } from '@interop/data-integrity-core'
import { WasClient, type Collection, type Resource } from '@interop/was-client'
import { createEdvEncryption } from '@interop/was-client/edv'
import type { ControllerProfile, User } from '@/types/auth'
import {
  DID_DOCUMENT_RESOURCE,
  ID_COLLECTION,
  KEYRING_COLLECTION,
  KEYRING_RESOURCE,
  UNLOCK_METHODS_COLLECTION,
  UNLOCK_METHODS_RESOURCE,
  WALLET_STANDARD_COLLECTIONS
} from '@/app.config'
import { bufferToBase64Url, digestHash } from '@/lib/cidFrom'
// Deep import (bypassing the `@/lib/sync` barrel) so this eagerly loaded module
// does not drag the barrel's RxDB replication machinery into the entry chunk.
import type { Json } from '@/lib/sync/types.js'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import type { SpaceQuotaReport } from '@/types/storageQuota'
import {
  type FetchedCollectionResource,
  isTextLikeContentType
} from '@/lib/storageResource'
import type { ImportSpaceSummary } from '@/stores/storageManager'
import { errorStatus } from '@/stores/wasSyncPort'

/**
 * Map from logical collection name to its WAS base URL.
 * Expected keys: 'privateCredentials' | 'publicCredentials' | 'walletActivity'
 */
export type ICollectionsSet = Map<string, string>

/**
 * The parsed components of a WAS resource/collection URL
 * (`/space/:spaceId/:collectionId/:resourceId`).
 */
interface ParsedWasPath {
  spaceId: string
  collectionId?: string
  resourceId?: string
}

/**
 * The delegated zcaps a restored (`delegated` tier) session invokes instead
 * of root capabilities: a GET/HEAD capability on the Space URL (covers reads
 * anywhere under the Space via target attenuation) and a read/write
 * capability per standard collection, keyed by WAS collection id. Absent in
 * the full tier, where the root key invokes root capabilities directly.
 */
export interface SessionCapabilities {
  spaceRead: IZcap
  collections: Record<string, IZcap>
}

/**
 * @see https://digitalcredentials.github.io/wallet-attached-storage-spec/
 * @see https://github.com/interop-alliance/zcap-developer-guide
 */
export class WASRemoteStore {
  public storageServerUrl: string
  public was: WasClient
  public spaceId: string
  public controller: string

  public spaceUrl: string
  public collections?: ICollectionsSet
  private _sessionCapabilities?: SessionCapabilities

  constructor({
    storageServerUrl,
    zcapClient,
    spaceId,
    controller,
    sessionCapabilities
  }: {
    storageServerUrl: string
    zcapClient: ZcapClient
    spaceId: string
    controller: string
    sessionCapabilities?: SessionCapabilities
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
    this._sessionCapabilities = sessionCapabilities
  }

  /**
   * The capability to attach to a request in the delegated tier (`undefined`
   * in the full tier, where handles invoke root capabilities). Writes into a
   * standard collection use its read/write capability; everything else uses
   * the Space read capability -- a write it cannot authorize is then denied
   * by the server, which is the intended failure mode.
   *
   * @param options {object}
   * @param [options.collectionId] {string}
   * @param [options.write] {boolean}
   * @returns {IZcap | undefined}
   */
  sessionCapabilityFor({
    collectionId,
    write = false
  }: {
    collectionId?: string
    write?: boolean
  } = {}): IZcap | undefined {
    if (!this._sessionCapabilities) {
      return undefined
    }
    if (write && collectionId) {
      return (
        this._sessionCapabilities.collections[collectionId] ??
        this._sessionCapabilities.spaceRead
      )
    }
    return this._sessionCapabilities.spaceRead
  }

  /**
   * Resolves the actual WAS collection id for one of the wallet's standard
   * logical collection keys.
   *
   * @param logicalKey {string} e.g. 'privateCredentials' | 'walletActivity'.
   * @returns {string}
   */
  private _collectionId(logicalKey: string): string {
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
   * @returns {ParsedWasPath}
   */
  private _parsePath(url: string): ParsedWasPath {
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
  private _collectionFromUrl(url: string): Collection {
    const { spaceId, collectionId } = this._parsePath(url)
    if (!collectionId) {
      throw new Error(`Not a WAS collection URL: "${url}".`)
    }
    return this.was
      .space(spaceId, this._handleOptions({ spaceId, collectionId }))
      .collection(collectionId)
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
   * @param [options] {object}
   * @param [options.write] {boolean}   the handle will be used to write
   * @returns {Resource}
   */
  private _resourceFromUrl(
    url: string,
    { write = false }: { write?: boolean } = {}
  ): Resource {
    const { spaceId, collectionId, resourceId } = this._parsePath(url)
    if (!collectionId || !resourceId) {
      throw new Error(`Not a WAS resource URL: "${url}".`)
    }
    return this.was
      .space(spaceId, this._handleOptions({ spaceId, collectionId, write }))
      .collection(collectionId)
      .resource(resourceId, { encryption: 'plaintext' })
  }

  /**
   * Handle options for a target within this store's own Space: carries the
   * matching session capability in the delegated tier, nothing otherwise
   * (root invocations, or a foreign Space this store holds no zcaps for).
   *
   * @param options {object}
   * @param options.spaceId {string}   the target's Space id (from its URL)
   * @param [options.collectionId] {string}
   * @param [options.write] {boolean}
   * @returns {{ capability?: IZcap }}
   */
  private _handleOptions({
    spaceId,
    collectionId,
    write = false
  }: {
    spaceId: string
    collectionId?: string
    write?: boolean
  }): { capability?: IZcap } {
    if (spaceId !== this.spaceId) {
      return {}
    }
    const capability = this.sessionCapabilityFor({ collectionId, write })
    return capability ? { capability } : {}
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

  async userExists() {
    // describe() returns null on a 404 (not-found or unauthorized).
    return (
      (await this.was
        .space(this.spaceId, this._handleOptions({ spaceId: this.spaceId }))
        .describe()) !== null
    )
  }

  async ensureUserCollections({ user }: { user: User }) {
    // A delegated session never (re)configures the Space or its collections
    // -- the full session that delegated it already provisioned everything
    // (and the session capabilities could not authorize the writes anyway).
    // Just rebuild the collection-URL map.
    if (this._sessionCapabilities) {
      const collections: ICollectionsSet = new Map()
      for (const { key, id } of WALLET_STANDARD_COLLECTIONS) {
        collections.set(key, this._collectionBaseUrl(id))
      }
      this.collections = collections
      return
    }
    const space = this.was.space(this.spaceId)

    // Create (upsert) the Space for this user on the remote storage server.
    try {
      await space.configure({
        name: 'Freewallet Space',
        controller: this.controller
      })
    } catch (err) {
      console.error('Error creating space:', err)
      throw new Error(
        `Error creating space for user "${user.id}" at "${this.spaceUrl}".`,
        { cause: err }
      )
    }

    // Space created, now create the standard collections plus the `id`
    // collection. Each collection's own configure-then-setPublic ordering
    // stays sequential within its chain, but the independent chains -- which
    // depend only on the Space already existing -- run concurrently under a
    // single Promise.all, collapsing what was a series of signed round trips
    // into one batch on every full login (including each CHAPI popup). A
    // rejected chain surfaces as Promise.all's first rejection; as with the
    // former serial loop, chains that already completed leave their
    // provisioning in place (partial provisioning was possible before too).
    const collections: ICollectionsSet = new Map()
    const provisionStandardCollections = WALLET_STANDARD_COLLECTIONS.map(
      async ({ key, id, name, isPublic, encryption }) => {
        try {
          const collection = space.collection(id)
          // Declare the encryption marker only for collections that opt in
          // (private-credentials, wallet-activity); the others stay plaintext.
          // The marker's scheme is set-once on the server, but a late
          // declaration on a pre-marker collection is allowed, so re-running
          // this against an existing Space upgrades it in place. `force` lets
          // the plaintext upsert create a fresh collection: this runs with the
          // root capability, so a 404 from the pre-merge describe really means
          // absent, not unreadable (was-client >= 0.13 fails closed otherwise).
          await collection.configure(
            encryption ? { name, encryption } : { name, force: true }
          )
          if (isPublic) {
            await collection.setPublic()
          }
        } catch (err) {
          console.error(`Error creating collection "${id}":`, err)
          throw new Error(
            `Error creating collection "${id}" in space "${this.spaceId}".`,
            { cause: err }
          )
        }
        collections.set(key, this._collectionBaseUrl(id))
      }
    )

    // The `id` collection: standard-on-the-server but not wallet-synced, so it
    // lives outside WALLET_STANDARD_COLLECTIONS and gets no local replica or
    // collection map entry. Plaintext, no collection-level public grant (the
    // DID document is published per-resource by `setIdResourcePublic`).
    const provisionIdCollection = (async () => {
      try {
        // `force`: same root-capability reasoning as the standard collections
        // above -- a 404 here means the collection does not exist yet.
        await space.collection(ID_COLLECTION.id).configure({
          name: ID_COLLECTION.name,
          force: true
        })
      } catch (err) {
        console.error(`Error creating collection "${ID_COLLECTION.id}":`, err)
        throw new Error(
          `Error creating collection "${ID_COLLECTION.id}" in space ` +
            `"${this.spaceId}".`,
          { cause: err }
        )
      }
    })()

    await Promise.all([...provisionStandardCollections, provisionIdCollection])

    this.collections = collections
  }

  /**
   * Returns a `Resource` handle for a resource in this Space's `id` collection,
   * invoked with the root capability. Full-tier only: a delegated session
   * holds no capability over the `id` collection (by design -- the DID
   * document changes only at key ceremonies, which need the root key).
   *
   * @param resourceId {string}
   * @returns {Resource}
   */
  private _idResource(resourceId: string): Resource {
    if (this._sessionCapabilities) {
      throw new Error(
        'A delegated session cannot access the `id` collection; log in with ' +
          'the passphrase.'
      )
    }
    return this.was
      .space(this.spaceId)
      .collection(ID_COLLECTION.id)
      .resource(resourceId)
  }

  /**
   * Reads a resource from the `id` collection, returning the parsed body or
   * `undefined` when it is missing (the DID provisioning existence probe).
   *
   * @param options {object}
   * @param options.resourceId {string}
   * @returns {Promise<unknown>}
   */
  async getIdResource({
    resourceId
  }: {
    resourceId: string
  }): Promise<unknown> {
    const result = await this._idResource(resourceId).get()
    return result === null ? undefined : result
  }

  /**
   * Writes (upserts) a resource into the `id` collection. An object body is
   * JSON-serialized; a string body (the raw `did.jsonl` JSON-Lines log) passes
   * through verbatim. Either way the bytes are sent with an explicit content
   * type -- `did.json` as `application/did+json`, `did.jsonl` as `text/jsonl`
   * (a plain-object `put` would force `application/json`, and the JSON-Lines
   * log is not a single JSON document).
   *
   * @param options {object}
   * @param options.resourceId {string}
   * @param options.content {object | string}   a JSON body, or a raw string body
   * @param [options.contentType] {string}   defaults to `application/json`
   * @returns {Promise<void>}
   */
  async putIdResource({
    resourceId,
    content,
    contentType = 'application/json'
  }: {
    resourceId: string
    content: object | string
    contentType?: string
  }): Promise<void> {
    const serialized =
      typeof content === 'string' ? content : JSON.stringify(content)
    const body = new TextEncoder().encode(serialized)
    await this._idResource(resourceId).put(body, { contentType })
  }

  /**
   * Reads a resource from the `id` collection as raw text, without JSON parsing
   * -- the did:webvh existence probe and log reader. Returns `undefined` when
   * the resource is missing (WAS conflates 404 for missing/unauthorized). Used
   * for `did.jsonl`, which is a JSON-Lines string rather than a JSON document.
   *
   * @param options {object}
   * @param options.resourceId {string}
   * @returns {Promise<string | undefined>}
   */
  async getIdResourceRaw({
    resourceId
  }: {
    resourceId: string
  }): Promise<string | undefined> {
    const result = await this._idResource(resourceId).getText()
    return result === null ? undefined : result
  }

  /**
   * Makes a single resource in the `id` collection world-readable (a
   * resource-level `PublicCanRead` policy). Used to publish `did.json` while
   * the sibling `keys.json` stays capability-only.
   *
   * @param options {object}
   * @param options.resourceId {string}
   * @returns {Promise<void>}
   */
  async setIdResourcePublic({
    resourceId
  }: {
    resourceId: string
  }): Promise<void> {
    await this._idResource(resourceId).setPublic()
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
   * always plaintext (no encryption marker) -- usable by a relying party
   * through its delegated zcap. By default it is not world-readable; with
   * `isPublic`, a collection-level `PublicCanRead` policy is set at
   * provisioning time, so anyone on the web can read it without
   * authorization (writes stay capability-only). Policy endpoints are
   * capability-only on the server, so only the wallet -- holding the space
   * root -- can set it. This is the `ensureUserCollections` pattern minus the
   * encryption marker. Full-tier only: a delegated session holds no
   * capability to (re)configure the Space, and only a fresh passphrase login
   * provisions on the RP's behalf.
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
    if (this._sessionCapabilities) {
      throw new Error(
        'A delegated session cannot provision collections; log in with the ' +
          'passphrase.'
      )
    }
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
    return this._collectionBaseUrl(id)
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
  private _collectionBaseUrl(collectionId: string): string {
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
    const controller = profile.keyAgent?.id || user.id
    const spaceId = bufferToBase64Url(await digestHash(controller))
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
    let collection
    let listing
    try {
      collection = this._collectionFromUrl(collectionUrl)
      listing = await collection.list()
    } catch (err) {
      console.error('Error listing collection resources:', err)
      throw new Error('Failed to list remote storage collection resources.', {
        cause: err
      })
    }

    const items = (listing?.items ?? []) as Array<StorageResource>
    const collectionIsPublic = await collection.isPublic()
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
    await this._resourceFromUrl(relativeUrl, { write: true }).delete()
  }

  async fetchCollectionResource(
    resource: StorageResource
  ): Promise<FetchedCollectionResource> {
    const result = await this._resourceFromUrl(resource.url).get()
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
    let listing
    try {
      listing = await this.was
        .space(this.spaceId, this._handleOptions({ spaceId: this.spaceId }))
        .collections()
    } catch (err) {
      console.error('Error listing collections:', err)
      throw new Error('Failed to list remote storage collections.', {
        cause: err
      })
    }
    const items = (listing?.items ?? []) as Array<StorageCollection>
    // The listing's `CollectionSummary` carries no public flag (only id / url /
    // name), so each collection's `PublicCanRead` status still needs its own
    // policy describe. Fan those out under a single Promise.all rather than a
    // serial loop, so the N probes overlap instead of waiting one-by-one.
    return await Promise.all(
      items.map(async item => {
        const handle = this._collectionFromUrl(item.url)
        const [isPublic, description] = await Promise.all([
          handle.isPublic(),
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
   * The absolute, world-readable URL of a credential's shared copy in the
   * `public-credentials` collection. A plain GET resolves it once a public
   * link has been created (locally) and replicated to this server.
   *
   * @param cid {string}
   * @returns {string}
   */
  publicCredentialUrl(cid: string): string {
    const collectionId = this._collectionId('publicCredentials')
    return new URL(
      `/space/${this.spaceId}/${collectionId}/${cid}`,
      this.storageServerUrl
    ).toString()
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
    const collectionId = this._collectionId(logicalKey)
    let listing
    try {
      listing = await this.was
        .space(
          this.spaceId,
          this._handleOptions({ spaceId: this.spaceId, collectionId })
        )
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
    const collectionId = this._collectionId(logicalKey)
    try {
      const response = await this.was.request({
        capability: this.sessionCapabilityFor({ collectionId }),
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
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.resourceId {string}   the content-derived envelope-hash id
   * @param options.body {Json}   the raw EDV envelope (or plaintext document)
   * @returns {Promise<{ created: boolean }>}
   */
  async putSyncedResource({
    logicalKey,
    resourceId,
    body
  }: {
    logicalKey: string
    resourceId: string
    body: Json
  }): Promise<{ created: boolean }> {
    const collectionId = this._collectionId(logicalKey)
    try {
      await this.was.request({
        capability: this.sessionCapabilityFor({ collectionId, write: true }),
        path: `/space/${this.spaceId}/${collectionId}/${encodeURIComponent(
          resourceId
        )}`,
        method: 'PUT',
        json: body as object,
        headers: { 'if-none-match': '*' }
      })
      return { created: true }
    } catch (err) {
      if (errorStatus(err) === 412) {
        return { created: false }
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
        method: 'GET',
        capability: this.sessionCapabilityFor()
      })

      return response.data as SpaceQuotaReport
    } catch (err) {
      const status =
        (err as { status?: number }).status ??
        (err as { response?: { status?: number } }).response?.status

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
      // In the delegated tier this fails server-side: export is a POST and
      // the session capabilities are read-only outside the collections.
      response = await this.was.request({
        path: `/space/${this.spaceId}/export`,
        method: 'POST',
        headers: { accept: 'application/x-tar' },
        capability: this.sessionCapabilityFor()
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
 * invocation signer is the unlock root key (full-tier root invocation, no
 * capability attached -- the same posture the data Space uses in the full
 * tier). The one resource is a plaintext JSON document (its keyring payload is
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
 * Ensures the unlock Space and its single `keyring` collection exist
 * (upsert -- idempotent). Runs with the unlock root capability, so `force`
 * lets the collection upsert treat a 404 from the pre-merge describe as
 * genuinely absent rather than unreadable.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}   the unlock Space id
 * @param options.controller {string}   the unlock did:key
 * @returns {Promise<void>}
 */
export async function ensureUnlockSpace({
  storageServerUrl,
  zcapClient,
  spaceId,
  controller
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  controller: string
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  const space = was.space(spaceId)
  await space.configure({ name: 'Freewallet Keyring', controller })
  await space
    .collection(KEYRING_COLLECTION.id)
    .configure({ name: KEYRING_COLLECTION.name, force: true })
}

/**
 * Reads the keyring record from the unlock Space, or returns `null` when it
 * does not exist yet (a missing Space, collection, or resource all surface as
 * a 404-shaped `null` from `resource.get()`). A network / unreachable error
 * propagates, so callers can distinguish "no keyring" from "could not check".
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}   the unlock Space id
 * @returns {Promise<unknown | null>}
 */
export async function getUnlockKeyring({
  storageServerUrl,
  zcapClient,
  spaceId
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
}): Promise<unknown | null> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  const result = await was
    .space(spaceId)
    .collection(KEYRING_COLLECTION.id, { encryption: 'plaintext' })
    .resource(KEYRING_RESOURCE)
    .get()
  return result === null ? null : result
}

/**
 * Writes (upserts) the keyring record into the unlock Space as a JSON
 * document. Serialized to bytes with an explicit `application/json`
 * content-type (mirroring `putIdResource`).
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}   the unlock Space id
 * @param options.record {object}   the keyring record
 * @returns {Promise<void>}
 */
export async function putUnlockKeyring({
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
    .collection(KEYRING_COLLECTION.id, { encryption: 'plaintext' })
    .resource(KEYRING_RESOURCE)
    .put(body, { contentType: 'application/json' })
}

/**
 * Deletes the whole unlock Space (what retires an old passphrase on a
 * passphrase change). `space.delete()` is idempotent, so an already-absent
 * Space is a success.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}   the unlock Space id
 * @returns {Promise<void>}
 */
export async function deleteUnlockSpace({
  storageServerUrl,
  zcapClient,
  spaceId
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  await was.space(spaceId).delete()
}

/**
 * Deletes an unlock Space with an explicitly attached management capability,
 * rather than by root invocation. The `zcapClient` here is the DATA identity's
 * (not the unlock identity's); the attached `capability` -- the management zcap
 * the unlock identity delegated to the data identity at bind time -- is what
 * authorizes the DELETE against the unlock Space. This is the tap-free
 * revocation path for a lost unlock method: the data identity can retire it
 * without re-deriving the unlock identity from the (possibly lost) secret. A
 * 404 is treated as success (idempotent -- the Space is already gone).
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   the data identity's client
 * @param options.spaceId {string}   the unlock Space id
 * @param options.capability {IZcap}   the delegated management zcap
 * @returns {Promise<void>}
 */
export async function deleteUnlockSpaceWithCapability({
  storageServerUrl,
  zcapClient,
  spaceId,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  capability: IZcap
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  try {
    await was.request({
      capability,
      path: `/space/${spaceId}`,
      method: 'DELETE'
    })
  } catch (err) {
    if (errorStatus(err) === 404) {
      return
    }
    throw err
  }
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
 * `null` when it does not exist yet (a missing collection or resource surfaces
 * as a 404-shaped `null` from `resource.get()`). A network / unreachable error
 * propagates.
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
  const result = await was
    .space(spaceId)
    .collection(UNLOCK_METHODS_COLLECTION.id, { encryption: 'plaintext' })
    .resource(UNLOCK_METHODS_RESOURCE)
    .get()
  return result === null ? null : result
}

/**
 * Writes (upserts) the unlock-methods registry record into the data Space as a
 * JSON document. Serialized to bytes with an explicit `application/json`
 * content-type (mirroring `putUnlockKeyring`).
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
