/**
 * WASRemoteStore: the remote WAS (Wallet Attached Storage) backend, attached
 * when VITE_WAS_SERVER_URL is set. Since the local BrowserStore became the
 * always-active replica, this class no longer serves credential / history /
 * public-link reads and writes -- those replicate in the background through
 * the sync controller. What remains here is the Space lifecycle (create /
 * exists / wipe), the storage-browser read-through over arbitrary Collections
 * and Resources, export / import, and quotas.
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
import { WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import { bufferToBase64Url, digestHash } from '@/lib/cidFrom'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import type { SpaceQuotaReport } from '@/types/storageQuota'
import {
  type FetchedCollectionResource,
  isTextLikeContentType
} from '@/lib/storageResource'
import type { ImportSpaceSummary } from '@/stores/storageManager'

/**
 * Map from logical collection name to its WAS base URL.
 * Expected keys: 'privateCredentials' | 'publicCredentials' | 'walletActivity'
 */
export type ICollectionsSet = Map<string, { url: string }>

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
   * Whether this store invokes delegated session capabilities (a restored
   * `delegated` tier session) rather than root capabilities.
   */
  get isDelegated(): boolean {
    return !!this._sessionCapabilities
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
      .resource(resourceId)
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
    const collection = this.collections?.get(collectionId)
    if (!collection) {
      throw new Error(
        `Collection "${collectionId}" is not initialized. ` +
          'Call ensureUserCollections() first.'
      )
    }
    return collection.url
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
        collections.set(key, { url: this._collectionBaseUrl(id) })
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

    // Space created, now create the standard collections.
    const collections: ICollectionsSet = new Map()
    for (const {
      key,
      id,
      name,
      isPublic,
      encryption
    } of WALLET_STANDARD_COLLECTIONS) {
      try {
        const collection = space.collection(id)
        // Declare the encryption marker only for collections that opt in
        // (private-credentials, wallet-activity); the others stay plaintext.
        // The marker's scheme is set-once on the server, but a late
        // declaration on a pre-marker collection is allowed, so re-running
        // this against an existing Space upgrades it in place.
        await collection.configure(encryption ? { name, encryption } : { name })
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
      collections.set(key, { url: this._collectionBaseUrl(id) })
    }
    this.collections = collections
  }

  /**
   * Provisions an arbitrary (RP-requested) collection in this user's Space:
   * plaintext and non-public -- usable by a relying party through its delegated
   * zcap, but not world-readable. This is the `ensureUserCollections` pattern
   * minus the encryption marker and `setPublic`. Full-tier only: a delegated
   * session holds no capability to (re)configure the Space, and only a fresh
   * passphrase login provisions on the RP's behalf.
   *
   * @param options {object}
   * @param options.id {string}   the WAS collection id (validated by the caller)
   * @param [options.name] {string}   display name; defaults to the id
   * @returns {Promise<string>}   the collection's base URL
   */
  async ensureCollection({
    id,
    name
  }: {
    id: string
    name?: string
  }): Promise<string> {
    if (this._sessionCapabilities) {
      throw new Error(
        'A delegated session cannot provision collections; log in with the ' +
          'passphrase.'
      )
    }
    try {
      await this.was
        .space(this.spaceId)
        .collection(id)
        .configure({
          name: name ?? id
        })
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
    return await Promise.all(
      items.map(async item => {
        const isPublic = await this._collectionFromUrl(item.url).isPublic()
        return { ...item, isPublic }
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

      if (response.status === 404 || response.status === 501) {
        return null
      }

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
