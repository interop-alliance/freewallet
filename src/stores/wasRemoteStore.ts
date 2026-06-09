/**
 * WASRemoteStore: remote storage backend speaking the Wallet Attached Storage
 * (WAS) protocol. Supports credentials plus arbitrary Spaces, Collections,
 * Resources, and the wallet-activity history log. Used by StorageManager when
 * VITE_WAS_SERVER_URL is set.
 *
 * All WAS operations go through `@interop/was-client`'s `WasClient` and its
 * lazy navigational handles (`space` / `collection` / `resource`) rather than
 * hand-built ezcap requests. The `WasClient` wraps the ezcap `ZcapClient` that
 * carries the user's invocation signer.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import {
  WasClient,
  type Collection,
  type Json,
  type Resource
} from '@interop/was-client'
import type { ControllerProfile, User } from '@/types/auth'
import { WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import { bufferToBase64Url, digestHash } from '@/lib/cidFrom'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import {
  type FetchedCollectionResource,
  isTextLikeContentType
} from '@/lib/storageResource'
import type {
  ImportSpaceSummary,
  IWalletStore,
  WalletActivity
} from '@/stores/storageManager'

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
 * @see https://digitalcredentials.github.io/wallet-attached-storage-spec/
 * @see https://github.com/interop-alliance/zcap-developer-guide
 */
export class WASRemoteStore implements IWalletStore {
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
    this.was = new WasClient({ serverUrl: storageServerUrl, zcapClient })
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
   * Returns a `Collection` handle for one of the wallet's standard logical
   * collections, throwing a clear error if collections haven't been initialized
   * yet (i.e. `ensureUserCollections()` hasn't run for this session).
   *
   * @param logicalKey {string} e.g. 'privateCredentials' | 'walletActivity'.
   * @returns {Collection}
   */
  private _collection(logicalKey: string): Collection {
    if (!this.collections?.has(logicalKey)) {
      throw new Error(
        `Collection "${logicalKey}" is not initialized. ` +
          'Call ensureUserCollections() first.'
      )
    }
    return this.was
      .space(this.spaceId)
      .collection(this._collectionId(logicalKey))
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
    return this.was.space(spaceId).collection(collectionId)
  }

  /**
   * Returns a `Resource` handle addressed by an arbitrary WAS resource URL.
   *
   * @param url {string}
   * @returns {Resource}
   */
  private _resourceFromUrl(url: string): Resource {
    const { spaceId, collectionId, resourceId } = this._parsePath(url)
    if (!collectionId || !resourceId) {
      throw new Error(`Not a WAS resource URL: "${url}".`)
    }
    return this.was.space(spaceId).collection(collectionId).resource(resourceId)
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
    return (await this.was.space(this.spaceId).describe()) !== null
  }

  async ensureUserCollections({ user }: { user: User }) {
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
    for (const { key, id, name, isPublic } of WALLET_STANDARD_COLLECTIONS) {
      try {
        const collection = space.collection(id)
        await collection.configure({ name })
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
    const controller = profile.keyAgent.id || user.id
    const spaceId = bufferToBase64Url(await digestHash(controller))
    const remoteStore = new WASRemoteStore({
      storageServerUrl,
      zcapClient: profile.zcapClient,
      spaceId,
      controller
    })

    return { remoteStore }
  }

  async addCollectionResource({
    resourceId,
    collectionId,
    resourceBody
  }: {
    resourceId: string
    collectionId: string
    resourceBody: object
  }) {
    try {
      await this._collection(collectionId).put(resourceId, resourceBody as Json)
    } catch (err) {
      console.error(
        `Error adding resource "${resourceId}" to "${collectionId}":`,
        err
      )
      throw new Error(
        `Failed to add resource "${resourceId}" to "${collectionId}".`,
        { cause: err }
      )
    }
  }

  async addCredential({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }) {
    return await this.addCollectionResource({
      resourceId: cid,
      collectionId: 'privateCredentials',
      resourceBody: credential
    })
  }

  /**
   * Lists the documents of one of the wallet's standard collections, fetching
   * each resource body.
   *
   * @param logicalKey {string}
   * @returns {Promise<Array<{ id: string; doc: Record<string, unknown> }>>}
   */
  private async _listCollectionDocs(
    logicalKey: string
  ): Promise<Array<{ id: string; doc: Record<string, unknown> }>> {
    const collection = this._collection(logicalKey)
    let listing
    try {
      listing = await collection.list()
    } catch (err) {
      console.error(`Error listing collection "${logicalKey}":`, err)
      throw new Error('Failed to list remote storage collection items.', {
        cause: err
      })
    }
    const items = listing?.items ?? []
    return await Promise.all(
      items.map(async row => {
        const doc = (await collection.get(row.id)) as Record<string, unknown>
        return { id: row.id, doc }
      })
    )
  }

  async listCollectionResources({
    collectionUrl
  }: {
    collectionUrl: string
  }): Promise<Array<StorageResource>> {
    let listing
    try {
      listing = await this._collectionFromUrl(collectionUrl).list()
    } catch (err) {
      console.error('Error listing collection resources:', err)
      throw new Error('Failed to list remote storage collection resources.', {
        cause: err
      })
    }
    return (listing?.items ?? []) as Array<StorageResource>
  }

  async deleteCollectionResource({
    relativeUrl
  }: {
    relativeUrl: string
  }): Promise<void> {
    await this._resourceFromUrl(relativeUrl).delete()
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
      listing = await this.was.space(this.spaceId).collections()
    } catch (err) {
      console.error('Error listing collections:', err)
      throw new Error('Failed to list remote storage collections.', {
        cause: err
      })
    }
    return (listing?.items ?? []) as Array<StorageCollection>
  }

  async listHistoryItems(): Promise<
    Array<{ id: string; doc: WalletActivity }>
  > {
    const docs = await this._listCollectionDocs('walletActivity')
    return docs.map(({ id, doc }) => ({ id, doc: doc as WalletActivity }))
  }

  async listCredentials() {
    const docs = await this._listCollectionDocs('privateCredentials')
    return docs.map(({ id, doc }) => ({
      cid: id,
      vc: doc as unknown as IVerifiableCredential
    }))
  }

  async loadCredential({ cid }: { cid: string }) {
    const doc = await this._collection('privateCredentials').get(cid)
    // get() returns null on a miss; honour the undefined contract.
    return (doc ?? undefined) as IVerifiableCredential | undefined
  }

  async deleteCredential({ cid }: { cid: string }) {
    try {
      await this._collection('privateCredentials').resource(cid).delete()
    } catch (err) {
      console.error('Error deleting credential:', err)
      throw new Error('Failed to delete remote credential.', { cause: err })
    }
  }

  /**
   * The absolute, world-readable URL of a credential's shared copy in the
   * `public-credentials` collection. A plain GET resolves it once a public
   * link has been created.
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
   * Publishes a credential by writing a copy into the
   * `public-credentials` collection.
   *
   * @param cid {string}
   * @param credential {IVerifiableCredential}
   * @returns {Promise<string>} the public URL anyone can GET.
   */
  async createPublicLink({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }): Promise<string> {
    try {
      await this.addCollectionResource({
        resourceId: cid,
        collectionId: 'publicCredentials',
        resourceBody: credential
      })
    } catch (err) {
      console.error('Error creating public link:', err)
      throw new Error('Failed to create public link.', { cause: err })
    }
    return this.publicCredentialUrl(cid)
  }

  /**
   * Revokes a credential's public link by removing its copy from
   * `public-credentials`.
   *
   * @param cid {string}
   * @returns {Promise<void>}
   */
  async removePublicLink({ cid }: { cid: string }): Promise<void> {
    try {
      await this._collection('publicCredentials').resource(cid).delete()
    } catch (err) {
      console.error('Error removing public link:', err)
      throw new Error('Failed to remove public link.', { cause: err })
    }
  }

  /**
   * Whether a credential currently has a public link (a copy in the
   * `public-credentials` collection). Returns `false` when the status can't be determined.
   *
   * @param cid {string}
   * @returns {Promise<boolean>}
   */
  async isShared({ cid }: { cid: string }): Promise<boolean> {
    try {
      const doc = await this._collection('publicCredentials').get(cid)
      return doc !== null
    } catch (err) {
      console.error('Error checking public link status:', err)
      return false
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
