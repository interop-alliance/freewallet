/**
 * The storage-backend seam every synced-collection read/write in
 * `StorageManager` routes through, plus the remote-direct implementation of it.
 *
 * `SyncedCollectionStore` is the port: the subset of storage operations that
 * target one of the wallet's standard synced collections (credentials, app
 * keys, history, public links, contacts). Two backends satisfy it and are
 * selected ONCE at `StorageManager` construction:
 *
 * - the local active replica, `BrowserStore` (RxDB/IndexedDB), which owns the
 *   envelope/id/epoch orchestration -- the normal case; and
 * - `RemoteDirectStore` (this file), used by the CHAPI popup. A popup runs in a
 *   third-party partitioned iframe whose local IndexedDB no sync controller
 *   drives, so a credential stored locally would be stranded and a list would
 *   always come back empty. This backend reads and writes the standard synced
 *   collections straight over the remote WAS collections
 *   (`WASRemoteStore.listSyncedResources` / `getSyncedResource` /
 *   `putSyncedResource` / `deleteSyncedResource`).
 *
 * Both backends encrypt/decrypt through the SAME per-collection {@link DocCipher}
 * instances the session built (`@interop/was-client/edv`): the content-derived
 * envelope-hash id and the key-epoch stamp come from `cipher.encrypt`, so a
 * remote-direct write reproduces verbatim what background replication would have
 * pushed (the raw EDV envelope under its content-derived id, created with
 * `If-None-Match: *`, stamped with the same `Key-Epoch`) and the main app's
 * replication pulls popup writes cleanly.
 *
 * Contacts (and their revisions) are not reachable in a popup -- neither CHAPI
 * flow manages them -- so this backend rejects contact operations with a clear
 * error rather than silently operating on the empty partitioned IndexedDB.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { ContactData, ContactRevisionPayload } from '@interop/social-core'
import { cidFrom } from '@interop/was-client/sync'
import type { Json } from '@/lib/sync'
import {
  isEncryptedEnvelope,
  UnknownEpochError,
  type DocCipher
} from '@interop/was-client/edv'
import { KeyUnwrapError } from '@interop/was-client'
import type { StoredCredential } from '@/types/credential'
import type { StoredContact } from '@/types/contact'
import type { WalletActivity } from '@/stores/storageManager'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

/**
 * The storage operations `StorageManager` routes uniformly through one selected
 * backend (the local active replica, or the remote-direct popup backend). The
 * facade never forks per operation: it holds one `SyncedCollectionStore` and the
 * envelope/id/encryption logic lives in the injected {@link DocCipher} each
 * backend shares.
 *
 * The unknown-epoch counters and `setCiphers` are the descriptor-refresh contract:
 * after a read reports unknown-epoch rows the facade rebuilds the ciphers under
 * a freshly fetched descriptor, swaps them in via `setCiphers`, and re-reads.
 */
export interface SyncedCollectionStore {
  addCredential(options: {
    cid: string
    credential: IVerifiableCredential
  }): Promise<boolean>
  listCredentials(): Promise<Array<StoredCredential>>
  loadCredential(options: {
    cid: string
  }): Promise<IVerifiableCredential | undefined>
  deleteCredential(options: { cid: string }): Promise<void>
  addAppKey(options: {
    cid: string
    credential: IVerifiableCredential
  }): Promise<boolean>
  listAppKeys(): Promise<Array<StoredCredential>>
  deleteAppKey(options: { cid: string }): Promise<void>
  readonly unknownEpochAppKeys: number
  readonly undecryptableCredentials: number
  purgeUndecryptableCredentials(): Promise<number>
  readonly unknownEpochCredentials: number
  readonly unknownEpochHistory: number
  readonly noEpochKeyCredentials: number
  addHistoryItem(options: {
    resourceId: string
    activity: WalletActivity
  }): Promise<void>
  listHistoryItems(): Promise<Array<{ id: string; doc: WalletActivity }>>
  addPublicCredential(options: {
    cid: string
    credential: IVerifiableCredential
  }): Promise<void>
  removePublicCredential(options: { cid: string }): Promise<void>
  hasPublicCredential(options: { cid: string }): Promise<boolean>
  listContacts(): Promise<Array<StoredContact>>
  loadContact(options: { id: string }): Promise<StoredContact | undefined>
  addContact(options: {
    contact: ContactData
    writerId: string
  }): Promise<StoredContact>
  updateContact(options: {
    id: string
    contact: ContactData
    writerId: string
  }): Promise<StoredContact>
  deleteContact(options: { id: string }): Promise<void>
  addContactRevision(options: {
    revision: ContactRevisionPayload
  }): Promise<void>
  listContactRevisions(options: {
    contactId: string
  }): Promise<Array<ContactRevisionPayload>>
  setCiphers(ciphers: Record<string, DocCipher>): void
}

/**
 * The remote-direct backend: serves the standard synced collections straight
 * over a session's `WASRemoteStore`, encrypting/decrypting with the same
 * per-collection ciphers the local store uses.
 */
export class RemoteDirectStore implements SyncedCollectionStore {
  #remote: WASRemoteStore
  #ciphers: Record<string, DocCipher>
  // Counts from the most recent list read, mirroring BrowserStore's surface so
  // the facade's shared epoch-refresh path drives both backends identically.
  #undecryptableCredentials = 0
  #unknownEpochCredentials = 0
  #unknownEpochHistory = 0
  // Same signal for the `app-connections` collection, so a rekey by another
  // client cannot make a stored app key read as absent (which would mint a
  // second identity for the app).
  #unknownEpochAppKeys = 0
  // Count of resources the last read skipped because this wallet holds no key
  // for their key epoch (never a recipient, or removed and the epoch rotated).
  // Never purged -- they are another reader's data, not garbage -- and they
  // drive no descriptor refresh, which could not help.
  #noEpochKeyCredentials = 0
  // Session cache of the remote `private-credentials` contents, so a batch of
  // adds does not re-list-and-decrypt the whole collection per item (it is
  // rebuilt by every list read and maintained incrementally on add/delete).
  #credentialsLoaded = false
  #credentialEntries: Array<{
    resourceId: string
    cid: string
    vc: IVerifiableCredential
  }> = []
  #credentialCidIndex = new Map<string, Set<string>>()
  // The resource ids of undecryptable rows from the most recent scan, so
  // `purgeUndecryptableCredentials` can remove them without a second scan.
  #undecryptableCredentialRowIds: string[] = []

  constructor({
    remoteStore,
    ciphers
  }: {
    remoteStore: WASRemoteStore
    ciphers: Record<string, DocCipher>
  }) {
    this.#remote = remoteStore
    this.#ciphers = ciphers
  }

  /**
   * One synced collection's cipher, or a clear error when it is absent (a
   * remote-direct session is always a passphrase session with vault keys, so
   * this is a misconfiguration guard rather than an expected path).
   *
   * @param logicalKey {string}   'privateCredentials' | 'walletActivity'
   * @returns {DocCipher}
   */
  #cipherFor(logicalKey: string): DocCipher {
    const cipher = this.#ciphers[logicalKey]
    if (!cipher) {
      throw new Error(
        `Remote-direct storage requires the "${logicalKey}" cipher.`
      )
    }
    return cipher
  }

  /**
   * Records a `(cid, resourceId)` pair in a cid -> live-row-ids index.
   *
   * @param options {object}
   * @param options.index {Map<string, Set<string>>}
   * @param options.cid {string}
   * @param options.resourceId {string}
   * @returns {void}
   */
  #indexCredential({
    index,
    cid,
    resourceId
  }: {
    index: Map<string, Set<string>>
    cid: string
    resourceId: string
  }): void {
    let rowIds = index.get(cid)
    if (!rowIds) {
      rowIds = new Set<string>()
      index.set(cid, rowIds)
    }
    rowIds.add(resourceId)
  }

  /**
   * Reads every resource of one content-addressed encrypted collection and
   * resolves each to its content cid + decrypted document, mirroring
   * `BrowserStore.#credentialEntries` (decrypt envelope rows, pass legacy
   * plaintext rows through keyed by their resource id) and its tolerant
   * bucketing: a row whose envelope will not decrypt under the current KAK is
   * collected as undecryptable (purgeable), a row naming an unknown key epoch
   * is counted separately so a descriptor refresh can pick it up, and a row
   * this wallet holds no key for is counted apart from both (no refresh can
   * help, and it is another reader's data). The per-resource GETs and the
   * decrypts run in parallel; the fold walks them in list order, so the entry
   * ordering and the failure buckets match what a sequential pass produced.
   *
   * Shared by the credential and app-key reads -- the two collections differ
   * only in what their callers do with the result (the credential path keeps a
   * session cache and a purge list, the app-key path scans per call).
   *
   * @param options {object}
   * @param options.logicalKey {string}   'privateCredentials' | 'appConnections'
   * @returns {Promise<{ entries: Array<{ resourceId: string; cid: string;
   *   vc: IVerifiableCredential }>; undecryptableRowIds: string[];
   *   unknownEpoch: number; noEpochKey: number }>}
   */
  async #scanContentCollection({
    logicalKey
  }: {
    logicalKey: string
  }): Promise<{
    entries: Array<{
      resourceId: string
      cid: string
      vc: IVerifiableCredential
    }>
    undecryptableRowIds: string[]
    unknownEpoch: number
    noEpochKey: number
  }> {
    const cipher = this.#cipherFor(logicalKey)
    const resources = await this.#remote.listSyncedResources({ logicalKey })
    const bodies = await Promise.all(
      resources.map(({ id }) =>
        this.#remote.getSyncedResource({ logicalKey, resourceId: id })
      )
    )
    const entries: Array<{
      resourceId: string
      cid: string
      vc: IVerifiableCredential
    }> = []
    const undecryptableRowIds: string[] = []
    let unknownEpoch = 0
    let noEpochKey = 0
    const decrypted = await Promise.all(
      bodies.map(async data => {
        if (data === undefined || !isEncryptedEnvelope(data)) {
          return { vc: data as unknown as IVerifiableCredential | undefined }
        }
        try {
          return {
            vc: (await cipher.decrypt({
              envelope: data
            })) as unknown as IVerifiableCredential,
            fromEnvelope: true
          }
        } catch (err) {
          return { err, fromEnvelope: true }
        }
      })
    )
    for (let position = 0; position < resources.length; position++) {
      const { id: resourceId } = resources[position]
      const { vc, fromEnvelope, err } = decrypted[position]
      if (err) {
        if (err instanceof UnknownEpochError) {
          // Possibly-fresh data behind a stale descriptor: skip it so a descriptor
          // refresh can pick it up, never purge it.
          console.warn(
            `Skipping unknown-epoch remote "${logicalKey}" resource ` +
              `"${resourceId}":`,
            err
          )
          unknownEpoch += 1
        } else if (err instanceof KeyUnwrapError) {
          // This wallet is not a recipient of the resource's key epoch: skip it,
          // but never purge it -- a purge here would delete it from the server.
          console.warn(
            `Skipping remote "${logicalKey}" resource "${resourceId}": ` +
              `this wallet is not a recipient of its key epoch:`,
            err
          )
          noEpochKey += 1
        } else {
          // One undecryptable remote row must not brick the whole popup list.
          console.warn(
            `Skipping undecryptable remote "${logicalKey}" resource ` +
              `"${resourceId}":`,
            err
          )
          undecryptableRowIds.push(resourceId)
        }
        continue
      }
      if (vc === undefined) {
        continue
      }
      const cid = fromEnvelope ? await cidFrom({ doc: vc }) : resourceId
      entries.push({ resourceId, cid, vc })
    }
    return { entries, undecryptableRowIds, unknownEpoch, noEpochKey }
  }

  /**
   * Reads the remote `private-credentials` collection, rebuilding the session
   * cache, the cid index, and the read counters the facade's epoch-refresh
   * path consults.
   *
   * @returns {Promise<void>}
   */
  async #loadCredentialEntries(): Promise<void> {
    const { entries, undecryptableRowIds, unknownEpoch, noEpochKey } =
      await this.#scanContentCollection({ logicalKey: 'privateCredentials' })
    const index = new Map<string, Set<string>>()
    for (const { resourceId, cid } of entries) {
      this.#indexCredential({ index, cid, resourceId })
    }
    this.#credentialEntries = entries
    this.#credentialCidIndex = index
    this.#undecryptableCredentialRowIds = undecryptableRowIds
    this.#undecryptableCredentials = undecryptableRowIds.length
    this.#unknownEpochCredentials = unknownEpoch
    this.#noEpochKeyCredentials = noEpochKey
    this.#credentialsLoaded = true
  }

  /**
   * Loads the credential session cache once (a single full scan), so a batch of
   * adds consults an in-memory index rather than re-listing per item.
   *
   * @returns {Promise<void>}
   */
  async #ensureCredentialsLoaded(): Promise<void> {
    if (!this.#credentialsLoaded) {
      await this.#loadCredentialEntries()
    }
  }

  async addCredential({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }): Promise<boolean> {
    const cipher = this.#cipherFor('privateCredentials')
    // Dedupe by content cid against the cached remote contents (scanned once per
    // session), not a full refetch per add.
    await this.#ensureCredentialsLoaded()
    if (this.#credentialCidIndex.has(cid)) {
      return false
    }
    const { id, envelope, epoch } = await cipher.encrypt({
      data: credential as unknown as Json
    })
    const { created } = await this.#remote.putSyncedResource({
      logicalKey: 'privateCredentials',
      resourceId: id,
      body: envelope,
      epoch
    })
    if (created) {
      // Maintain the cache/index incrementally so the next add in a batch sees
      // this one without another scan.
      this.#indexCredential({
        index: this.#credentialCidIndex,
        cid,
        resourceId: id
      })
      this.#credentialEntries.push({ resourceId: id, cid, vc: credential })
    }
    return created
  }

  async listCredentials(): Promise<Array<StoredCredential>> {
    // A fresh scan (updating the unknown-epoch / undecryptable counts the facade
    // reads) that also rebuilds the session cache.
    await this.#loadCredentialEntries()
    const seen = new Set<string>()
    const credentials: StoredCredential[] = []
    for (const { cid, vc } of this.#credentialEntries) {
      if (seen.has(cid)) {
        continue
      }
      seen.add(cid)
      credentials.push({ cid, vc })
    }
    return credentials
  }

  async loadCredential({
    cid
  }: {
    cid: string
  }): Promise<IVerifiableCredential | undefined> {
    await this.#ensureCredentialsLoaded()
    return this.#credentialEntries.find(entry => entry.cid === cid)?.vc
  }

  async deleteCredential({ cid }: { cid: string }): Promise<void> {
    await this.#ensureCredentialsLoaded()
    const rowIds = this.#credentialCidIndex.get(cid)
    if (!rowIds) {
      return
    }
    for (const resourceId of rowIds) {
      await this.#remote.deleteSyncedResource({
        logicalKey: 'privateCredentials',
        resourceId
      })
    }
    this.#credentialCidIndex.delete(cid)
    this.#credentialEntries = this.#credentialEntries.filter(
      entry => entry.cid !== cid
    )
  }

  /**
   * Adds an app-key credential to the remote `app-connections` collection,
   * idempotent on the credential's content cid (encryption is
   * nondeterministic, so the row id cannot carry idempotence). Returns whether
   * a row was actually created.
   *
   * The collection is scanned per call rather than cached for the session:
   * it holds one row per connected app, and an App Connect popup performs at
   * most one add.
   *
   * @param options {object}
   * @param options.cid {string}
   * @param options.credential {IVerifiableCredential}
   * @returns {Promise<boolean>}
   */
  async addAppKey({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }): Promise<boolean> {
    const cipher = this.#cipherFor('appConnections')
    const { entries } = await this.#scanContentCollection({
      logicalKey: 'appConnections'
    })
    if (entries.some(entry => entry.cid === cid)) {
      return false
    }
    const { id, envelope, epoch } = await cipher.encrypt({
      data: credential as unknown as Json
    })
    const { created } = await this.#remote.putSyncedResource({
      logicalKey: 'appConnections',
      resourceId: id,
      body: envelope,
      epoch
    })
    return created
  }

  async listAppKeys(): Promise<Array<StoredCredential>> {
    const { entries, unknownEpoch } = await this.#scanContentCollection({
      logicalKey: 'appConnections'
    })
    this.#unknownEpochAppKeys = unknownEpoch
    const seen = new Set<string>()
    const appKeys: StoredCredential[] = []
    for (const { cid, vc } of entries) {
      if (seen.has(cid)) {
        continue
      }
      seen.add(cid)
      appKeys.push({ cid, vc })
    }
    return appKeys
  }

  async deleteAppKey({ cid }: { cid: string }): Promise<void> {
    const { entries } = await this.#scanContentCollection({
      logicalKey: 'appConnections'
    })
    for (const entry of entries) {
      if (entry.cid !== cid) {
        continue
      }
      await this.#remote.deleteSyncedResource({
        logicalKey: 'appConnections',
        resourceId: entry.resourceId
      })
    }
  }

  get unknownEpochAppKeys(): number {
    return this.#unknownEpochAppKeys
  }

  get undecryptableCredentials(): number {
    return this.#undecryptableCredentials
  }

  get unknownEpochCredentials(): number {
    return this.#unknownEpochCredentials
  }

  get unknownEpochHistory(): number {
    return this.#unknownEpochHistory
  }

  get noEpochKeyCredentials(): number {
    return this.#noEpochKeyCredentials
  }

  async purgeUndecryptableCredentials(): Promise<number> {
    // A fresh scan collects the current undecryptable resource ids. Only that
    // bucket is deleted: unknown-epoch resources and resources this wallet
    // holds no key for stay on the server.
    await this.#loadCredentialEntries()
    for (const resourceId of this.#undecryptableCredentialRowIds) {
      await this.#remote.deleteSyncedResource({
        logicalKey: 'privateCredentials',
        resourceId
      })
    }
    const removed = this.#undecryptableCredentialRowIds.length
    this.#undecryptableCredentialRowIds = []
    this.#undecryptableCredentials = 0
    return removed
  }

  async addHistoryItem({
    activity
  }: {
    resourceId: string
    activity: WalletActivity
  }): Promise<void> {
    // The caller's `resourceId` lives on only as the activity's own `id` inside
    // the encrypted document (mirroring the local store); the row is keyed by
    // the cipher's content-derived envelope-hash id.
    const cipher = this.#cipherFor('walletActivity')
    const { id, envelope, epoch } = await cipher.encrypt({
      data: activity as Json
    })
    await this.#remote.putSyncedResource({
      logicalKey: 'walletActivity',
      resourceId: id,
      body: envelope,
      epoch
    })
  }

  async listHistoryItems(): Promise<
    Array<{ id: string; doc: WalletActivity }>
  > {
    const cipher = this.#cipherFor('walletActivity')
    const resources = await this.#remote.listSyncedResources({
      logicalKey: 'walletActivity'
    })
    const bodies = await Promise.all(
      resources.map(({ id }) =>
        this.#remote.getSyncedResource({
          logicalKey: 'walletActivity',
          resourceId: id
        })
      )
    )
    const seen = new Set<string>()
    const items: Array<{ id: string; doc: WalletActivity }> = []
    let unknownEpoch = 0
    // Same shape as the credential scan: decrypt in parallel, fold in order.
    const decrypted = await Promise.all(
      bodies.map(async data => {
        if (data === undefined || !isEncryptedEnvelope(data)) {
          return { activity: data as unknown as WalletActivity | undefined }
        }
        try {
          return {
            activity: (await cipher.decrypt({
              envelope: data
            })) as unknown as WalletActivity
          }
        } catch (err) {
          return { err }
        }
      })
    )
    for (let position = 0; position < resources.length; position++) {
      const { id: resourceId } = resources[position]
      const { activity, err } = decrypted[position]
      if (err) {
        if (err instanceof UnknownEpochError) {
          unknownEpoch += 1
          continue
        }
        if (err instanceof KeyUnwrapError) {
          // Not a recipient of this resource's key epoch: skip it, and keep it
          // out of the refresh signal -- a descriptor refresh cannot help.
          console.warn(
            `Skipping remote wallet-activity resource "${resourceId}": this ` +
              `wallet is not a recipient of its key epoch:`,
            err
          )
          continue
        }
        console.warn(
          `Skipping undecryptable remote wallet-activity resource ` +
            `"${resourceId}":`,
          err
        )
        continue
      }
      if (activity === undefined) {
        continue
      }
      const id = activity.id ?? resourceId
      if (seen.has(id)) {
        continue
      }
      seen.add(id)
      items.push({ id, doc: activity })
    }
    this.#unknownEpochHistory = unknownEpoch
    return items
  }

  async addPublicCredential({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }): Promise<void> {
    // `public-credentials` is plaintext (public data), keyed directly by cid.
    await this.#remote.putSyncedResource({
      logicalKey: 'publicCredentials',
      resourceId: cid,
      body: credential as unknown as Json
    })
  }

  async removePublicCredential({ cid }: { cid: string }): Promise<void> {
    await this.#remote.deleteSyncedResource({
      logicalKey: 'publicCredentials',
      resourceId: cid
    })
  }

  async hasPublicCredential({ cid }: { cid: string }): Promise<boolean> {
    const data = await this.#remote.getSyncedResource({
      logicalKey: 'publicCredentials',
      resourceId: cid
    })
    return data !== undefined
  }

  /**
   * Rejects a contact operation: contacts are not reachable in the CHAPI popup
   * (neither flow manages them), so this backend refuses rather than silently
   * operating on the empty partitioned IndexedDB.
   *
   * @returns {never}
   */
  #contactsUnsupported(): never {
    throw new Error(
      'Contacts are not available in the remote-direct popup storage backend.'
    )
  }

  async listContacts(): Promise<Array<StoredContact>> {
    return this.#contactsUnsupported()
  }

  async loadContact(): Promise<StoredContact | undefined> {
    return this.#contactsUnsupported()
  }

  async addContact(): Promise<StoredContact> {
    return this.#contactsUnsupported()
  }

  async updateContact(): Promise<StoredContact> {
    return this.#contactsUnsupported()
  }

  async deleteContact(): Promise<void> {
    return this.#contactsUnsupported()
  }

  async addContactRevision(): Promise<void> {
    return this.#contactsUnsupported()
  }

  async listContactRevisions(): Promise<Array<ContactRevisionPayload>> {
    return this.#contactsUnsupported()
  }

  setCiphers(ciphers: Record<string, DocCipher>): void {
    this.#ciphers = ciphers
    // A wider cipher set can reveal rows the last scan skipped as unknown-epoch,
    // so the session cache is no longer known-complete; force the next read to
    // rescan.
    this.#credentialsLoaded = false
  }
}
