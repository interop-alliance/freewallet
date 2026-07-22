/**
 * The storage-backend seam every synced-collection read/write in
 * `StorageManager` routes through, plus the remote-direct implementation of it.
 *
 * `SyncedCollectionStore` is the port: the subset of storage operations that
 * target one of the wallet's standard synced collections (credentials, history,
 * public links, contacts). Two backends satisfy it and are selected ONCE at
 * `StorageManager` construction:
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
 * `If-None-Match: *`, stamped with the same `WAS-Key-Epoch`) and the main app's
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
 * The unknown-epoch counters and `setCiphers` are the marker-refresh contract:
 * after a read reports unknown-epoch rows the facade rebuilds the ciphers under
 * a freshly fetched marker, swaps them in via `setCiphers`, and re-reads.
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
  readonly undecryptableCredentials: number
  purgeUndecryptableCredentials(): Promise<number>
  readonly unknownEpochCredentials: number
  readonly unknownEpochHistory: number
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
    deviceId: string
  }): Promise<StoredContact>
  updateContact(options: {
    id: string
    contact: ContactData
    deviceId: string
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
   * The `private-credentials` cipher, or a clear error when it is absent (a
   * remote-direct session is always a passphrase session with vault keys, so
   * this is a misconfiguration guard rather than an expected path).
   *
   * @returns {DocCipher}
   */
  #privateCredentialsCipher(): DocCipher {
    const cipher = this.#ciphers.privateCredentials
    if (!cipher) {
      throw new Error(
        'Remote-direct credential storage requires the private-credentials ' +
          'cipher.'
      )
    }
    return cipher
  }

  /**
   * The `wallet-activity` cipher, or a clear error when it is absent.
   *
   * @returns {DocCipher}
   */
  #walletActivityCipher(): DocCipher {
    const cipher = this.#ciphers.walletActivity
    if (!cipher) {
      throw new Error(
        'Remote-direct history storage requires the wallet-activity cipher.'
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
   * Reads every resource of the remote `private-credentials` collection and
   * resolves each to its content cid + decrypted VC, mirroring
   * `BrowserStore.#credentialEntries` (decrypt envelope rows, pass legacy
   * plaintext rows through keyed by their resource id) and its tolerant
   * bucketing: a row whose envelope will not decrypt under the current KAK is
   * counted undecryptable (purgeable), a row naming an unknown key epoch is
   * counted separately so a marker refresh can pick it up. Rebuilds the session
   * cache and the cid index. The per-resource GETs run in parallel.
   *
   * @returns {Promise<void>}
   */
  async #loadCredentialEntries(): Promise<void> {
    const cipher = this.#privateCredentialsCipher()
    const resources = await this.#remote.listSyncedResources({
      logicalKey: 'privateCredentials'
    })
    const bodies = await Promise.all(
      resources.map(({ id }) =>
        this.#remote.getSyncedResource({
          logicalKey: 'privateCredentials',
          resourceId: id
        })
      )
    )
    const entries: Array<{
      resourceId: string
      cid: string
      vc: IVerifiableCredential
    }> = []
    const index = new Map<string, Set<string>>()
    const undecryptableRowIds: string[] = []
    let unknownEpoch = 0
    for (let position = 0; position < resources.length; position++) {
      const data = bodies[position]
      if (data === undefined) {
        continue
      }
      const { id: resourceId } = resources[position]
      if (isEncryptedEnvelope(data)) {
        try {
          const vc = (await cipher.decrypt({
            envelope: data
          })) as unknown as IVerifiableCredential
          const cid = await cidFrom({ doc: vc })
          this.#indexCredential({ index, cid, resourceId })
          entries.push({ resourceId, cid, vc })
        } catch (err) {
          if (err instanceof UnknownEpochError) {
            // Possibly-fresh data behind a stale marker: skip it so a marker
            // refresh can pick it up, never purge it.
            console.warn(
              `Skipping unknown-epoch remote private-credentials resource ` +
                `"${resourceId}":`,
              err
            )
            unknownEpoch += 1
          } else {
            // One undecryptable remote row must not brick the whole popup list.
            console.warn(
              `Skipping undecryptable remote private-credentials resource ` +
                `"${resourceId}":`,
              err
            )
            undecryptableRowIds.push(resourceId)
          }
        }
      } else {
        const vc = data as unknown as IVerifiableCredential
        this.#indexCredential({ index, cid: resourceId, resourceId })
        entries.push({ resourceId, cid: resourceId, vc })
      }
    }
    this.#credentialEntries = entries
    this.#credentialCidIndex = index
    this.#undecryptableCredentialRowIds = undecryptableRowIds
    this.#undecryptableCredentials = undecryptableRowIds.length
    this.#unknownEpochCredentials = unknownEpoch
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
    const cipher = this.#privateCredentialsCipher()
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

  get undecryptableCredentials(): number {
    return this.#undecryptableCredentials
  }

  get unknownEpochCredentials(): number {
    return this.#unknownEpochCredentials
  }

  get unknownEpochHistory(): number {
    return this.#unknownEpochHistory
  }

  async purgeUndecryptableCredentials(): Promise<number> {
    // A fresh scan collects the current undecryptable resource ids.
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
    const cipher = this.#walletActivityCipher()
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
    const cipher = this.#walletActivityCipher()
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
    for (let position = 0; position < resources.length; position++) {
      const data = bodies[position]
      if (data === undefined) {
        continue
      }
      const { id: resourceId } = resources[position]
      let activity: WalletActivity
      if (isEncryptedEnvelope(data)) {
        try {
          activity = (await cipher.decrypt({
            envelope: data
          })) as unknown as WalletActivity
        } catch (err) {
          if (err instanceof UnknownEpochError) {
            unknownEpoch += 1
            continue
          }
          console.warn(
            `Skipping undecryptable remote wallet-activity resource ` +
              `"${resourceId}":`,
            err
          )
          continue
        }
      } else {
        activity = data as unknown as WalletActivity
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
