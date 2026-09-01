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
 * Contacts (and their revisions) are served remote-direct too: the head rows
 * ride the mutable `contacts` collection (stable row ids, `If-Match`
 * compare-and-swap on update/delete with a bounded re-read retry, so a lost
 * race against a concurrent writer re-applies on the fresh head instead of
 * silently clobbering it), and revisions are direct content-addressed appends
 * to `contacts-history` -- both byte-identical to what background replication
 * would have pushed, so local replicas pull transient contact edits cleanly.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import {
  upgradeContactHeadPayload,
  upgradeContactRevisionPayload,
  type ContactData,
  type ContactHeadPayload,
  type ContactRevisionPayload
} from '@interop/social-core'
import { cidFrom, errorStatus } from '@interop/was-client/sync'
import { compareContactRevisionsNewestFirst } from '@/lib/contactRevisions'
import type { Json } from '@/lib/sync'
import { isEncryptedEnvelope, type DocCipher } from '@interop/was-client/edv'
import { isUnknownEpochError } from '@interop/wallet-core/sync'
import { isKeyUnwrapError } from '@interop/wallet-core/descriptors'
import { uuidv7 } from 'uuidv7'
import type { StoredCredential } from '@/types/credential'
import type { StoredContact } from '@/types/contact'
import type { WalletActivity } from '@/stores/storageManager'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:storage:direct')

/**
 * How many times a contacts head compare-and-swap (update or delete) tries in
 * total: each `412` re-reads the fresh head and re-applies the edit on it;
 * exhausting the attempts throws the final `412`.
 */
const CONTACT_CAS_ATTEMPTS = 3

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
  readonly noEpochKeyAppKeys: number
  readonly undecryptableAppKeys: number
  purgeUndecryptableAppKeys(): Promise<number>
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
  listPublicCredentials(): Promise<Array<StoredCredential>>
  readonly unknownEpochContacts: number
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
  // The contacts scan's counterpart of the credential counter above.
  #unknownEpochContacts = 0
  #noEpochKeyAppKeys = 0
  #undecryptableAppKeys = 0
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
  // The same list for the most recent app-key scan, so
  // `purgeUndecryptableAppKeys` can remove those resources without a second
  // scan.
  #undecryptableAppKeyRowIds: string[] = []

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
        if (isUnknownEpochError(err)) {
          // Possibly-fresh data behind a stale descriptor: skip it so a descriptor
          // refresh can pick it up, never purge it.
          log.warn('Skipping unknown-epoch remote resource', {
            logicalKey,
            resourceId,
            err
          })
          unknownEpoch += 1
        } else if (isKeyUnwrapError(err)) {
          // This wallet is not a recipient of the resource's key epoch: skip it,
          // but never purge it -- a purge here would delete it from the server.
          log.warn(
            'Skipping remote resource: this wallet is not a recipient of its ' +
              'key epoch',
            { logicalKey, resourceId, err }
          )
          noEpochKey += 1
        } else {
          // One undecryptable remote row must not brick the whole popup list.
          log.warn('Skipping undecryptable remote resource', {
            logicalKey,
            resourceId,
            err
          })
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
    const { entries, undecryptableRowIds, unknownEpoch, noEpochKey } =
      await this.#scanContentCollection({
        logicalKey: 'appConnections'
      })
    this.#unknownEpochAppKeys = unknownEpoch
    this.#noEpochKeyAppKeys = noEpochKey
    this.#undecryptableAppKeyRowIds = undecryptableRowIds
    this.#undecryptableAppKeys = undecryptableRowIds.length
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

  get noEpochKeyAppKeys(): number {
    return this.#noEpochKeyAppKeys
  }

  get undecryptableAppKeys(): number {
    return this.#undecryptableAppKeys
  }

  /**
   * Removes the remote `app-connections` resources whose envelopes will not
   * decrypt at all, from the most recent scan. Only that bucket is deleted:
   * unknown-epoch resources and resources this wallet holds no key for are an
   * app's real identity and stay on the server.
   *
   * @returns {Promise<number>}
   */
  async purgeUndecryptableAppKeys(): Promise<number> {
    // A fresh scan collects the current undecryptable resource ids.
    await this.listAppKeys()
    for (const resourceId of this.#undecryptableAppKeyRowIds) {
      await this.#remote.deleteSyncedResource({
        logicalKey: 'appConnections',
        resourceId
      })
    }
    const removed = this.#undecryptableAppKeyRowIds.length
    this.#undecryptableAppKeyRowIds = []
    this.#undecryptableAppKeys = 0
    return removed
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
        if (isUnknownEpochError(err)) {
          unknownEpoch += 1
          continue
        }
        if (isKeyUnwrapError(err)) {
          // Not a recipient of this resource's key epoch: skip it, and keep it
          // out of the refresh signal -- a descriptor refresh cannot help.
          log.warn(
            'Skipping remote wallet-activity resource: this wallet is not a ' +
              'recipient of its key epoch',
            { resourceId, err }
          )
          continue
        }
        log.warn('Skipping undecryptable remote wallet-activity resource', {
          resourceId,
          err
        })
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
   * Lists the remote `public-credentials` collection's resources. The
   * collection is plaintext and keyed by the credential's content cid, so each
   * resource id IS the cid and each body IS the credential; a resource that
   * has gone away between the listing and its read is skipped.
   *
   * @returns {Promise<Array<StoredCredential>>}
   */
  async listPublicCredentials(): Promise<Array<StoredCredential>> {
    const resources = await this.#remote.listSyncedResources({
      logicalKey: 'publicCredentials'
    })
    const bodies = await Promise.all(
      resources.map(({ id }) =>
        this.#remote.getSyncedResource({
          logicalKey: 'publicCredentials',
          resourceId: id
        })
      )
    )
    const credentials: StoredCredential[] = []
    resources.forEach(({ id }, index) => {
      const body = bodies[index]
      if (body === undefined) {
        return
      }
      credentials.push({
        cid: id,
        vc: body as unknown as IVerifiableCredential
      })
    })
    return credentials
  }

  get unknownEpochContacts(): number {
    return this.#unknownEpochContacts
  }

  /**
   * Decrypts one remote `contacts` row body to its head payload, mirroring
   * the local store's per-row tolerance: a plaintext (legacy) body passes
   * through, an unknown-epoch row is reported apart (a descriptor refresh may
   * pick it up), and any other decrypt failure -- a no-epoch-key row
   * included -- is reported as unreadable. Every readable head passes through
   * the idempotent `upgradeContactHeadPayload` read-side upgrade.
   *
   * @param options {object}
   * @param options.data {Json | undefined}   the raw stored body
   * @returns {Promise<{ head?: ContactHeadPayload; unknownEpoch?: boolean;
   *   err?: unknown }>}
   */
  async #decryptContactHead({ data }: { data: Json | undefined }): Promise<{
    head?: ContactHeadPayload
    unknownEpoch?: boolean
    err?: unknown
  }> {
    if (data === undefined) {
      return {}
    }
    if (!isEncryptedEnvelope(data)) {
      return {
        head: upgradeContactHeadPayload(data as unknown as ContactHeadPayload)
      }
    }
    const cipher = this.#cipherFor('contacts')
    try {
      const raw = await cipher.decrypt({ envelope: data })
      return {
        head: upgradeContactHeadPayload(raw as unknown as ContactHeadPayload)
      }
    } catch (err) {
      if (isUnknownEpochError(err)) {
        return { unknownEpoch: true, err }
      }
      return { err }
    }
  }

  /**
   * Lists the remote `contacts` collection, decrypting each head row with the
   * local store's tolerance (an unknown-epoch row is skipped and counted for
   * the facade's descriptor refresh; an unreadable row is warned and skipped),
   * and mapping each readable head to a {@link StoredContact} with the same
   * legacy `contactId ?? rowId` fallback the local reads apply.
   *
   * @returns {Promise<Array<StoredContact>>}
   */
  async listContacts(): Promise<Array<StoredContact>> {
    const resources = await this.#remote.listSyncedResources({
      logicalKey: 'contacts'
    })
    const bodies = await Promise.all(
      resources.map(({ id }) =>
        this.#remote.getSyncedResource({
          logicalKey: 'contacts',
          resourceId: id
        })
      )
    )
    const decrypted = await Promise.all(
      bodies.map(data => this.#decryptContactHead({ data }))
    )
    const contacts: StoredContact[] = []
    let unknownEpoch = 0
    for (let position = 0; position < resources.length; position++) {
      const { id: rowId } = resources[position]
      const { head, unknownEpoch: isUnknownEpoch, err } = decrypted[position]
      if (err) {
        if (isUnknownEpoch) {
          // Possibly-fresh data behind a stale descriptor: skip it so a
          // descriptor refresh can pick it up.
          log.warn('Skipping unknown-epoch remote contacts row', { rowId, err })
          unknownEpoch += 1
        } else {
          log.warn('Skipping unreadable remote contacts row', { rowId, err })
        }
        continue
      }
      if (!head) {
        continue
      }
      contacts.push({
        id: rowId,
        // Legacy heads written before the row-id / contact-id split carry no
        // usable distinction; fall back to the row id for those.
        contactId: head.contactId ?? rowId,
        contact: head.contact,
        updatedAt: head.updatedAt
      })
    }
    this.#unknownEpochContacts = unknownEpoch
    return contacts
  }

  /**
   * Loads one contact by row id -- a single remote GET plus at most one
   * decrypt. Mirrors the scan's per-row tolerance: a missing row, or one
   * whose envelope will not decrypt under the current keys, resolves to
   * `undefined` exactly as the scan would have skipped it.
   *
   * @param options {object}
   * @param options.id {string}
   * @returns {Promise<StoredContact | undefined>}
   */
  async loadContact({
    id
  }: {
    id: string
  }): Promise<StoredContact | undefined> {
    const data = await this.#remote.getSyncedResource({
      logicalKey: 'contacts',
      resourceId: id
    })
    const { head, err } = await this.#decryptContactHead({ data })
    if (err) {
      log.warn('Skipping unreadable remote contacts row', { id, err })
      return undefined
    }
    if (!head) {
      return undefined
    }
    return {
      id,
      contactId: head.contactId ?? id,
      contact: head.contact,
      updatedAt: head.updatedAt
    }
  }

  /**
   * Adds a contact to the remote `contacts` collection under the cipher's
   * freshly minted stable row id (the collection spec's
   * `idDerivation: 'random'`), with the same head payload and epoch stamp the
   * local store's write would replicate -- so a local replica pulls this
   * transient add verbatim. Created with `If-None-Match: *`; the row id is
   * fresh randomness, so `created: false` normally cannot happen -- except
   * when the transport retried a PUT whose success response was lost (the
   * underlying http client retries idempotent methods), and the retry hit the
   * server's `412` on the row the first attempt already created. So a
   * not-created outcome re-reads the row: one that carries the contactId this
   * call just minted IS this call's own write and reports success; anything
   * else is a genuine collision and throws.
   *
   * @param options {object}
   * @param options.contact {ContactData}
   * @param options.writerId {string}
   * @returns {Promise<StoredContact>}
   */
  async addContact({
    contact,
    writerId
  }: {
    contact: ContactData
    writerId: string
  }): Promise<StoredContact> {
    const cipher = this.#cipherFor('contacts')
    const contactId = uuidv7()
    const updatedAt = new Date().toISOString()
    const head: ContactHeadPayload = {
      contactId,
      updatedAt,
      writerId,
      contact
    }
    const { id, envelope, epoch } = await cipher.encrypt({
      data: head as unknown as Json
    })
    const { created } = await this.#remote.putSyncedResource({
      logicalKey: 'contacts',
      resourceId: id,
      body: envelope,
      epoch
    })
    if (!created) {
      const found = await this.#remote.getSyncedResourceWithEtag({
        logicalKey: 'contacts',
        resourceId: id
      })
      const { head: storedHead } = found
        ? await this.#decryptContactHead({ data: found.data })
        : { head: undefined }
      if (storedHead?.contactId !== contactId) {
        throw new Error(`Remote "contacts" row "${id}" already exists.`)
      }
      // The transport's retried create: the stored row is this call's own
      // write, so the add succeeded.
    }
    return { id, contactId, contact, updatedAt }
  }

  /**
   * Rewrites a contact's remote head row in place under its existing id, as a
   * compare-and-swap on the ETag of the read the new head was built on, with
   * a bounded re-read retry: a `412` (a concurrent writer got there first)
   * re-reads the fresh head and re-applies this edit on it, matching the
   * replication driver's last-write-wins outcome (the fresh `updatedAt` wins)
   * without silently clobbering the concurrent write mid-flight. The logical
   * `contactId` sealed in the existing head is preserved verbatim. Throws
   * when the existing head is unreachable (missing row, undecryptable
   * envelope, no served ETag): rewriting it blind would sever the contact
   * from its history.
   *
   * @param options {object}
   * @param options.id {string}
   * @param options.contact {ContactData}
   * @param options.writerId {string}
   * @returns {Promise<StoredContact>}
   */
  async updateContact({
    id,
    contact,
    writerId
  }: {
    id: string
    contact: ContactData
    writerId: string
  }): Promise<StoredContact> {
    for (let attempt = 1; attempt <= CONTACT_CAS_ATTEMPTS; attempt++) {
      // Resolved per attempt: a descriptor refresh (`setCiphers`) racing a
      // retry must land on the freshly swapped cipher, never a stale capture.
      const cipher = this.#cipherFor('contacts')
      const found = await this.#remote.getSyncedResourceWithEtag({
        logicalKey: 'contacts',
        resourceId: id
      })
      if (!found) {
        throw new Error(`No remote "contacts" row "${id}" to update.`)
      }
      const { data, etag } = found
      if (etag === undefined) {
        // Fail closed rather than downgrading the compare-and-swap to an
        // unconditional overwrite (the registry writes' no-ETag rule).
        throw new Error(
          `Cannot update contact "${id}": the server served no ETag to ` +
            'compare-and-swap against.'
        )
      }
      const { head: existingHead, err } = await this.#decryptContactHead({
        data
      })
      if (err || !existingHead) {
        throw new Error(
          `Cannot update contact "${id}": its stored head is unreadable.`,
          { cause: err }
        )
      }
      const contactId = existingHead.contactId ?? id
      const updatedAt = new Date().toISOString()
      const head: ContactHeadPayload = {
        contactId,
        updatedAt,
        writerId,
        contact
      }
      // Re-encrypt in place through the cipher's update path when the prior
      // body is an envelope: it keeps the row's existing id verbatim and
      // advances the EDV `sequence` from the prior envelope. A plaintext
      // (legacy) prior row falls back to a fresh encrypt written under the
      // same row id -- `encryptUpdate` needs a prior envelope to advance from.
      let body: Json
      let epoch: string | undefined
      if (cipher.encryptUpdate && isEncryptedEnvelope(data)) {
        ;({ envelope: body, epoch } = await cipher.encryptUpdate({
          id,
          data: head as unknown as Json,
          current: data
        }))
      } else {
        ;({ envelope: body, epoch } = await cipher.encrypt({
          data: head as unknown as Json
        }))
      }
      try {
        await this.#remote.putSyncedResource({
          logicalKey: 'contacts',
          resourceId: id,
          body,
          epoch,
          ifMatch: etag
        })
        return { id, contactId, contact, updatedAt }
      } catch (casErr) {
        if (errorStatus(casErr) !== 412 || attempt === CONTACT_CAS_ATTEMPTS) {
          throw casErr
        }
        log.warn('Lost a contacts update race; re-reading the fresh head', {
          id,
          attempt,
          err: casErr
        })
      }
    }
    // Unreachable: every loop arm returns or throws.
    throw new Error(`Could not update contact "${id}".`)
  }

  /**
   * Hard-deletes a contact's remote head row (the server keeps a tombstone
   * its `changes` feed serves, so local replicas pull the removal), as a
   * compare-and-swap on the ETag of the read that decided the delete: a `412`
   * re-reads and retries (bounded), and a row already gone -- a `404`, or a
   * fresh read finding nothing -- counts as deleted. A read served without an
   * ETag fails closed rather than degrading to an unconditional delete (the
   * no-ETag rule the update path applies).
   *
   * @param options {object}
   * @param options.id {string}
   * @returns {Promise<void>}
   */
  async deleteContact({ id }: { id: string }): Promise<void> {
    for (let attempt = 1; attempt <= CONTACT_CAS_ATTEMPTS; attempt++) {
      const found = await this.#remote.getSyncedResourceWithEtag({
        logicalKey: 'contacts',
        resourceId: id
      })
      if (!found) {
        return
      }
      if (found.etag === undefined) {
        throw new Error(
          `Cannot delete contact "${id}": the server served no ETag to ` +
            'compare-and-swap against.'
        )
      }
      try {
        await this.#remote.deleteSyncedResource({
          logicalKey: 'contacts',
          resourceId: id,
          ifMatch: found.etag
        })
        return
      } catch (err) {
        if (errorStatus(err) !== 412 || attempt === CONTACT_CAS_ATTEMPTS) {
          throw err
        }
        log.warn('Lost a contacts delete race; re-reading the fresh head', {
          id,
          attempt,
          err
        })
      }
    }
  }

  /**
   * Appends one revision to the remote `contacts-history` collection --
   * content-addressed and append-only, exactly like `wallet-activity`, and
   * byte-identical to what background replication would have pushed. The
   * create is `If-None-Match: *`, so a re-append of the identical envelope
   * (the content-derived id collided) is an idempotent no-op.
   *
   * @param options {object}
   * @param options.revision {ContactRevisionPayload}
   * @returns {Promise<void>}
   */
  async addContactRevision({
    revision
  }: {
    revision: ContactRevisionPayload
  }): Promise<void> {
    const cipher = this.#cipherFor('contactsHistory')
    const { id, envelope, epoch } = await cipher.encrypt({
      data: revision as unknown as Json
    })
    await this.#remote.putSyncedResource({
      logicalKey: 'contactsHistory',
      resourceId: id,
      body: envelope,
      epoch
    })
  }

  /**
   * Lists a single contact's revision history, most recent first, ordered by
   * the logical `timestamp` each payload carries (`writerId` descending
   * breaks a tie) -- the shared {@link compareContactRevisionsNewestFirst}.
   * The remote-direct backend has no plaintext row-to-contact index (that is
   * a local-replica read accelerator), so every history row is fetched and
   * decrypted, filtered by its TRUE `contactId`, with the usual per-row
   * tolerance: an unknown-epoch, no-epoch-key, or otherwise unreadable row is
   * warned and skipped.
   *
   * @param options {object}
   * @param options.contactId {string}
   * @returns {Promise<Array<ContactRevisionPayload>>}
   */
  async listContactRevisions({
    contactId
  }: {
    contactId: string
  }): Promise<Array<ContactRevisionPayload>> {
    const cipher = this.#cipherFor('contactsHistory')
    const resources = await this.#remote.listSyncedResources({
      logicalKey: 'contactsHistory'
    })
    const bodies = await Promise.all(
      resources.map(({ id }) =>
        this.#remote.getSyncedResource({
          logicalKey: 'contactsHistory',
          resourceId: id
        })
      )
    )
    const decrypted = await Promise.all(
      bodies.map(async data => {
        if (data === undefined || !isEncryptedEnvelope(data)) {
          return { raw: data }
        }
        try {
          return { raw: await cipher.decrypt({ envelope: data }) }
        } catch (err) {
          return { err }
        }
      })
    )
    const revisions: ContactRevisionPayload[] = []
    for (let position = 0; position < resources.length; position++) {
      const { id: resourceId } = resources[position]
      const { raw, err } = decrypted[position]
      if (err) {
        log.warn('Skipping unreadable remote contacts-history row', {
          resourceId,
          err
        })
        continue
      }
      if (raw === undefined) {
        continue
      }
      const revision = upgradeContactRevisionPayload(
        raw as unknown as ContactRevisionPayload
      )
      if (revision.contactId === contactId) {
        revisions.push(revision)
      }
    }
    revisions.sort(compareContactRevisionsNewestFirst)
    return revisions
  }

  setCiphers(ciphers: Record<string, DocCipher>): void {
    this.#ciphers = ciphers
    // A wider cipher set can reveal rows the last scan skipped as unknown-epoch,
    // so the session cache is no longer known-complete; force the next read to
    // rescan.
    this.#credentialsLoaded = false
  }
}
