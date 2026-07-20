/**
 * BrowserStore: the wallet's always-on local storage backend -- the ACTIVE
 * replica. Owns one RxDB (Dexie/IndexedDB) database per user holding every
 * standard wallet collection (`private-credentials`, `public-credentials`,
 * `wallet-activity`) on the generic synced-doc schema
 * (`{ id, updatedAt, version, data }`). All page reads and writes land here,
 * online or offline, guest or not; when a remote WAS Space is configured, the
 * sync controller replicates these same RxDB collections to it in the
 * background (see `src/stores/syncController.ts`).
 *
 * Encrypted collections (`private-credentials`, `wallet-activity`) store EDV
 * envelopes, not plaintext: a per-collection {@link DocCipher} (injected at
 * init) encrypts on write -- minting the content-derived envelope-hash id that
 * keys the row on every replica -- and decrypts on read. Because JWE
 * encryption is nondeterministic, the same document encrypts to a fresh id
 * each time, so writes dedupe by the document's content identity (the
 * credential `cid`, the activity `id`) rather than by row id, and reads
 * collapse any duplicate rows the same way.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import {
  createRxDatabase,
  type RxCollection,
  type RxDatabase,
  type RxStorage
} from 'rxdb/plugins/core'
import { getRxStorageDexie } from 'rxdb/plugins/storage-dexie'
import type { User } from '@/types/auth'
import { WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import { bufferToBase64Url, cidFrom, digestHash } from '@/lib/cidFrom'
import {
  syncedDocMigrationStrategies,
  syncedDocSchema,
  type Json,
  type SyncedDoc
} from '@/lib/sync'
import {
  isEncryptedEnvelope,
  UnknownEpochError,
  type DocCipher
} from '@/stores/edvDocCipher'
import type { StoredCredential } from '@/types/credential'
import type { WalletActivity } from '@/stores/storageManager'

/**
 * The local active replica of the wallet's standard collections, stored in
 * IndexedDB via RxDB/Dexie. Documents use the same synced-doc shape the
 * replication adapter moves over the wire, so a local write is directly
 * pushable and a pulled remote change is directly readable.
 */
export class BrowserStore {
  public dbPrefix: string
  public db?: RxDatabase
  private _collections?: Record<string, RxCollection<SyncedDoc>>
  private _storage: RxStorage<unknown, unknown>
  private _ciphers?: Record<string, DocCipher>
  // Count of rows the most recent list read had to skip because their envelope
  // would not decrypt under the current vault KAK (corrupted, replicated
  // verbatim from another identity, or written under a mismatched KAK). A
  // locked vault -- no cipher at all -- is a different, fail-closed case and is
  // not counted here. Surfaced so the pages can warn the user without any one
  // bad row bricking the whole list.
  private _undecryptableCredentials = 0
  private _undecryptableHistory = 0
  // Count of rows the most recent list read had to skip because their envelope
  // named a key epoch this instance's cipher does not know
  // (UnknownEpochError). Unlike the undecryptable rows above, these are not
  // purgeable garbage: the row is likely fresh data written under an epoch the
  // cached Collection Description has not caught up to (a rekey emits no change
  // feed entry). They are counted separately, skipped, and NOT cached, so a
  // caller can refresh the marker and re-read.
  private _unknownEpochCredentials = 0
  private _unknownEpochHistory = 0
  // Session-lifetime decrypt caches, keyed by RxDB row id. Every credential
  // operation (list, load-one, delete, add's dedupe scan) otherwise re-decrypts
  // the whole collection and re-derives `cidFrom` per row; these memoize the
  // decrypted content identity so a row is decrypted at most once per session.
  // The key is safe: a row id is the content-derived hash of the JWE
  // ciphertext, so it maps to exactly one plaintext under ANY cipher that can
  // decrypt it -- an envelope's content, and therefore its content-derived id,
  // is fixed once written. `setCiphers` may swap the injected ciphers (after a
  // marker refresh or a share), but that only widens which rows decrypt; it
  // never changes the plaintext a given row id yields, so the cached entries
  // stay valid across a swap. Entries are dropped when their row is removed and
  // both caches are cleared on teardown; an insert needs no invalidation
  // because a new envelope always carries a fresh, previously-unseen id.
  private _credentialCache = new Map<
    string,
    { cid: string; vc: IVerifiableCredential }
  >()
  private _historyCache = new Map<string, WalletActivity>()

  constructor({
    dbPrefix,
    storage,
    ciphers
  }: {
    dbPrefix: string
    // Injectable for tests (memory storage); defaults to Dexie/IndexedDB.
    storage?: RxStorage<unknown, unknown>
    // Per-collection document ciphers, keyed by logical key (e.g.
    // 'privateCredentials'). A collection with a cipher stores EDV envelopes;
    // one without stores plaintext.
    ciphers?: Record<string, DocCipher>
  }) {
    this.dbPrefix = dbPrefix
    this._storage = storage ?? getRxStorageDexie()
    this._ciphers = ciphers
  }

  /**
   * @param user {User}
   * @param [storage] {RxStorage<unknown, unknown>}
   * @param [ciphers] {Record<string, DocCipher>}
   * @see https://rxdb.info/rx-storage-dexie.html
   */
  static async initClient({
    user,
    storage,
    ciphers
  }: {
    user: User
    storage?: RxStorage<unknown, unknown>
    ciphers?: Record<string, DocCipher>
  }) {
    // Local DBs will have a prefix of <hash of user.id>
    const dbPrefix = bufferToBase64Url(await digestHash(user.id))

    const localStore = new BrowserStore({ dbPrefix, storage, ciphers })
    return { localStore }
  }

  /**
   * Whether this user already has a local wallet database in this browser.
   *
   * @returns {Promise<boolean>}
   */
  async userExists(): Promise<boolean> {
    const databases = await indexedDB.databases()
    return databases.some(db => db.name!.includes(this.dbPrefix))
  }

  /**
   * Opens (or creates) the user's wallet database and its standard
   * collections. `addCollections` is idempotent, so this is safe to call on
   * every login.
   *
   * @param user {User}
   * @returns {Promise<void>}
   */
  async ensureUserCollections({ user }: { user: User }) {
    const db = await createRxDatabase({
      name: `${this.dbPrefix}-wallet-db`,
      storage: this._storage,
      closeDuplicates: true,
      // Single-tab for the MVP: with `multiInstance` RxDB gates replication on
      // `waitForLeadership()`, which needs the leader-election plugin. Multi-tab
      // (elect one replicating tab) is deferred, so disable it and replicate in
      // this tab directly.
      multiInstance: false
    })
    // One local collection per standard wallet collection, all on the generic
    // synced-doc schema.
    const collectionsConfig = Object.fromEntries(
      WALLET_STANDARD_COLLECTIONS.map(({ key }) => [
        key,
        {
          schema: syncedDocSchema(),
          migrationStrategies: syncedDocMigrationStrategies()
        }
      ])
    )
    this._collections = (await db.addCollections(
      collectionsConfig
    )) as unknown as Record<string, RxCollection<SyncedDoc>>
    this.db = db
    console.log('Initialized local wallet collections for user:', user.id)
  }

  /**
   * Returns the live RxDB collection for one of the wallet's standard logical
   * collections. Used by the pages (via StorageManager) for reads/writes and
   * by the sync controller as the local end of replication.
   *
   * @param logicalKey {string} e.g. 'privateCredentials' | 'walletActivity'.
   * @returns {RxCollection<SyncedDoc>}
   */
  rxCollection(logicalKey: string): RxCollection<SyncedDoc> {
    const collection = this._collections?.[logicalKey]
    if (!collection) {
      throw new Error(
        `Local collection "${logicalKey}" is not initialized. ` +
          'Call ensureUserCollections() first.'
      )
    }
    return collection
  }

  /**
   * Inserts a synced-doc row if absent (or previously deleted). Local writes
   * stamp `updatedAt` so new rows sort into the change feed; `version` is
   * server-authoritative and unknown until a pull, so `0` is the local
   * placeholder (the replication create path sends `If-None-Match: *`, not
   * this value).
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.id {string}
   * @param options.data {Json}
   * @param [options.epoch] {string}   the key-epoch id the envelope was
   *   encrypted under, stored on the row so the sync layer can push it as the
   *   `WAS-Key-Epoch` header; absent for a plaintext or pre-epoch write
   * @returns {Promise<void>}
   */
  private async _insertDoc({
    logicalKey,
    id,
    data,
    epoch
  }: {
    logicalKey: string
    id: string
    data: Json
    epoch?: string
  }) {
    await this.rxCollection(logicalKey).insertIfNotExists({
      id,
      updatedAt: new Date().toISOString(),
      version: 0,
      ...(epoch !== undefined && { epoch }),
      data
    })
  }

  /**
   * The count of `private-credentials` rows the most recent
   * {@link listCredentials} call had to skip because their envelope would not
   * decrypt under the current vault KAK. Zero when the vault is locked (that
   * path returns nothing rather than attempting to decrypt).
   *
   * @returns {number}
   */
  get undecryptableCredentials(): number {
    return this._undecryptableCredentials
  }

  /**
   * The count of `wallet-activity` rows the most recent
   * {@link listHistoryItems} call had to skip for the same reason.
   *
   * @returns {number}
   */
  get undecryptableHistory(): number {
    return this._undecryptableHistory
  }

  /**
   * The count of `private-credentials` rows the most recent
   * {@link listCredentials} call had to skip because their envelope named a key
   * epoch this instance's cipher does not know (its cached Collection
   * Description is likely stale). Unlike {@link undecryptableCredentials} these
   * rows are not purged -- a caller refreshes the marker, rebuilds the cipher
   * via {@link setCiphers}, and re-reads.
   *
   * @returns {number}
   */
  get unknownEpochCredentials(): number {
    return this._unknownEpochCredentials
  }

  /**
   * The count of `wallet-activity` rows the most recent
   * {@link listHistoryItems} call had to skip for the same reason.
   *
   * @returns {number}
   */
  get unknownEpochHistory(): number {
    return this._unknownEpochHistory
  }

  /**
   * Swaps the injected per-collection document ciphers -- used after a
   * Collection Description marker refresh or a share/unshare rebuilds the
   * ciphers under a new key epoch. The decrypt caches are deliberately kept:
   * a row id is the content-derived hash of its envelope, so it maps to exactly
   * one plaintext under any cipher that can decrypt it; a wider cipher set only
   * decrypts more rows, never remaps an already-cached one.
   *
   * @param ciphers {Record<string, DocCipher>}
   * @returns {void}
   */
  setCiphers(ciphers: Record<string, DocCipher>): void {
    this._ciphers = ciphers
  }

  /**
   * Reads every live `private-credentials` row, oldest first, decrypting
   * envelope rows and passing legacy plaintext rows through. Each entry keeps
   * its RxDB row id (the write/delete key) alongside the credential's content
   * cid (the page-facing key): for an envelope row the cid is recomputed from
   * the decrypted VC, for a plaintext row it IS the row id.
   *
   * A single row whose envelope does not decrypt under the current KAK
   * (corrupted, replicated verbatim from another identity, or written under a
   * mismatched KAK) is skipped -- logged and collected in `undecryptableRowIds`
   * -- rather than rejecting the whole read, so one poisoned row cannot brick
   * list/load/add/delete. The row id is returned so a caller can still target
   * (and remove) it even though its content cid is unknowable.
   *
   * A row whose envelope names an UNKNOWN key epoch (its cached marker is
   * likely stale, `UnknownEpochError`) is collected separately in
   * `unknownEpochRowIds` and NOT cached: it is possibly-fresh data behind a
   * stale marker, not purgeable garbage, so a caller can refresh the marker and
   * re-read rather than deleting it.
   *
   * @returns {Promise<{ entries: Array<{ rowId: string; cid: string;
   *   vc: IVerifiableCredential }>; undecryptableRowIds: string[];
   *   unknownEpochRowIds: string[] }>}
   */
  private async _credentialEntries(): Promise<{
    entries: Array<{ rowId: string; cid: string; vc: IVerifiableCredential }>
    undecryptableRowIds: string[]
    unknownEpochRowIds: string[]
  }> {
    const docs = await this.rxCollection('privateCredentials')
      .find({ sort: [{ updatedAt: 'asc' }] })
      .exec()
    const cipher = this._ciphers?.privateCredentials
    const entries = []
    const undecryptableRowIds: string[] = []
    const unknownEpochRowIds: string[] = []
    for (const doc of docs) {
      const { id, data } = doc.toMutableJSON()
      if (cipher && isEncryptedEnvelope(data)) {
        const cached = this._credentialCache.get(id)
        if (cached) {
          entries.push({ rowId: id, cid: cached.cid, vc: cached.vc })
          continue
        }
        try {
          const vc = (await cipher.decrypt({
            envelope: data!
          })) as unknown as IVerifiableCredential
          const cid = await cidFrom({ doc: vc })
          this._credentialCache.set(id, { cid, vc })
          entries.push({ rowId: id, cid, vc })
        } catch (err) {
          if (err instanceof UnknownEpochError) {
            // Possibly-fresh data behind a stale marker: skip it (uncached) so
            // a marker refresh can pick it up, never purge it.
            console.warn(
              `Skipping unknown-epoch private-credentials row "${id}":`,
              err
            )
            unknownEpochRowIds.push(id)
          } else {
            console.warn(
              `Skipping undecryptable private-credentials row "${id}":`,
              err
            )
            undecryptableRowIds.push(id)
          }
        }
      } else {
        entries.push({
          rowId: id,
          cid: id,
          vc: data as unknown as IVerifiableCredential
        })
      }
    }
    return { entries, undecryptableRowIds, unknownEpochRowIds }
  }

  /**
   * Adds a VC to the local `private-credentials` collection. On an encrypted
   * store the row is the credential's EDV envelope keyed by its
   * content-derived envelope-hash id; because encryption is nondeterministic,
   * idempotence is by the credential's content cid (a re-add of a stored
   * credential is a no-op), not by row id. Returns whether a row was actually
   * inserted (`false` when the credential was already present), so the caller
   * can gate credential-created history on a genuine insert.
   *
   * @param options {object}
   * @param options.cid {string}
   * @param options.credential {IVerifiableCredential}
   * @returns {Promise<boolean>}
   */
  async addCredential({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }): Promise<boolean> {
    const cipher = this._ciphers?.privateCredentials
    if (!cipher) {
      // Cipher-less (plaintext) store: the row is keyed by cid, so an existing
      // (live) row means an already-stored credential. Checking first derives
      // inserted-ness, since insertIfNotExists returns the conflicting doc.
      const existing = await this.rxCollection('privateCredentials')
        .findOne(cid)
        .exec()
      if (existing) {
        return false
      }
      await this._insertDoc({
        logicalKey: 'privateCredentials',
        id: cid,
        data: credential as unknown as Json
      })
      return true
    }
    const { entries } = await this._credentialEntries()
    if (entries.some(entry => entry.cid === cid)) {
      return false
    }
    const { id, envelope, epoch } = await cipher.encrypt({
      data: credential as unknown as Json
    })
    await this._insertDoc({
      logicalKey: 'privateCredentials',
      id,
      data: envelope,
      epoch
    })
    return true
  }

  /**
   * @param options {object}
   * @param options.cid {string}
   * @returns {Promise<IVerifiableCredential | undefined>}
   */
  async loadCredential({ cid }: { cid: string }) {
    const { entries } = await this._credentialEntries()
    return entries.find(entry => entry.cid === cid)?.vc
  }

  /**
   * Deletes a credential by content cid. Removes every row carrying that
   * credential (duplicate envelope rows for the same VC can exist, e.g. a
   * legacy random-id envelope replicated from remote alongside a re-keyed
   * local copy); each removal is a soft delete replication pushes as a
   * tombstone.
   *
   * @param options {object}
   * @param options.cid {string}
   * @returns {Promise<void>}
   */
  async deleteCredential({ cid }: { cid: string }) {
    const { entries } = await this._credentialEntries()
    for (const entry of entries) {
      if (entry.cid !== cid) {
        continue
      }
      await this.deleteCredentialByRowId({ rowId: entry.rowId })
    }
  }

  /**
   * Removes a single `private-credentials` row by its RxDB row id (a soft
   * delete replication pushes as a tombstone). Unlike {@link deleteCredential},
   * this needs no decryption, so it is the way to remove an undecryptable row
   * whose content cid cannot be recovered (see {@link undecryptableCredentials}
   * / {@link purgeUndecryptableCredentials}).
   *
   * @param options {object}
   * @param options.rowId {string}
   * @returns {Promise<void>}
   */
  async deleteCredentialByRowId({ rowId }: { rowId: string }) {
    const doc = await this.rxCollection('privateCredentials')
      .findOne(rowId)
      .exec()
    if (doc) {
      await doc.remove()
    }
    this._credentialCache.delete(rowId)
  }

  /**
   * Removes every `private-credentials` row whose envelope will not decrypt
   * under the current vault KAK, so a user can clear rows that can never be
   * shown (corrupted, or written under a mismatched KAK). Requires an unlocked
   * vault: with the vault locked there is no cipher and nothing is treated as
   * undecryptable (fail closed -- locked rows are left intact). Returns the
   * number of rows removed.
   *
   * @returns {Promise<number>}
   */
  async purgeUndecryptableCredentials(): Promise<number> {
    const { undecryptableRowIds } = await this._credentialEntries()
    for (const rowId of undecryptableRowIds) {
      await this.deleteCredentialByRowId({ rowId })
    }
    this._undecryptableCredentials = 0
    return undecryptableRowIds.length
  }

  /**
   * Lists the stored VCs, oldest first, collapsing duplicate rows that carry
   * the same credential (same content cid) to their oldest copy.
   *
   * @returns {Promise<Array<StoredCredential>>}
   */
  async listCredentials(): Promise<Array<StoredCredential>> {
    const { entries, undecryptableRowIds, unknownEpochRowIds } =
      await this._credentialEntries()
    this._undecryptableCredentials = undecryptableRowIds.length
    this._unknownEpochCredentials = unknownEpochRowIds.length
    const seen = new Set<string>()
    const credentials: StoredCredential[] = []
    for (const { cid, vc } of entries) {
      if (seen.has(cid)) {
        continue
      }
      seen.add(cid)
      credentials.push({ cid, vc })
    }
    return credentials
  }

  /**
   * Writes a credential's world-readable copy into the local
   * `public-credentials` collection, keyed by its content cid. The sync
   * controller replicates it to the remote WAS Collection in the background.
   *
   * @param options {object}
   * @param options.cid {string}
   * @param options.credential {IVerifiableCredential}
   * @returns {Promise<void>}
   */
  async addPublicCredential({
    cid,
    credential
  }: {
    cid: string
    credential: IVerifiableCredential
  }) {
    await this._insertDoc({
      logicalKey: 'publicCredentials',
      id: cid,
      data: credential as unknown as Json
    })
  }

  /**
   * Removes a credential's public copy (a soft delete; replication pushes the
   * tombstone to the remote Collection).
   *
   * @param options {object}
   * @param options.cid {string}
   * @returns {Promise<void>}
   */
  async removePublicCredential({ cid }: { cid: string }) {
    const doc = await this.rxCollection('publicCredentials').findOne(cid).exec()
    if (doc) {
      await doc.remove()
    }
  }

  /**
   * Whether a credential currently has a public copy in `public-credentials`.
   *
   * @param options {object}
   * @param options.cid {string}
   * @returns {Promise<boolean>}
   */
  async hasPublicCredential({ cid }: { cid: string }): Promise<boolean> {
    const doc = await this.rxCollection('publicCredentials').findOne(cid).exec()
    return doc !== null
  }

  /**
   * Appends an entry to the local `wallet-activity` log. On an encrypted
   * store the row is the activity's EDV envelope keyed by its content-derived
   * envelope-hash id; the caller's `resourceId` then lives on only as the
   * activity's own `id` inside the encrypted document.
   *
   * @param options {object}
   * @param options.resourceId {string}
   * @param options.activity {WalletActivity}
   * @returns {Promise<void>}
   */
  async addHistoryItem({
    resourceId,
    activity
  }: {
    resourceId: string
    activity: WalletActivity
  }) {
    const cipher = this._ciphers?.walletActivity
    if (!cipher) {
      await this._insertDoc({
        logicalKey: 'walletActivity',
        id: resourceId,
        data: activity as Json
      })
      return
    }
    const { id, envelope, epoch } = await cipher.encrypt({
      data: activity as Json
    })
    await this._insertDoc({
      logicalKey: 'walletActivity',
      id,
      data: envelope,
      epoch
    })
  }

  /**
   * Lists the `wallet-activity` log entries, oldest first, decrypting
   * envelope rows and passing legacy plaintext rows through. Each item's `id`
   * is the activity's own id (a uuid minted at record time); duplicate rows
   * carrying the same activity are collapsed to their oldest copy.
   *
   * A row whose envelope will not decrypt under the current KAK is skipped
   * (logged and counted in {@link undecryptableHistory}) rather than rejecting
   * the whole read, so one poisoned row cannot hang the history page.
   *
   * @returns {Promise<Array<{ id: string; doc: WalletActivity }>>}
   */
  async listHistoryItems(): Promise<
    Array<{ id: string; doc: WalletActivity }>
  > {
    const docs = await this.rxCollection('walletActivity')
      .find({ sort: [{ updatedAt: 'asc' }] })
      .exec()
    const cipher = this._ciphers?.walletActivity
    const seen = new Set<string>()
    const items: Array<{ id: string; doc: WalletActivity }> = []
    let undecryptable = 0
    let unknownEpoch = 0
    for (const rxDoc of docs) {
      const { id: rowId, data } = rxDoc.toMutableJSON()
      let activity: WalletActivity
      if (cipher && isEncryptedEnvelope(data)) {
        const cached = this._historyCache.get(rowId)
        if (cached) {
          activity = cached
        } else {
          try {
            activity = (await cipher.decrypt({
              envelope: data!
            })) as WalletActivity
          } catch (err) {
            if (err instanceof UnknownEpochError) {
              // Possibly-fresh data behind a stale marker: skip it (uncached)
              // for a marker refresh to pick up, do not treat as garbage.
              console.warn(
                `Skipping unknown-epoch wallet-activity row "${rowId}":`,
                err
              )
              unknownEpoch += 1
            } else {
              console.warn(
                `Skipping undecryptable wallet-activity row "${rowId}":`,
                err
              )
              undecryptable += 1
            }
            continue
          }
          this._historyCache.set(rowId, activity)
        }
      } else {
        activity = data as WalletActivity
      }
      const id = activity.id ?? rowId
      if (seen.has(id)) {
        continue
      }
      seen.add(id)
      items.push({ id, doc: activity })
    }
    this._undecryptableHistory = undecryptable
    this._unknownEpochHistory = unknownEpoch
    return items
  }

  /**
   * One-time local migration for the encrypted collections: re-keys plaintext
   * rows written before encrypted sync landed (when
   * `private-credentials` / `wallet-activity` were local-active but not yet
   * replicating) into EDV envelopes under their content-derived ids. Runs at
   * login before replication starts -- required, not just tidy: once a remote
   * collection carries its encryption marker, the server rejects a plaintext
   * content push (422), which would wedge the push cycle in retry.
   *
   * Only never-synced rows are touched (`version === 0`, the local
   * placeholder; a pulled row carries the server revision, >= 1) -- a legacy
   * plaintext row replicated down from a pre-marker remote collection is left
   * as-is and handled by the tolerant read paths. The re-keyed original is
   * soft-deleted; its pushed tombstone targets a resource that never existed
   * remotely, which the server treats as an idempotent no-op. The original's
   * `updatedAt` is preserved so log/list ordering survives the re-key.
   *
   * Runs at most once per user: after the first pass no never-synced plaintext
   * row can remain, so a persistent per-`dbPrefix` marker (localStorage, guarded
   * for the non-browser test/SSR environments) short-circuits the full-collection
   * scan that would otherwise materialize every encrypted row on every later
   * login and unlocked-vault restore.
   *
   * @returns {Promise<void>}
   */
  async migrateLocalPlaintextDocs() {
    const markerKey = `freewallet:plaintext-migrated:${this.dbPrefix}`
    const hasLocalStorage = typeof localStorage !== 'undefined'
    if (hasLocalStorage && localStorage.getItem(markerKey)) {
      return
    }
    for (const [logicalKey, cipher] of Object.entries(this._ciphers ?? {})) {
      const collection = this.rxCollection(logicalKey)
      const docs = await collection.find().exec()
      for (const doc of docs) {
        const { updatedAt, version, data } = doc.toMutableJSON()
        if (version !== 0 || data === undefined || isEncryptedEnvelope(data)) {
          continue
        }
        const { id, envelope, epoch } = await cipher.encrypt({ data })
        await collection.insertIfNotExists({
          id,
          updatedAt,
          version: 0,
          ...(epoch !== undefined && { epoch }),
          data: envelope
        })
        await doc.remove()
      }
    }
    if (hasLocalStorage) {
      localStorage.setItem(markerKey, new Date().toISOString())
    }
  }

  /**
   * One-time re-key of the `public-credentials` collection after the CID
   * formula fix. The pre-fix formula hashed the JSON-escaped canonical string
   * rather than the canonical JCS bytes, so a public credential's row id no
   * longer matches `cidFrom` of its body. Each mis-keyed row is re-inserted
   * under the recomputed cid (with its `updatedAt` preserved and `version` 0 so
   * it pushes as a create) and the old row is soft-deleted.
   *
   * Runs at login before replication starts, so the tombstone and the new row
   * both propagate to the remote collection. Unlike the plaintext migration
   * there is no `version` gate: pulled rows must be re-keyed too, so the remote
   * old-cid resource gets tombstoned. Idempotent by construction (a correctly
   * keyed row is skipped) and cheap (public rows are few and plaintext), so no
   * marker gating. Note that any public link already shared to an old-cid
   * resource stops resolving once its remote row is tombstoned.
   *
   * @returns {Promise<void>}
   */
  async migratePublicCredentialCids() {
    const collection = this.rxCollection('publicCredentials')
    const docs = await collection.find().exec()
    for (const doc of docs) {
      const { id, updatedAt, data } = doc.toMutableJSON()
      if (data === undefined) {
        continue
      }
      const cid = await cidFrom({ doc: data as object })
      if (cid === id) {
        continue
      }
      await collection.insertIfNotExists({
        id: cid,
        updatedAt,
        version: 0,
        data
      })
      await doc.remove()
    }
  }

  /**
   * Removes the wallet database and any legacy local databases carrying this
   * user's prefix (e.g. the pre-flip `-credentials-db` / `-sync-db`).
   *
   * @see https://rxdb.info/rx-database.html#remove
   * @returns {Promise<void>}
   */
  async wipeStorage() {
    this._credentialCache.clear()
    this._historyCache.clear()
    if (this.db) {
      await this.db.remove()
      this.db = undefined
      this._collections = undefined
    }
    // Guarded: absent under the memory storage used in unit tests.
    if (typeof indexedDB !== 'undefined') {
      const databases = await indexedDB.databases()
      await Promise.all(
        databases
          .filter(db => db.name!.includes(this.dbPrefix))
          .map(db => this._deleteDatabase(db.name!))
      )
    }
  }

  /**
   * Deletes a single IndexedDB database, resolving only once the request
   * settles so `wipeStorage` cannot report success while the database still
   * exists. `deleteDatabase` fires `onsuccess` on completion and `onerror` on
   * failure; both resolve here (errors are logged, not thrown, so one stuck
   * database does not abort the wipe of the others).
   *
   * `onblocked` fires when another tab still holds an open connection: the
   * request then stays pending and may never complete while that tab lives.
   * We deliberately do not wait for that -- blocking `wipeStorage` on a
   * sibling tab could hang logout / account deletion indefinitely. Instead we
   * log a warning and resolve; the deletion remains queued and completes once
   * the other connection closes.
   *
   * @param name {string}
   * @returns {Promise<void>}
   */
  private _deleteDatabase(name: string): Promise<void> {
    return new Promise<void>(resolve => {
      const request = indexedDB.deleteDatabase(name)
      request.onsuccess = () => resolve()
      request.onerror = () => {
        console.error(
          `Failed to delete IndexedDB database "${name}":`,
          request.error
        )
        resolve()
      }
      request.onblocked = () => {
        console.warn(
          `Deletion of IndexedDB database "${name}" is blocked by another ` +
            'open connection (e.g. a second tab); it will complete once that ' +
            'connection closes.'
        )
        resolve()
      }
    })
  }

  /**
   * Closes the database (without removing data). Called on logout.
   *
   * @returns {Promise<void>}
   */
  async close() {
    this._credentialCache.clear()
    this._historyCache.clear()
    if (this.db) {
      await this.db.close()
      this.db = undefined
      this._collections = undefined
    }
  }
}
