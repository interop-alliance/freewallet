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
import type {
  ContactHeadPayload,
  ContactRevisionPayload
} from '@interop/social-core'
import {
  upgradeContactHeadPayload,
  upgradeContactRevisionPayload
} from '@interop/social-core'
import {
  createRxDatabase,
  type RxCollection,
  type RxDatabase,
  type RxStorage
} from 'rxdb/plugins/core'
import { getRxStorageDexie } from 'rxdb/plugins/storage-dexie'
import { uuidv7 } from 'uuidv7'
import type { User } from '@/types/auth'
import { WALLET_STANDARD_COLLECTIONS } from '@/app.config'
import { cidFrom, deriveSpaceId } from '@interop/was-client/sync'
import {
  syncedDocMigrationStrategies,
  syncedDocSchema,
  type Json,
  type SyncedDoc
} from '@/lib/sync'
import { createContactsConflictHandler } from '@/stores/contactsConflictHandler'
import {
  isEncryptedEnvelope,
  UnknownEpochError,
  type DocCipher
} from '@interop/was-client/edv'
import type { StoredCredential } from '@/types/credential'
import type { StoredContact } from '@/types/contact'
import type { WalletActivity } from '@/stores/storageManager'

/**
 * The local-only projection index over the append-only `contacts-history`
 * collection: one row per history row, carrying just that row's id and the
 * `contactId` its (encrypted) revision belongs to. It exists so a single
 * contact's history can be read without decrypting every other contact's
 * revisions, and it never leaves this browser -- it is deliberately not a
 * `WALLET_STANDARD_COLLECTIONS` entry, so nothing replicates it and the wire
 * body stays an opaque EDV envelope.
 *
 * Privacy: the index stores only the opaque `contactId` uuid beside the row
 * id -- never any part of the decrypted snapshot -- so what it exposes at rest
 * locally is revision grouping and per-contact revision counts, nothing about
 * the contact itself.
 *
 * RxDB requires an explicit `maxLength` on every indexed string field.
 */
const contactsHistoryIndexSchema = {
  version: 0,
  primaryKey: 'id',
  type: 'object',
  properties: {
    id: { type: 'string', maxLength: 256 },
    contactId: { type: 'string', maxLength: 256 }
  },
  required: ['id', 'contactId'],
  indexes: ['contactId']
} as const

/**
 * Orders two contact revisions newest first by the LOGICAL timestamp their
 * payloads carry, not by the order the local rows happened to be written --
 * the same `ORDER BY timestamp DESC, writerId DESC` the mobile wallet applies
 * to its `contact_revisions` table, so a history replicated from another
 * writer reads identically in both wallets.
 *
 * Timestamps are compared as parsed instants, falling back to a lexical
 * comparison of the raw strings when either side is unparseable or the two
 * instants are equal -- ISO stamps minted by different writers differ in
 * fractional-second precision, so the raw strings are only a tiebreak, never
 * the primary key. Equal timestamps are broken by `writerId` descending, the
 * same "lexically greater writerId wins" convention as social-core's
 * `remotePayloadWins`.
 *
 * @param first {ContactRevisionPayload}
 * @param second {ContactRevisionPayload}
 * @returns {number}
 */
function compareContactRevisionsNewestFirst(
  first: ContactRevisionPayload,
  second: ContactRevisionPayload
): number {
  const firstInstant = Date.parse(first.timestamp ?? '')
  const secondInstant = Date.parse(second.timestamp ?? '')
  if (
    Number.isFinite(firstInstant) &&
    Number.isFinite(secondInstant) &&
    firstInstant !== secondInstant
  ) {
    return secondInstant - firstInstant
  }
  const firstStamp = first.timestamp ?? ''
  const secondStamp = second.timestamp ?? ''
  if (firstStamp !== secondStamp) {
    return firstStamp < secondStamp ? 1 : -1
  }
  const firstWriter = first.writerId ?? ''
  const secondWriter = second.writerId ?? ''
  if (firstWriter === secondWriter) {
    return 0
  }
  return firstWriter < secondWriter ? 1 : -1
}

/**
 * The local active replica of the wallet's standard collections, stored in
 * IndexedDB via RxDB/Dexie. Documents use the same synced-doc shape the
 * replication adapter moves over the wire, so a local write is directly
 * pushable and a pulled remote change is directly readable.
 */
export class BrowserStore {
  public dbPrefix: string
  public db?: RxDatabase
  #collections?: Record<string, RxCollection<SyncedDoc>>
  // The local-only `contacts-history` projection index (see
  // {@link contactsHistoryIndexSchema}). Held in its own member rather than in
  // `#collections`, which is typed to `SyncedDoc` and enumerates exactly the
  // collections that replicate.
  #contactsHistoryIndex?: RxCollection<{ id: string; contactId: string }>
  #storage: RxStorage<unknown, unknown>
  #ciphers?: Record<string, DocCipher>
  // Count of rows the most recent list read had to skip because their envelope
  // would not decrypt under the current vault KAK (corrupted, replicated
  // verbatim from another identity, or written under a mismatched KAK).
  // Surfaced so the pages can warn the user without any one bad row bricking
  // the whole list.
  #undecryptableCredentials = 0
  // Count of rows the most recent list read had to skip because their envelope
  // named a key epoch this instance's cipher does not know
  // (UnknownEpochError). Unlike the undecryptable rows above, these are not
  // purgeable garbage: the row is likely fresh data written under an epoch the
  // cached Collection Description has not caught up to (a rekey emits no change
  // feed entry). They are counted separately, skipped, and NOT cached, so a
  // caller can refresh the descriptor and re-read.
  #unknownEpochCredentials = 0
  #unknownEpochHistory = 0
  // Session-lifetime decrypt cache, keyed first by logical collection key and
  // then by RxDB row id, holding each envelope row's decrypted plaintext so a
  // row is decrypted at most once per session. Every read (list, load-one,
  // delete's collapse scan, add's dedupe) otherwise re-decrypts the whole
  // collection; this memoizes the plaintext. The key is safe: a row id is the
  // content-derived hash of the JWE ciphertext, so it maps to exactly one
  // plaintext under ANY cipher that can decrypt it -- an envelope's content, and
  // therefore its content-derived id, is fixed once written. `setCiphers` may
  // swap the injected ciphers (after a descriptor refresh or a share), but that only
  // widens which rows decrypt; it never changes the plaintext a given row id
  // yields, so the cached entries stay valid across a swap. Entries are dropped
  // when their row is removed and the cache is cleared on teardown; an insert
  // needs no invalidation because a new envelope always carries a fresh,
  // previously-unseen id.
  #decryptCache = new Map<string, Map<string, Json>>()
  // The content cid of each decrypted `private-credentials` envelope row, keyed
  // by row id, so `#credentialEntries` need not re-run `cidFrom` per read. Valid
  // across a `setCiphers` swap for the same reason as `#decryptCache` (a row id
  // maps to one plaintext, hence one cid); dropped with its row.
  #credentialCidByRow = new Map<string, string>()
  // In-memory content cid -> live-row-ids index over the encrypted
  // `private-credentials` collection: the authority `addCredential` consults to
  // stay idempotent by content cid without a full decrypt-scan per insert (see
  // `addCredential`). Rebuilt from a full scan by `#credentialEntries` (so every
  // list/load/delete refreshes it) and maintained incrementally on add/delete.
  #credentialCidIndex = new Map<string, Set<string>>()
  // Whether `#credentialCidIndex` reflects a full scan of the live collection
  // this session. Reset by `setCiphers` (a wider cipher can reveal rows the last
  // scan skipped as unknown-epoch), forcing the next `addCredential` to rebuild.
  #credentialsIndexed = false

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
    this.#storage = storage ?? getRxStorageDexie()
    this.#ciphers = ciphers
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
    const dbPrefix = deriveSpaceId(user.id)

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
      storage: this.#storage,
      closeDuplicates: true,
      // Single-tab for the MVP: with `multiInstance` RxDB gates replication on
      // `waitForLeadership()`, which needs the leader-election plugin. Multi-tab
      // (elect one replicating tab) is deferred, so disable it and replicate in
      // this tab directly.
      multiInstance: false
    })
    // One local collection per standard wallet collection, all on the generic
    // synced-doc schema. `contacts` -- the one mutable, overwritten-in-place
    // collection -- gets the shared last-write-wins conflict handler; the
    // content-addressed collections can never write-write conflict, so they
    // keep RxDB's default.
    const collectionsConfig = Object.fromEntries(
      WALLET_STANDARD_COLLECTIONS.map(({ key }) => [
        key,
        {
          schema: syncedDocSchema(),
          migrationStrategies: syncedDocMigrationStrategies(),
          ...(key === 'contacts' && {
            conflictHandler: createContactsConflictHandler({
              getCipher: () => this.#ciphers?.contacts
            })
          })
        }
      ])
    )
    this.#collections = (await db.addCollections(
      collectionsConfig
    )) as unknown as Record<string, RxCollection<SyncedDoc>>
    // The local-only `contacts-history` projection index, added alongside the
    // standard collections but deliberately NOT one of them: this collection
    // must never sync (`WALLET_STANDARD_COLLECTIONS` drives replication and
    // remote provisioning), so it is created here and kept out of
    // `#collections`.
    const indexCollections = await db.addCollections({
      contactsHistoryIndex: { schema: contactsHistoryIndexSchema }
    })
    this.#contactsHistoryIndex =
      indexCollections.contactsHistoryIndex as unknown as RxCollection<{
        id: string
        contactId: string
      }>
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
    const collection = this.#collections?.[logicalKey]
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
   *   `Key-Epoch` header; absent for a plaintext or pre-epoch write
   * @returns {Promise<void>}
   */
  async #insertDoc({
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
   * Rewrites an existing synced-doc row's body in place -- the mutable
   * counterpart of {@link _insertDoc}, used only by the `contacts` head
   * document (every other collection is content-addressed and never updated).
   * Throws if the row does not exist; the caller (`updateContact`) always
   * targets a row it just read.
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.id {string}
   * @param options.data {Json}
   * @param [options.epoch] {string}   the key-epoch id the re-encrypted body was
   *   written under, re-stamped on the row so replication pushes the current
   *   `Key-Epoch`; absent for a plaintext write
   * @returns {Promise<void>}
   */
  async #updateDoc({
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
    const doc = await this.rxCollection(logicalKey).findOne(id).exec()
    if (!doc) {
      throw new Error(`No local "${logicalKey}" row "${id}" to update.`)
    }
    await doc.incrementalPatch({
      updatedAt: new Date().toISOString(),
      ...(epoch !== undefined && { epoch }),
      data
    })
  }

  /**
   * The session-lifetime decrypt cache (row id -> plaintext) for one collection,
   * created on first use. See {@link _decryptCache}.
   *
   * @param logicalKey {string}
   * @returns {Map<string, Json>}
   */
  #cacheFor(logicalKey: string): Map<string, Json> {
    let cache = this.#decryptCache.get(logicalKey)
    if (!cache) {
      cache = new Map<string, Json>()
      this.#decryptCache.set(logicalKey, cache)
    }
    return cache
  }

  /**
   * The single decrypt-read skeleton shared by every collection: reads the live
   * rows in the requested order, decrypting envelope rows (through the
   * per-collection cache) and passing legacy plaintext rows through, and sorts
   * each decrypt failure into one of two buckets so a caller stays tolerant of a
   * single bad row rather than failing the whole read.
   *
   * A row whose envelope will not decrypt under the current KAK (corrupted,
   * replicated verbatim from another identity, or written under a mismatched
   * KAK) is collected in `undecryptableRowIds` -- purgeable garbage. A row whose
   * envelope names an UNKNOWN key epoch ({@link UnknownEpochError}) is collected
   * separately in `unknownEpochRowIds` and NOT cached: it is possibly-fresh data
   * behind a stale descriptor, so a caller can refresh the descriptor (rebuild the cipher
   * via {@link setCiphers}) and re-read rather than deleting it.
   *
   * `fromEnvelope` distinguishes a decrypted envelope row from a plaintext
   * passthrough, which the credential caller needs (a plaintext row is keyed by
   * its content cid, an envelope row's cid is recomputed from the plaintext).
   *
   * The decrypt cache is keyed by row id, which is sound only for the
   * content-addressed collections (a row's content -- and thus its id -- is fixed
   * once written). The one mutable collection (`contacts`, rewritten in place by
   * an edit or a replication conflict merge under a stable row id) opts out with
   * `cache: false`, since a row-id-keyed entry would go stale after an in-place
   * rewrite.
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.sort {'asc' | 'desc'}   `updatedAt` order
   * @param [options.cache] {boolean}   memoize decrypts by row id (default true);
   *   pass false for a mutable, rewritten-in-place collection
   * @returns {Promise<{ entries: Array<{ rowId: string; data: Json;
   *   fromEnvelope: boolean }>; undecryptableRowIds: string[];
   *   unknownEpochRowIds: string[] }>}
   */
  async #decryptedRows({
    logicalKey,
    sort,
    cache = true
  }: {
    logicalKey: string
    sort: 'asc' | 'desc'
    cache?: boolean
  }): Promise<{
    entries: Array<{ rowId: string; data: Json; fromEnvelope: boolean }>
    undecryptableRowIds: string[]
    unknownEpochRowIds: string[]
  }> {
    const docs = await this.rxCollection(logicalKey)
      .find({ sort: [{ updatedAt: sort }] })
      .exec()
    const cipher = this.#ciphers?.[logicalKey]
    const decryptCache = cache ? this.#cacheFor(logicalKey) : undefined
    const entries: Array<{ rowId: string; data: Json; fromEnvelope: boolean }> =
      []
    const undecryptableRowIds: string[] = []
    const unknownEpochRowIds: string[] = []
    // Every row's decrypt is independent, so they run together; the fold below
    // then walks them in list order, keeping the entry ordering and the
    // per-row failure buckets exactly as a sequential pass produced them.
    const rows = await Promise.all(
      docs.map(async doc => {
        const { id, data } = doc.toMutableJSON()
        if (!cipher || !isEncryptedEnvelope(data)) {
          return { id, plaintext: data as Json, fromEnvelope: false }
        }
        const cached = decryptCache?.get(id)
        if (cached !== undefined) {
          return { id, plaintext: cached, fromEnvelope: true }
        }
        try {
          const plaintext = await cipher.decrypt({ envelope: data! })
          decryptCache?.set(id, plaintext)
          return { id, plaintext, fromEnvelope: true }
        } catch (err) {
          return { id, fromEnvelope: true, err }
        }
      })
    )
    for (const { id, plaintext, fromEnvelope, err } of rows) {
      if (err) {
        if (err instanceof UnknownEpochError) {
          // Possibly-fresh data behind a stale descriptor: skip it (uncached) so a
          // descriptor refresh can pick it up, never purge it.
          console.warn(
            `Skipping unknown-epoch "${logicalKey}" row "${id}":`,
            err
          )
          unknownEpochRowIds.push(id)
        } else {
          console.warn(
            `Skipping undecryptable "${logicalKey}" row "${id}":`,
            err
          )
          undecryptableRowIds.push(id)
        }
        continue
      }
      entries.push({ rowId: id, data: plaintext as Json, fromEnvelope })
    }
    return { entries, undecryptableRowIds, unknownEpochRowIds }
  }

  /**
   * Encrypts a document for one collection when that collection has a cipher,
   * else passes it through as plaintext -- the single choose-cipher / encrypt /
   * plaintext-fallback seam every writer shares. Returns the body to store
   * (envelope or plaintext), the cipher-minted content id (only when encrypted),
   * and the key-epoch id the write went under (only on a multi-recipient
   * cipher).
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.data {Json}
   * @returns {Promise<{ body: Json; mintedId?: string; epoch?: string }>}
   */
  async #encrypt({
    logicalKey,
    data
  }: {
    logicalKey: string
    data: Json
  }): Promise<{ body: Json; mintedId?: string; epoch?: string }> {
    const cipher = this.#ciphers?.[logicalKey]
    if (!cipher) {
      return { body: data }
    }
    const { id, envelope, epoch } = await cipher.encrypt({ data })
    return { body: envelope, mintedId: id, epoch }
  }

  /**
   * Inserts a document into one collection, folding cipher selection,
   * encryption, and the key-epoch stamp (see {@link _encrypt}). When the write
   * encrypted, the cipher-minted id keys the row -- the envelope-hash id on a
   * content-addressed collection, the random EDV id on the stable-id `contacts`
   * head (each cipher mints per its collection spec's `idDerivation`) -- and
   * the passed `id` serves only as the plaintext-store fallback key. Returns
   * the row id actually written and the stamped epoch.
   *
   * @param options {object}
   * @param options.logicalKey {string}
   * @param options.id {string}
   * @param options.data {Json}
   * @returns {Promise<{ rowId: string; epoch?: string }>}
   */
  async #insertEncrypted({
    logicalKey,
    id,
    data
  }: {
    logicalKey: string
    id: string
    data: Json
  }): Promise<{ rowId: string; epoch?: string }> {
    const { body, mintedId, epoch } = await this.#encrypt({ logicalKey, data })
    const rowId = mintedId ?? id
    await this.#insertDoc({ logicalKey, id: rowId, data: body, epoch })
    return { rowId, epoch }
  }

  /**
   * The count of `private-credentials` rows the most recent
   * {@link listCredentials} call had to skip because their envelope would not
   * decrypt under the current vault KAK.
   *
   * @returns {number}
   */
  get undecryptableCredentials(): number {
    return this.#undecryptableCredentials
  }

  /**
   * The count of `private-credentials` rows the most recent
   * {@link listCredentials} call had to skip because their envelope named a key
   * epoch this instance's cipher does not know (its cached Collection
   * Description is likely stale). Unlike {@link undecryptableCredentials} these
   * rows are not purged -- a caller refreshes the descriptor, rebuilds the cipher
   * via {@link setCiphers}, and re-reads.
   *
   * @returns {number}
   */
  get unknownEpochCredentials(): number {
    return this.#unknownEpochCredentials
  }

  /**
   * The count of `wallet-activity` rows the most recent
   * {@link listHistoryItems} call had to skip for the same reason.
   *
   * @returns {number}
   */
  get unknownEpochHistory(): number {
    return this.#unknownEpochHistory
  }

  /**
   * Swaps the injected per-collection document ciphers -- used after a
   * Collection Description descriptor refresh or a share/unshare rebuilds the
   * ciphers under a new key epoch. The decrypt caches are deliberately kept:
   * a row id is the content-derived hash of its envelope, so it maps to exactly
   * one plaintext under any cipher that can decrypt it; a wider cipher set only
   * decrypts more rows, never remaps an already-cached one.
   *
   * @param ciphers {Record<string, DocCipher>}
   * @returns {void}
   */
  setCiphers(ciphers: Record<string, DocCipher>): void {
    this.#ciphers = ciphers
    // A wider cipher set can reveal rows the last scan skipped as unknown-epoch,
    // so the cid index is no longer known-complete; force the next
    // `addCredential` to rebuild it. The decrypt caches stay valid (a row id
    // maps to one plaintext under any cipher that can read it).
    this.#credentialsIndexed = false
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
   * A row whose envelope names an UNKNOWN key epoch (its cached descriptor is
   * likely stale, `UnknownEpochError`) is collected separately in
   * `unknownEpochRowIds` and NOT cached: it is possibly-fresh data behind a
   * stale descriptor, not purgeable garbage, so a caller can refresh the descriptor and
   * re-read rather than deleting it.
   *
   * @returns {Promise<{ entries: Array<{ rowId: string; cid: string;
   *   vc: IVerifiableCredential }>; undecryptableRowIds: string[];
   *   unknownEpochRowIds: string[] }>}
   */
  async #credentialEntries(): Promise<{
    entries: Array<{ rowId: string; cid: string; vc: IVerifiableCredential }>
    undecryptableRowIds: string[]
    unknownEpochRowIds: string[]
  }> {
    const {
      entries: rows,
      undecryptableRowIds,
      unknownEpochRowIds
    } = await this.#decryptedRows({
      logicalKey: 'privateCredentials',
      sort: 'asc'
    })
    const entries: Array<{
      rowId: string
      cid: string
      vc: IVerifiableCredential
    }> = []
    // Rebuild the cid index from this full scan, so every list/load/delete
    // refreshes the authority `addCredential` consults.
    const cidIndex = new Map<string, Set<string>>()
    for (const { rowId, data, fromEnvelope } of rows) {
      const vc = data as unknown as IVerifiableCredential
      let cid: string
      if (fromEnvelope) {
        // An envelope row's cid is recomputed from the decrypted VC (memoized
        // per row id, since the envelope's plaintext -- and thus its cid -- is
        // fixed once written).
        cid =
          this.#credentialCidByRow.get(rowId) ?? (await cidFrom({ doc: vc }))
        this.#credentialCidByRow.set(rowId, cid)
      } else {
        // A plaintext row IS keyed by its content cid.
        cid = rowId
      }
      let rowIds = cidIndex.get(cid)
      if (!rowIds) {
        rowIds = new Set<string>()
        cidIndex.set(cid, rowIds)
      }
      rowIds.add(rowId)
      entries.push({ rowId, cid, vc })
    }
    this.#credentialCidIndex = cidIndex
    this.#credentialsIndexed = true
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
   * Idempotence is enforced through the in-memory `#credentialCidIndex`
   * (cid -> live row ids), consulted in O(1) rather than by a full decrypt-scan
   * per insert. The index is built once per session on first use (a single scan)
   * and maintained incrementally on add/delete, so a batch import runs in O(N)
   * decrypts, not O(N^2) -- and idempotence no longer depends on the caller
   * pre-deduping the batch or storing sequentially.
   *
   * Design tradeoff: the index is in-memory, not a persisted row field. A
   * plaintext cid on the encrypted row would be simplest but would replicate to
   * the server and defeat the encrypted-at-rest model (the cid links a subject
   * to a stored ciphertext); the index keeps the server seeing only opaque
   * envelopes. Its cost is a narrow staleness window: a credential pulled by
   * background replication AFTER the index was last built (any list/load/delete
   * rebuilds it) but before a racing local `addCredential` of the same cid can
   * yield a second envelope row for that VC. That is the already-tolerated
   * "duplicate envelope rows for the same VC" case -- `listCredentials` collapses
   * duplicates by cid and `deleteCredential` removes every row for a cid -- so it
   * costs a redundant row, never a correctness failure.
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
    const cipher = this.#ciphers?.privateCredentials
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
      await this.#insertDoc({
        logicalKey: 'privateCredentials',
        id: cid,
        data: credential as unknown as Json
      })
      return true
    }
    // Ensure the cid index reflects a full scan of the live rows this session,
    // then check it in O(1) instead of re-decrypting the whole collection.
    if (!this.#credentialsIndexed) {
      await this.#credentialEntries()
    }
    if (this.#credentialCidIndex.has(cid)) {
      return false
    }
    const { rowId } = await this.#insertEncrypted({
      logicalKey: 'privateCredentials',
      id: cid,
      data: credential as unknown as Json
    })
    // Maintain the caches and index incrementally so the next insert in a batch
    // sees this one without another scan, and a subsequent read need not decrypt
    // this fresh row.
    this.#cacheFor('privateCredentials').set(
      rowId,
      credential as unknown as Json
    )
    this.#credentialCidByRow.set(rowId, cid)
    this.#credentialCidIndex.set(cid, new Set([rowId]))
    return true
  }

  /**
   * @param options {object}
   * @param options.cid {string}
   * @returns {Promise<IVerifiableCredential | undefined>}
   */
  async loadCredential({ cid }: { cid: string }) {
    const { entries } = await this.#credentialEntries()
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
    const { entries } = await this.#credentialEntries()
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
    this.#cacheFor('privateCredentials').delete(rowId)
    // Drop the row from the cid index so a later re-add of the same credential
    // is not wrongly treated as already present.
    const cid = this.#credentialCidByRow.get(rowId)
    if (cid !== undefined) {
      this.#credentialCidByRow.delete(rowId)
      const rowIds = this.#credentialCidIndex.get(cid)
      if (rowIds) {
        rowIds.delete(rowId)
        if (rowIds.size === 0) {
          this.#credentialCidIndex.delete(cid)
        }
      }
    }
  }

  /**
   * Removes every `private-credentials` row whose envelope will not decrypt
   * under the current vault KAK, so a user can clear rows that can never be
   * shown (corrupted, or written under a mismatched KAK). Returns the number
   * of rows removed.
   *
   * @returns {Promise<number>}
   */
  async purgeUndecryptableCredentials(): Promise<number> {
    const { undecryptableRowIds } = await this.#credentialEntries()
    for (const rowId of undecryptableRowIds) {
      await this.deleteCredentialByRowId({ rowId })
    }
    this.#undecryptableCredentials = 0
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
      await this.#credentialEntries()
    this.#undecryptableCredentials = undecryptableRowIds.length
    this.#unknownEpochCredentials = unknownEpochRowIds.length
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
    await this.#insertDoc({
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
    await this.#insertEncrypted({
      logicalKey: 'walletActivity',
      id: resourceId,
      data: activity as Json
    })
  }

  /**
   * Lists the `wallet-activity` log entries, oldest first, decrypting
   * envelope rows and passing legacy plaintext rows through. Each item's `id`
   * is the activity's own id (a uuid minted at record time); duplicate rows
   * carrying the same activity are collapsed to their oldest copy.
   *
   * A row whose envelope will not decrypt under the current KAK is skipped
   * (logged) rather than rejecting the whole read, so one poisoned row cannot hang the history page.
   *
   * @returns {Promise<Array<{ id: string; doc: WalletActivity }>>}
   */
  async listHistoryItems(): Promise<
    Array<{ id: string; doc: WalletActivity }>
  > {
    const { entries, unknownEpochRowIds } = await this.#decryptedRows({
      logicalKey: 'walletActivity',
      sort: 'asc'
    })
    this.#unknownEpochHistory = unknownEpochRowIds.length
    const seen = new Set<string>()
    const items: Array<{ id: string; doc: WalletActivity }> = []
    for (const { rowId, data } of entries) {
      const activity = data as WalletActivity
      const id = activity.id ?? rowId
      if (seen.has(id)) {
        continue
      }
      seen.add(id)
      items.push({ id, doc: activity })
    }
    return items
  }

  /**
   * Reads every live `contacts` row, decrypting envelope rows and passing
   * legacy plaintext rows through. Unlike credentials, a contact's row id is
   * NOT content-derived -- it is a stable id minted at creation
   * ({@link addContact}) -- so this simply reflects the current row set
   * (`_updateDoc` rewrites a row's body in place rather than replacing the
   * row), no cid-based dedupe needed.
   *
   * A row whose envelope will not decrypt under the current KAK is skipped, and
   * an unknown-epoch row is skipped uncached for a descriptor refresh to pick up --
   * the shared {@link _decryptedRows} tolerance (and its decrypt cache) that the
   * credential and history reads use.
   *
   * Every head passes through `upgradeContactHeadPayload` (as does
   * {@link loadContact}'s point read), so a row written before the current
   * `ContactData` postal shape is seen by the rest of the app, and by any
   * save that carries its untouched fields forward, in the current shape.
   * The upgrade is idempotent, so a row already in the current shape is
   * unaffected, and a re-save therefore produces no spurious
   * last-write-wins edit.
   *
   * @returns {Promise<Array<{ rowId: string; head: ContactHeadPayload }>>}
   */
  async #contactEntries(): Promise<
    Array<{ rowId: string; head: ContactHeadPayload }>
  > {
    const { entries } = await this.#decryptedRows({
      logicalKey: 'contacts',
      sort: 'asc',
      cache: false
    })
    return entries.map(({ rowId, data }) => ({
      rowId,
      head: upgradeContactHeadPayload(data as unknown as ContactHeadPayload)
    }))
  }

  /**
   * Lists the stored contacts, oldest first.
   *
   * @returns {Promise<Array<StoredContact>>}
   */
  async listContacts(): Promise<Array<StoredContact>> {
    const entries = await this.#contactEntries()
    return entries.map(({ rowId, head }) => ({
      id: rowId,
      // Legacy heads written before the row-id / contact-id split carry no
      // usable distinction; fall back to the row id for those.
      contactId: head.contactId ?? rowId,
      contact: head.contact,
      updatedAt: head.updatedAt
    }))
  }

  /**
   * Loads one contact by row id -- a `findOne` point read plus at most one
   * decrypt (the row id IS the RxDB primary key), never the full-collection
   * scan {@link listContacts} pays. Mirrors the scan's per-row tolerance: a
   * row whose envelope will not decrypt under the current KAK (or names an
   * unknown key epoch) resolves to `undefined`, exactly as the scan would
   * have skipped it. The head passes through the same idempotent
   * `upgradeContactHeadPayload` read-side upgrade as {@link #contactEntries}.
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
    const doc = await this.rxCollection('contacts').findOne(id).exec()
    if (!doc) {
      return undefined
    }
    const { data } = doc.toMutableJSON()
    const cipher = this.#ciphers?.contacts
    let raw: Json
    if (cipher && isEncryptedEnvelope(data)) {
      try {
        raw = await cipher.decrypt({ envelope: data! })
      } catch (err) {
        console.warn(`Skipping undecryptable "contacts" row "${id}":`, err)
        return undefined
      }
    } else {
      raw = data as Json
    }
    const head = upgradeContactHeadPayload(raw as unknown as ContactHeadPayload)
    return {
      id,
      contactId: head.contactId ?? id,
      contact: head.contact,
      updatedAt: head.updatedAt
    }
  }

  /**
   * Adds a contact to the local `contacts` collection under a freshly minted,
   * stable row id -- unlike credentials, this id is NOT content-derived, so
   * a later edit can rewrite the same row in place ({@link updateContact}).
   *
   * The row id and the head payload's `contactId` are minted separately,
   * matching Freewallet mobile (resource `syncId` vs local `_id`): the row id
   * is transport-level addressing, `contactId` is the logical identity that
   * every `contacts-history` revision refers to.
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
    contact: ContactHeadPayload['contact']
    writerId: string
  }): Promise<StoredContact> {
    const contactId = uuidv7()
    const updatedAt = new Date().toISOString()
    const head: ContactHeadPayload = {
      contactId,
      updatedAt,
      writerId,
      contact
    }
    // `contacts` is stable-id (mutable, updated in place): an encrypted write
    // keys the row with the cipher-minted random EDV id (the collection spec's
    // `idDerivation: 'random'`), which the sync layer pushes as the server
    // resource id -- an EDV-format id like every other replica's. The uuid is
    // only the plaintext-fallback row key. Rows created before this cipher
    // change keep their uuid ids; every reader and updater (here and on other
    // replicas) accepts both id universes.
    const { rowId } = await this.#insertEncrypted({
      logicalKey: 'contacts',
      id: uuidv7(),
      data: head as unknown as Json
    })
    return { id: rowId, contactId, contact, updatedAt }
  }

  /**
   * Rewrites a contact's row in place under its existing id, re-encrypting
   * the whole head payload (fresh JWE nonce, so the envelope bytes always
   * change even for a no-op save). The logical `contactId` sealed in the
   * existing head is preserved verbatim -- it is the identity every revision
   * (on every replica) refers to, and it differs from the row id for
   * mobile-authored contacts. Throws when the existing head is unreachable
   * (missing row, undecryptable envelope): rewriting it blind would sever the
   * contact from its history.
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
    contact: ContactHeadPayload['contact']
    writerId: string
  }): Promise<StoredContact> {
    const doc = await this.rxCollection('contacts').findOne(id).exec()
    if (!doc) {
      throw new Error(`No local "contacts" row "${id}" to update.`)
    }
    const { data } = doc.toMutableJSON()
    const cipherForRead = this.#ciphers?.contacts
    let existingHead: ContactHeadPayload
    if (isEncryptedEnvelope(data)) {
      if (!cipherForRead) {
        throw new Error(
          `Cannot update contact "${id}": the contacts cipher is unavailable.`
        )
      }
      existingHead = (await cipherForRead.decrypt({
        envelope: data!
      })) as unknown as ContactHeadPayload
    } else {
      existingHead = data as unknown as ContactHeadPayload
    }
    const contactId = existingHead.contactId ?? id
    const updatedAt = new Date().toISOString()
    const head: ContactHeadPayload = {
      contactId,
      updatedAt,
      writerId,
      contact
    }
    // Re-encrypt in place through the cipher's update path: it keeps the row's
    // existing id verbatim (binding the envelope to the true resource id --
    // including a legacy uuid row id) and advances the EDV `sequence` from the
    // prior envelope, then re-stamp the epoch so replication pushes the current
    // `Key-Epoch` for the rewritten body. A plaintext prior row (or no
    // cipher) falls back to the inserters' encrypt seam -- `encryptUpdate`
    // needs a prior envelope to advance from.
    if (cipherForRead?.encryptUpdate && isEncryptedEnvelope(data)) {
      const { envelope, epoch } = await cipherForRead.encryptUpdate({
        id,
        data: head as unknown as Json,
        current: data!
      })
      await this.#updateDoc({
        logicalKey: 'contacts',
        id,
        data: envelope,
        epoch
      })
    } else {
      const { body, epoch } = await this.#encrypt({
        logicalKey: 'contacts',
        data: head as unknown as Json
      })
      await this.#updateDoc({ logicalKey: 'contacts', id, data: body, epoch })
    }
    return { id, contactId, contact, updatedAt }
  }

  /**
   * Removes a contact's row (a soft delete; replication pushes the tombstone).
   *
   * @param options {object}
   * @param options.id {string}
   * @returns {Promise<void>}
   */
  async deleteContact({ id }: { id: string }): Promise<void> {
    const doc = await this.rxCollection('contacts').findOne(id).exec()
    if (doc) {
      await doc.remove()
    }
  }

  /**
   * Appends an entry to the local `contacts-history` log -- content-addressed
   * and append-only, exactly like `wallet-activity`. Called once per contact
   * mutation (create/update/delete) so the edit log mirrors Freewallet
   * mobile's `contact_revisions` table.
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
    // Content-addressed under encryption (the cipher's envelope-hash id keys the
    // row); the passed `id` is only the plaintext-store key, so a plaintext
    // revision gets a fresh uuid. The epoch is now stamped too (via
    // {@link _insertEncrypted}), matching the other encrypted writers.
    const { rowId } = await this.#insertEncrypted({
      logicalKey: 'contactsHistory',
      id: uuidv7(),
      data: revision as unknown as Json
    })
    await this.#indexContactRevision({ rowId, contactId: revision.contactId })
  }

  /**
   * Records one history row's `rowId -> contactId` projection in the local-only
   * index, best-effort: the index is a read accelerator, so a failure here must
   * never fail the revision write -- the row simply gets decrypted once by a
   * later read, which backfills it.
   *
   * The mapping is permanently valid: history rows are content-addressed and
   * immutable, so a row id names one envelope, hence one revision, forever. An
   * index row whose history row has since disappeared is harmless -- reads walk
   * the history rows and consult the index, never the other way round.
   *
   * @param options {object}
   * @param options.rowId {string}
   * @param options.contactId {string}
   * @returns {Promise<void>}
   */
  async #indexContactRevision({
    rowId,
    contactId
  }: {
    rowId: string
    contactId: string
  }): Promise<void> {
    try {
      await this.#contactsHistoryIndex?.insertIfNotExists({
        id: rowId,
        contactId
      })
    } catch (err) {
      console.warn(`Failed to index "contacts-history" row "${rowId}":`, err)
    }
  }

  /**
   * Lists a single contact's revision history, most recent first -- ordered by
   * the logical `timestamp` each revision payload carries (`writerId`
   * descending breaks a tie), never by local row insertion order, so a history
   * whose rows arrived out of order still reads chronologically
   * ({@link compareContactRevisionsNewestFirst}).
   *
   * `contacts-history` is append-only and grows without bound, so this read
   * does not decrypt it: the local-only projection index
   * ({@link contactsHistoryIndexSchema}) answers "which contact does this row
   * belong to?" in plaintext, and a row the index attributes to another
   * contact is skipped with zero cryptographic work. Only rows attributed to
   * the requested contact -- plus any row not yet in the index -- are
   * decrypted, and every decrypt of a previously unindexed row backfills the
   * index with its TRUE `contactId` (matching or not). Fresh revisions are
   * indexed at write time, so the amortized cost of a read is one decrypt per
   * revision of the requested contact, and each historical row is decrypted at
   * most once ever per browser.
   *
   * Per-row tolerance mirrors {@link #decryptedRows}: a plaintext (legacy or
   * cipher-less) body passes through; an {@link UnknownEpochError} row is
   * skipped uncached AND left unindexed, since it is possibly-fresh data
   * behind a stale descriptor that must stay retryable after a descriptor
   * refresh; any other decrypt failure is warned, skipped, and likewise left
   * unindexed.
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
    const docs = await this.rxCollection('contactsHistory')
      .find({ sort: [{ updatedAt: 'desc' }] })
      .exec()
    const indexRows = (await this.#contactsHistoryIndex?.find().exec()) ?? []
    const contactIdByRow = new Map<string, string>(
      indexRows.map(row => [row.id, row.contactId])
    )
    const cipher = this.#ciphers?.contactsHistory
    const decryptCache = this.#cacheFor('contactsHistory')
    // Each needed decrypt is independent, so they run together; the fold below
    // walks the results in document order, which is only the walk order -- the
    // returned revisions are sorted by their logical timestamp at the end.
    const rows = await Promise.all(
      docs.map(async doc => {
        const { id, data } = doc.toMutableJSON()
        const indexed = contactIdByRow.get(id)
        if (indexed !== undefined && indexed !== contactId) {
          // The whole win: another contact's revision, skipped undecrypted.
          return { id, skipped: true }
        }
        if (!cipher || !isEncryptedEnvelope(data)) {
          return { id, plaintext: data as Json, indexed }
        }
        const cached = decryptCache.get(id)
        if (cached !== undefined) {
          return { id, plaintext: cached, indexed }
        }
        try {
          const plaintext = await cipher.decrypt({ envelope: data! })
          decryptCache.set(id, plaintext)
          return { id, plaintext, indexed }
        } catch (err) {
          return { id, indexed, err }
        }
      })
    )
    const revisions: ContactRevisionPayload[] = []
    const backfill: Array<{ rowId: string; contactId: string }> = []
    for (const { id, skipped, plaintext, indexed, err } of rows) {
      if (skipped) {
        continue
      }
      if (err) {
        if (err instanceof UnknownEpochError) {
          // Possibly-fresh data behind a stale descriptor: skip it uncached and
          // unindexed so a descriptor refresh can pick it up on a later read.
          console.warn(
            `Skipping unknown-epoch "contactsHistory" row "${id}":`,
            err
          )
        } else {
          console.warn(
            `Skipping undecryptable "contactsHistory" row "${id}":`,
            err
          )
        }
        continue
      }
      // Same idempotent read-side upgrade as the head reads, so a snapshot
      // stored before the current `ContactData` postal shape views and
      // restores in the current shape.
      const revision = upgradeContactRevisionPayload(
        plaintext as unknown as ContactRevisionPayload
      )
      if (indexed === undefined && revision.contactId) {
        backfill.push({ rowId: id, contactId: revision.contactId })
      }
      if (revision.contactId === contactId) {
        revisions.push(revision)
      }
    }
    // Best-effort, and after the fold so a slow index write never delays the
    // revisions the caller asked for.
    await Promise.all(backfill.map(entry => this.#indexContactRevision(entry)))
    revisions.sort(compareContactRevisionsNewestFirst)
    return revisions
  }

  /**
   * Runs a one-time local migration at most once per user: a persistent
   * per-`dbPrefix` marker (localStorage, guarded for the non-browser test/SSR
   * environments) short-circuits the full-collection scan on every later
   * login, and is stamped only once the pass completes.
   *
   * @param markerKey {string}   the localStorage marker key
   * @param migrate {() => Promise<void>}   the migration pass
   * @returns {Promise<void>}
   */
  async #runOnce(markerKey: string, migrate: () => Promise<void>) {
    const hasLocalStorage = typeof localStorage !== 'undefined'
    if (hasLocalStorage && localStorage.getItem(markerKey)) {
      return
    }
    await migrate()
    if (hasLocalStorage) {
      localStorage.setItem(markerKey, new Date().toISOString())
    }
  }

  /**
   * One-time local migration for the encrypted collections: re-keys plaintext
   * rows written before encrypted sync landed (when
   * `private-credentials` / `wallet-activity` were local-active but not yet
   * replicating) into EDV envelopes under their content-derived ids. Runs at
   * login before replication starts -- required, not just tidy: once a remote
   * collection carries its encryption descriptor, the server rejects a plaintext
   * content push (422), which would wedge the push cycle in retry.
   *
   * Only never-synced rows are touched (`version === 0`, the local
   * placeholder; a pulled row carries the server revision, >= 1) -- a legacy
   * plaintext row replicated down from a pre-descriptor remote collection is left
   * as-is and handled by the tolerant read paths. The re-keyed original is
   * soft-deleted; its pushed tombstone targets a resource that never existed
   * remotely, which the server treats as an idempotent no-op. The original's
   * `updatedAt` is preserved so log/list ordering survives the re-key.
   *
   * Runs at most once per user: after the first pass no never-synced plaintext
   * row can remain, so a persistent per-`dbPrefix` marker (localStorage, guarded
   * for the non-browser test/SSR environments) short-circuits the full-collection
   * scan that would otherwise materialize every encrypted row on every later
   * login.
   *
   * @returns {Promise<void>}
   */
  async migrateLocalPlaintextDocs() {
    await this.#runOnce(
      `freewallet:plaintext-migrated:${this.dbPrefix}`,
      async () => {
        for (const [logicalKey, cipher] of Object.entries(
          this.#ciphers ?? {}
        )) {
          const collection = this.rxCollection(logicalKey)
          const docs = await collection.find().exec()
          for (const doc of docs) {
            const { updatedAt, version, data } = doc.toMutableJSON()
            if (
              version !== 0 ||
              data === undefined ||
              isEncryptedEnvelope(data)
            ) {
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
      }
    )
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
   * keyed row is skipped). Note that any public link already shared to an
   * old-cid resource stops resolving once its remote row is tombstoned.
   *
   * Runs at most once per user: after the first pass no mis-keyed row can remain
   * (the pre-fix formula is retired), so a persistent per-`dbPrefix` marker
   * (localStorage, guarded for the non-browser test/SSR environments)
   * short-circuits the full-collection `cidFrom` recompute that would otherwise
   * run on every later login.
   *
   * @returns {Promise<void>}
   */
  async migratePublicCredentialCids() {
    await this.#runOnce(
      `freewallet:public-cids-migrated:${this.dbPrefix}`,
      async () => {
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
    )
  }

  /**
   * Drops the session-lifetime decrypt cache and the credential cid index,
   * called on teardown (close/wipe) so a later session never reads stale
   * plaintext or a stale idempotency verdict.
   *
   * @returns {void}
   */
  #clearCaches(): void {
    this.#decryptCache.clear()
    this.#credentialCidByRow.clear()
    this.#credentialCidIndex.clear()
    this.#credentialsIndexed = false
  }

  /**
   * Removes the wallet database and any legacy local databases carrying this
   * user's prefix (e.g. the pre-flip `-credentials-db` / `-sync-db`).
   *
   * @see https://rxdb.info/rx-database.html#remove
   * @returns {Promise<void>}
   */
  async wipeStorage() {
    this.#clearCaches()
    if (this.db) {
      await this.db.remove()
      this.db = undefined
      this.#collections = undefined
      this.#contactsHistoryIndex = undefined
    }
    // Guarded: absent under the memory storage used in unit tests.
    if (typeof indexedDB !== 'undefined') {
      const databases = await indexedDB.databases()
      await Promise.all(
        databases
          .filter(db => db.name!.includes(this.dbPrefix))
          .map(db => this.#deleteDatabase(db.name!))
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
  #deleteDatabase(name: string): Promise<void> {
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
    this.#clearCaches()
    if (this.db) {
      await this.db.close()
      this.db = undefined
      this.#collections = undefined
      this.#contactsHistoryIndex = undefined
    }
  }
}
