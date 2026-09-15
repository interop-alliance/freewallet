/**
 * Storage layer for the wallet. StorageManager is the single facade used by
 * all pages. Every credential, public-link, and history read/write goes
 * through one `SyncedCollectionStore` backend, chosen ONCE at session
 * construction. A session that has a local replica (a remembered login, a
 * guest, a no-WAS session) serves them from the local `BrowserStore`
 * (RxDB/IndexedDB), online or offline. A session that has none -- the
 * replica-less transient session, the default -- serves them remote-direct
 * over the remote WAS collections, and so does a CHAPI popup session. When
 * VITE_WAS_SERVER_URL (the server's Spaces Repository URL) is set (and the
 * session is not a guest), a WASRemoteStore is attached as well: the sync
 * controller replicates a local replica's collections to it in the
 * background, and the storage browser / export / import / quota pages read
 * through it directly.
 *
 * The remote-direct backend is `src/stores/remoteDirectStore.ts`. A popup
 * runs in a third-party partitioned iframe: its local BrowserStore binds a
 * partitioned IndexedDB no sync controller drives, so a credential stored
 * there would be stranded and a credential list would always come back empty.
 * A transient session constructs no BrowserStore at all. Either way the
 * backend reads and writes the standard synced collections straight over the
 * remote WAS collections, reproducing verbatim what background replication
 * would have pushed (the raw EDV envelope under its content-derived id,
 * `Key-Epoch` stamped) so the main app pulls those writes cleanly. Both
 * backends share the session's per-collection ciphers, so the envelope / id /
 * epoch logic lives once. The remote-direct backend is selected only when a
 * remote store is configured; a guest / no-WAS session always uses the local
 * BrowserStore.
 */
import type {
  IDID,
  IKeyAgreementKey,
  IKeyResolver,
  IVerifiableCredential,
  IZcap
} from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import {
  CONTACTS_COLLECTION,
  type ContactData,
  type ContactRevisionPayload
} from '@interop/social-core'
import type { RxCollection, RxStorage } from 'rxdb/plugins/core'
import type {
  CollectionEncryption,
  IDelegatedZcap,
  ServiceDescription,
  SpaceMetadata
} from '@interop/was-client'
import {
  acquireDescriptor,
  acquireDescriptors,
  addRecipient,
  DescriptorRefreshPolicy,
  removeRecipient,
  type EncryptionDescriptorCache,
  type EncryptionDescriptorSource,
  type EncryptionDescriptorStore,
  type RecipientPublicKey
} from '@interop/was-client/edv'
import { parseSpaceTarget, rootCapabilityId } from '@interop/was-client/paths'
import {
  accountCollectionStores,
  ensureIndexedFirstEpoch,
  userKeyRosterLogSigner
} from '@interop/wallet-core/keys'
import { isResourceLogRefusal } from '@interop/wallet-core/resourceLog'
import {
  descriptorLogSignerAgent,
  sessionCollectionDescriptorSource,
  sessionCollectionStores
} from '@/session/collectionLogStore'
import type { ControllerProfile, SessionCore, User } from '@/types/auth'
import { cidFrom } from '@interop/was-client/sync'
import { classifyDecryptFailure } from '@/lib/decryptFailure'
import { refreshingCollectionCipher } from '@/stores/refreshingCollectionCipher'
import {
  ENCRYPTED_STANDARD_COLLECTIONS,
  RP_ZCAP_TTL_MS,
  SYSTEM_COLLECTIONS,
  WALLET_STANDARD_COLLECTIONS,
  WAS_SERVER_URL
} from '@/app.config'
import {
  assertMintedAppKey,
  assertStorableAppKey
} from '@interop/wallet-request'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { didWebFromSpace } from '@/lib/didWeb'
import { ensureKmsAuthentication } from '@/lib/kms'
import {
  didKeyZcapClient,
  isWebvhDid,
  webvhCapabilityAgent,
  webvhZcapClient,
  type KmsAuthenticationBinding
} from '@interop/wallet-core/webvh'
import { ensureAccountGenesis } from '@interop/wallet-core/genesis'
import { errorNameOf, type MendOutcome } from '@interop/wallet-core/menders'
import {
  clampGrantExpires,
  revokeRecordedGrant,
  type AccountSignerCheck
} from '@interop/wallet-core/clientAnnex'
import { delegationExpired } from '@interop/wallet-core/webvh'
import { promoteKeystoreController, rebindKeystoreAgent } from '@/lib/kms'
import { accountRosterStore } from '@/session/rosterStore'
import { mintRecordEncryption } from '@interop/wallet-core/keyring'
import {
  loadAccountDidForSpace,
  saveAccountDidForSpace
} from '@/lib/sessionKey'
import {
  assertBrowserLocalSession,
  isBrowserLocalSession,
  type CollectionMetaCache,
  type SessionPersistence
} from '@/session/persistence'
import { invalidateVerifiedLogForPublish } from '@/session/verifiedLog'
import {
  createEdvDocCipher,
  isEncryptedEnvelope,
  ownerRecipient,
  type DocCipher,
  type EdvDocCipher
} from '@interop/was-client/edv'
import type { StorageCollection, StorageResource } from '@/lib/storage'
import type { Json, SyncedDoc } from '@interop/was-sync'
import type { SpaceQuotaReport } from '@/types/storageQuota'
import type { FetchedCollectionResource } from '@/lib/storageResource'
import type { StoredCredential } from '@/types/credential'
import type { StoredContact } from '@/types/contact'
import { BrowserStore } from '@/stores/browserStore'
import { WASRemoteStore } from '@/stores/wasRemoteStore'
import {
  RemoteDirectStore,
  type SyncedCollectionStore
} from '@/stores/remoteDirectStore'
import { EXTERNAL_REQUEST_ORIGIN } from '@/lib/walletRequest/externalRequest'
import type { SpaceLocation } from '@/lib/walletRequest/processZcaps'
import type { CredentialActivityVerb } from '@/lib/historyActivity'
import { uuidv7 } from 'uuidv7'
import {
  addHistoryNewAccount as buildHistoryNewAccount,
  addHistorySpaceCreated as buildHistorySpaceCreated,
  addHistoryCredentialCreated as buildHistoryCredentialCreated,
  addHistoryCredentialDeleted as buildHistoryCredentialDeleted,
  addHistoryCredentialShared as buildHistoryCredentialShared,
  addHistoryCredentialUnshared as buildHistoryCredentialUnshared,
  addHistoryLogin as buildHistoryLogin,
  addHistoryWalletLogin as buildHistoryWalletLogin,
  addHistoryAppRevoke as buildHistoryAppRevoke,
  addHistoryAgentRevoke as buildHistoryAgentRevoke,
  addHistoryClientRevoked as buildHistoryClientRevoked,
  addHistoryGenerationCollected as buildHistoryGenerationCollected,
  addHistoryCollectionShared as buildHistoryCollectionShared,
  addHistoryCollectionUnshared as buildHistoryCollectionUnshared,
  type WalletActivity
} from '@interop/wallet-core/space'
import { createLogger, stageTimer } from '@/lib/log'

const log = createLogger('fw:storage:manager')

// The `wallet-activity` wire shape now lives in `@interop/wallet-core/space`
// (shared with Freewallet mobile). Re-exported here so existing importers keep
// resolving it from `@/stores/storageManager`.
export type { WalletActivity }

export type ImportSpaceSummary = {
  collectionsCreated: number
  collectionsSkipped: number
  resourcesCreated: number
  resourcesSkipped: number
}

/**
 * The recipient kids of a descriptor's CURRENT key epoch, minus the owner's
 * own key-agreement key when one is given (the owner is recipient zero of
 * every epoch, so dropping it leaves exactly the other readers). Empty when the
 * descriptor carries no epochs, or none matching `currentEpoch`.
 *
 * @param options {object}
 * @param [options.descriptor] {CollectionEncryption | null}
 * @param [options.ownerKid] {string}   the owner's key-agreement key id
 * @returns {string[]}
 */
function currentEpochRecipientKids({
  descriptor,
  ownerKid
}: {
  descriptor?: CollectionEncryption | null
  ownerKid?: string
}): string[] {
  const epoch = descriptor?.epochs?.find(
    entry => entry.id === descriptor.currentEpoch
  )
  return (epoch?.recipients ?? [])
    .map(entry => entry.header.kid)
    .filter(kid => kid !== ownerKid)
}

/**
 * Decrypts one EDV envelope into the `{ value, unknownEpoch }` shape the
 * epoch-refresh readers bucket on: an `UnknownEpochError` (a rekey the cached
 * descriptor has not caught up to) becomes the refresh signal, and any other
 * failure is logged and degrades to `undefined`, so the caller can fall back
 * to the raw envelope. A `KeyUnwrapError` (the epoch is on the descriptor but
 * this wallet holds no key for it) is one of those other failures: it is never
 * the refresh signal, since no refresh can grant a key.
 *
 * @param options {object}
 * @param options.cipher {DocCipher}
 * @param options.envelope {Json}
 * @param options.source {string}   how the failure names the collection, e.g.
 *   `collection "private-credentials"`
 * @returns {Promise<{ value: Json | undefined, unknownEpoch: boolean }>}
 */
async function decryptEnvelope({
  cipher,
  envelope,
  source
}: {
  cipher: DocCipher
  envelope: Json
  source: string
}): Promise<{ value: Json | undefined; unknownEpoch: boolean }> {
  try {
    return { value: await cipher.decrypt({ envelope }), unknownEpoch: false }
  } catch (err) {
    const failure = classifyDecryptFailure(err)
    if (failure === 'unknown-epoch') {
      return { value: undefined, unknownEpoch: true }
    }
    if (failure === 'no-epoch-key') {
      log.warn(
        'This wallet is not a recipient of the key epoch of a resource',
        {
          source,
          err
        }
      )
      return { value: undefined, unknownEpoch: false }
    }
    log.warn('Could not decrypt resource envelope', { source, err })
    return { value: undefined, unknownEpoch: false }
  }
}

// The `wallet-activity` builder each single-credential activity verb records
// through. One entry per `CredentialActivityVerb`, so the History page's
// reader vocabulary and the writer's are the same set.
const CREDENTIAL_ACTIVITY_BUILDERS: Record<
  CredentialActivityVerb,
  (options: {
    cid: string
    title: string
    user: User
    id: string
  }) => WalletActivity
> = {
  created: buildHistoryCredentialCreated,
  deleted: buildHistoryCredentialDeleted,
  shared: buildHistoryCredentialShared,
  unshared: buildHistoryCredentialUnshared
}

// The WAS collection ids of the encrypted standard collections -- the set
// whose descriptors are acquired at session start and refreshed on an
// unknown-epoch read.
const ENCRYPTED_COLLECTION_IDS = ENCRYPTED_STANDARD_COLLECTIONS.map(
  ({ id }) => id
)

/**
 * Descriptors for a session with no remote store (a guest, or no WAS server
 * configured). Every encrypted collection still carries a key-epoch roster
 * from birth, so each collection gets a local one-epoch descriptor wrapped to
 * the session's vault KAK alone -- minted on first use and persisted in the
 * session's descriptor cache, scoped by the user's DID in place of a Space
 * id, so a returning local login rebuilds the same epoch and keeps
 * decrypting its own rows. A guest's identity is random per session and its
 * data dies with it, so a guest's persistence strategy supplies an in-memory
 * cache and its descriptors die with the session.
 *
 * @param options {object}
 * @param options.cache {EncryptionDescriptorCache}   the session's cache
 *   for the `local:<clientDid>` scope (in-memory for a guest)
 * @param options.keyAgreementKey {IKeyAgreementKey}   the vault KAK epoch[0]
 *   wraps to
 * @returns {Promise<Record<string, CollectionEncryption>>}   keyed by
 *   collection id
 */
async function localOnlyDescriptors({
  cache,
  keyAgreementKey
}: {
  cache: EncryptionDescriptorCache
  keyAgreementKey: IKeyAgreementKey
}): Promise<Record<string, CollectionEncryption>> {
  const entries = await Promise.all(
    ENCRYPTED_COLLECTION_IDS.map(async collectionId => {
      const cached = await cache.readDescriptor({ collectionId })
      if (cached?.epochs?.length) {
        return [collectionId, cached] as const
      }
      const minted = await mintRecordEncryption({ keyAgreementKey })
      await cache.writeDescriptor({ collectionId, descriptor: minted })
      return [collectionId, minted] as const
    })
  )
  return Object.fromEntries(entries)
}

/**
 * Logs a swallowed descriptor-fetch failure (the cached-fallback branch of
 * `acquireDescriptors`).
 *
 * @param err {unknown}
 * @param info {object}
 * @param info.collectionId {string}
 */
function warnDescriptorFetchError(
  err: unknown,
  { collectionId }: { collectionId: string }
): void {
  log.warn(
    'Could not fetch the encryption descriptor for collection; falling back to the cached copy',
    { collectionId, err }
  )
}

/**
 * A session's reach into the per-collection descriptor logs: the verifying
 * read side every descriptor acquisition goes through, and the per-collection
 * store each descriptor-writing operation appends through. Absent when the
 * session has no promoted account to verify against (no remote store, or a
 * pointer naming no did:webvh), in which case descriptors come from the
 * browser-local cache alone and no descriptor write can run.
 */
export interface DescriptorLogs {
  source: EncryptionDescriptorSource
  storeFor: (collectionId: string) => Promise<EncryptionDescriptorStore>
}

/**
 * The live session's descriptor logs: reads and appends anchored in the
 * profile's verified-log memo, requests through the remote store's handles,
 * appends signed by the session's descriptor-log signer (the enrolled
 * client's key, or a transient visit's ladder VM). The signer is resolved
 * at each store build, since a passphrase change restamps the ladder seed.
 *
 * @param options {object}
 * @param options.session {object}   the live session's profile and
 *   persistence strategy
 * @param options.remoteStore {WASRemoteStore}
 * @returns {DescriptorLogs}
 */
function sessionDescriptorLogs({
  session,
  remoteStore
}: {
  session: SessionCore
  remoteStore: WASRemoteStore
}): DescriptorLogs {
  return {
    source: sessionCollectionDescriptorSource({ session, remoteStore }),
    storeFor: async collectionId =>
      sessionCollectionStores({
        session,
        remoteStore,
        keyAgent: await descriptorLogSignerAgent({ session })
      })(collectionId)
  }
}

/**
 * Wraps the descriptor cache so a write that regresses the cached copy -- a
 * served head listing fewer epochs than this browser last verified -- is
 * warned about and then written. The cache is not a continuity pin: a log
 * behind the copy looks exactly like replication lag, so it overwrites
 * rather than refuses (the roster's rollback carve-out, applied here).
 *
 * @param cache {EncryptionDescriptorCache}
 * @returns {EncryptionDescriptorCache}
 */
function regressionWarningCache(
  cache: EncryptionDescriptorCache
): EncryptionDescriptorCache {
  return {
    readDescriptor: options => cache.readDescriptor(options),
    async writeDescriptor({ collectionId, descriptor }) {
      const cached = await cache.readDescriptor({ collectionId })
      const before = cached?.epochs?.length ?? 0
      const after = descriptor.epochs?.length ?? 0
      // Epochs are append-only, so a shorter list is a head behind the copy,
      // and so is a current epoch the copy lists at an earlier position than
      // its own current one.
      const position = (
        list: CollectionEncryption['epochs'],
        epochId: string | undefined
      ) => (list ?? []).findIndex(epoch => epoch.id === epochId)
      const cachedCurrent = position(cached?.epochs, cached?.currentEpoch)
      const servedCurrent = position(cached?.epochs, descriptor.currentEpoch)
      const currentRegressed =
        cachedCurrent >= 0 &&
        servedCurrent >= 0 &&
        servedCurrent < cachedCurrent
      if (after < before || currentRegressed) {
        log.warn(
          'The served encryption descriptor is behind the cached copy; overwriting the cache',
          {
            collectionId,
            cachedEpochs: before,
            servedEpochs: after,
            cachedCurrentEpoch: cached?.currentEpoch,
            servedCurrentEpoch: descriptor.currentEpoch
          }
        )
      }
      await cache.writeDescriptor({ collectionId, descriptor })
    }
  }
}

/**
 * Fetches each encrypted collection's stored `/meta` value best-effort
 * (concurrently, like the descriptor acquisition it rides beside), caching
 * each success and falling back to the cached copy on a fetch failure. A
 * collection with no stored metadata gets no entry -- its cipher then has no
 * schema to install, which is exactly the no-index case.
 *
 * @param options {object}
 * @param options.source {object}   the `collectionMeta` fetch (the remote
 *   store)
 * @param [options.cache] {object}   the localStorage meta cache
 * @param options.collectionIds {string[]}
 * @returns {Promise<Record<string, { custom?: unknown }>>}   keyed by WAS
 *   collection id
 */
async function acquireCollectionMetas({
  source,
  cache,
  collectionIds
}: {
  source: {
    collectionMeta(options: {
      collectionId: string
    }): Promise<{ custom?: unknown } | undefined>
  }
  cache?: CollectionMetaCache
  collectionIds: string[]
}): Promise<Record<string, { custom?: unknown }>> {
  const entries = await Promise.all(
    collectionIds.map(async collectionId => {
      try {
        const meta = await source.collectionMeta({ collectionId })
        if (meta !== undefined) {
          await cache?.writeMeta({ collectionId, meta })
          return [collectionId, meta] as const
        }
        return undefined
      } catch (err) {
        log.warn(
          'Could not fetch the stored metadata for collection; falling back to the cached copy',
          { collectionId, err }
        )
      }
      const cached = await cache?.readMeta({ collectionId })
      return cached !== undefined
        ? ([collectionId, cached] as const)
        : undefined
    })
  )
  return Object.fromEntries(entries.filter(entry => entry !== undefined))
}

/**
 * Thrown when a credential's live public copy could not be retracted, so the
 * delete of the private credential was refused rather than left to strand a
 * world-readable orphan. See {@link StorageManager.deleteCredential}.
 */
export class PublicCopyRetractionError extends Error {
  cid: string

  constructor({ cid, cause }: { cid: string; cause?: unknown }) {
    super(
      `Could not retract the public copy of credential "${cid}"; ` +
        'the credential was not deleted.',
      { cause }
    )
    this.name = 'PublicCopyRetractionError'
    this.cid = cid
  }
}

/**
 * Manages storage operations for the wallet and a logged-in user profile:
 * routes all wallet reads/writes to the local active replica and exposes the
 * optional remote WAS backend for replication and remote-only features.
 */
export class StorageManager {
  // The local active replica -- absent in the replica-less (transient)
  // variant, where constructing one would create the per-user RxDB database
  // in this browser and every synced-collection operation is served
  // remote-direct.
  #localStore?: BrowserStore
  #remoteStore?: WASRemoteStore // Only set if VITE_WAS_SERVER_URL env var is present
  // The backend every synced-collection read/write routes through, chosen once
  // at construction: the local active replica, or the remote-direct popup
  // backend. Never re-forked per operation.
  #store: SyncedCollectionStore
  // Whether the remote-direct backend is the one selected (drives the read
  // readiness contract: its reads need no local provisioning).
  #remoteDirect: boolean
  // The per-collection document ciphers, kept here for the storage browser's own
  // decrypt at the WAS seam (`decryptCollectionResource`) and rebuilt on a
  // descriptor refresh.
  #ciphers?: Record<string, DocCipher>
  // The provisioning promise from `ensureUserCollections` (fired at session
  // creation), awaited by the read-readiness contract in non-remote-direct mode.
  #provisioning?: Promise<void>
  // The keystore promotion this session fired, from whichever call to
  // `ensurePromotedController` ran first: provisioning's, or the login
  // block's pointer heal. Read by the block's tail registration, so the one
  // promotion a login runs is the one it reports.
  #keystorePromotion?: Promise<MendOutcome>
  // The vault key material, kept so ciphers can be rebuilt after a descriptor
  // refresh (an unknown-epoch read) without re-plumbing the profile.
  #vaultKeys?: {
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
  }
  // The last-known per-collection encryption descriptors, keyed by WAS collection
  // id, that the current ciphers were built from.
  #descriptors: Record<string, CollectionEncryption>
  // The last-known per-collection stored `/meta` values (the `custom` envelope
  // carrying the persisted blinded-index schema), keyed by WAS collection id,
  // installed onto the ciphers at every (re)build so wallet writes emit
  // blinded `indexed` entries. Acquired and refreshed beside the descriptors.
  #metas: Record<string, { custom?: unknown }>
  // The descriptor cache for this account's Space -- localStorage or
  // in-memory by the session's persistence strategy -- the offline fallback
  // descriptor acquisition falls back to. Only set with a remote store (a
  // guest / no-WAS session has no descriptors to cache).
  #descriptorCache?: EncryptionDescriptorCache
  // The collection-metadata cache, beside the descriptor cache and on the
  // same storage tier.
  #metaCache?: CollectionMetaCache
  // The per-collection descriptor logs (see `DescriptorLogs`): the verifying
  // source every descriptor refresh reads, and the stores every descriptor
  // write appends through. Resolved at each use rather than once, since a
  // login-time genesis can promote the account after the session was built;
  // `undefined` while there is no promoted account to verify against.
  #descriptorLogsFor: () => DescriptorLogs | undefined
  // The verified account document's reading a grant revocation checks
  // against (see `AccountSignerCheck`), resolved lazily from the session
  // layer at each revocation rather than once, since a login-time genesis
  // can promote the account after the session was built, and the read is
  // memoized for the session's lifetime upstream. Resolves `undefined` when
  // the session has no promoted account to check against.
  #signerCheckFor: () => Promise<AccountSignerCheck | undefined>
  // The once-per-collection-per-session unknown-epoch refresh guard, shared by
  // the standard and the app-provisioned encrypted collections, so a genuinely
  // foreign envelope cannot drive a refresh loop. Its `reset` re-arms a
  // collection whenever a share / unshare / recipient rotation installs a
  // fresh descriptor.
  #refreshPolicy = new DescriptorRefreshPolicy({
    refresh: async ({ collectionId }) => {
      if (ENCRYPTED_COLLECTION_IDS.includes(collectionId)) {
        await this.#refreshDescriptors()
      } else {
        // An app-provisioned collection: drop the cached descriptor and cipher so
        // the re-read rebuilds them from a fresh Description fetch.
        delete this.#appDescriptors[collectionId]
        delete this.#appCiphers[collectionId]
      }
    }
  })
  // Lazily-built per-collection ciphers for App Connect app-provisioned
  // (non-standard) encrypted collections, keyed by WAS collection id. The
  // wallet decrypts these as an ordinary recipient with its vault KAK (recipient
  // zero), driven by the collection's fetched descriptor; built on first
  // decrypt-read from the storage browser, invalidated when a rekey lands.
  #appCiphers: Record<string, DocCipher> = {}
  // The descriptors the `#appCiphers` entries were built from, keyed by WAS
  // collection id -- the offline/lazy source for an app collection's cipher.
  #appDescriptors: Record<string, CollectionEncryption> = {}
  // The session's typed persistence strategy: the writer id and the cache
  // pair come from it, so their storage tier is the strategy's rather than a
  // flag here.
  #persistence: SessionPersistence

  constructor({
    localStore,
    remoteStore,
    ciphers,
    remoteDirect = false,
    vaultKeys,
    descriptors,
    metas,
    persistence,
    descriptorLogs,
    signerCheck
  }: {
    localStore?: BrowserStore
    remoteStore?: WASRemoteStore
    ciphers?: Record<string, DocCipher>
    remoteDirect?: boolean
    vaultKeys?: {
      keyAgreementKey: IKeyAgreementKey
      keyResolver: IKeyResolver
    }
    descriptors?: Record<string, CollectionEncryption>
    metas?: Record<string, { custom?: unknown }>
    persistence: SessionPersistence
    descriptorLogs?: DescriptorLogs | (() => DescriptorLogs | undefined)
    signerCheck?: () => Promise<AccountSignerCheck | undefined>
  }) {
    this.#localStore = localStore
    this.#remoteStore = remoteStore
    this.#ciphers = ciphers
    this.#vaultKeys = vaultKeys
    this.#descriptors = descriptors ?? {}
    this.#metas = metas ?? {}
    this.#persistence = persistence
    this.#descriptorLogsFor =
      typeof descriptorLogs === 'function'
        ? descriptorLogs
        : () => descriptorLogs
    this.#signerCheckFor = signerCheck ?? (async () => undefined)
    // The cache pair rides the persistence strategy: one instance per scope
    // per session (the strategy memoizes), localStorage or in-memory by the
    // strategy's storage tier, and absent only when there is no remote Space
    // to cache for.
    this.#descriptorCache = remoteStore
      ? regressionWarningCache(
          persistence.descriptorCache({ scope: remoteStore.spaceId })
        )
      : undefined
    this.#metaCache = remoteStore
      ? persistence.metaCache({ scope: remoteStore.spaceId })
      : undefined
    // Remote-direct routing is only meaningful when a remote store is configured
    // (a guest / no-WAS session always uses the local BrowserStore). A
    // replica-less construction -- no local store at all, the transient
    // variant -- is remote-direct outright, so it requires a remote store.
    if (!localStore && !remoteStore) {
      throw new Error('Replica-less storage requires a remote WAS store.')
    }
    this.#remoteDirect = (remoteDirect || !localStore) && !!remoteStore
    this.#store = this.#remoteDirect
      ? new RemoteDirectStore({
          remoteStore: remoteStore!,
          ciphers: ciphers ?? {}
        })
      : localStore!
  }

  /**
   * Whether this session carries the local active replica. False exactly for
   * the replica-less remote-direct variant (a transient session), whose
   * synced-collection operations never touch a local database -- so the sync
   * controller has no local end to replicate and must not start.
   *
   * @returns {boolean}
   */
  get hasLocalReplica(): boolean {
    return this.#localStore !== undefined
  }

  /**
   * Resolves when the active storage backend can serve reads: the local active
   * replica's collections being open (part of the provisioning `storageReady`
   * runs), or nothing at all in the popup's remote-direct mode (reads hit the
   * remote collections directly and need no local provisioning). Full
   * provisioning -- the remote Space and did:web -- runs in the background as
   * `session.storageReady`; a caller awaits that separately where a grant needs
   * the Space to exist.
   *
   * @returns {Promise<void>}
   */
  async ready(): Promise<void> {
    if (this.#remoteDirect) {
      return
    }
    await this.#provisioning
  }

  /**
   * The remote backend, or a throw naming what needed it. The one place a
   * remote-only operation states its precondition; the operations that
   * degrade to an empty result without a remote keep their own `if` instead.
   *
   * @param action {string}   what the caller was doing, as the message opens
   *   ("Sharing a collection requires remote storage.")
   * @returns {WASRemoteStore}
   */
  #requireRemote(action: string): WASRemoteStore {
    if (!this.#remoteStore) {
      throw new Error(`${action} requires remote storage.`)
    }
    return this.#remoteStore
  }
  /**
   * The log-governed descriptor store for one encrypted collection, for a
   * descriptor-writing operation; refuses when this session has no descriptor
   * logs to append through (no promoted account to verify against).
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.action {string}   what the caller is doing, for the message
   * @returns {Promise<EncryptionDescriptorStore>}
   */
  async #collectionStore({
    collectionId,
    action
  }: {
    collectionId: string
    action: string
  }): Promise<EncryptionDescriptorStore> {
    const logs = this.#descriptorLogsFor()
    if (!logs) {
      throw new Error(
        `${action} requires a promoted account whose collection descriptor ` +
          'logs this session can verify.'
      )
    }
    return await logs.storeFor(collectionId)
  }

  /**
   * One collection's descriptor from the verified head of its governing log
   * (`undefined` for a collection with no log, a plaintext one), or from the
   * served Description member when this session has no logs to verify.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @returns {Promise<CollectionEncryption | undefined>}
   */
  async #readGovernedDescriptor({
    collectionId
  }: {
    collectionId: string
  }): Promise<CollectionEncryption | undefined> {
    const logs = this.#descriptorLogsFor()
    if (logs) {
      return await logs.source.collectionEncryption({ collectionId })
    }
    return await this.#requireRemote(
      'Reading a collection descriptor'
    ).collectionEncryption({ collectionId })
  }

  /**
   * Whether a remote WAS backend is configured for this session. Pages use this
   * instead of reaching into the backend directly.
   */
  get hasRemoteStorage(): boolean {
    return !!this.#remoteStore
  }

  /**
   * The remote Space id, or undefined when there is no remote backend.
   */
  get spaceId(): string | undefined {
    return this.#remoteStore?.spaceId
  }

  /**
   * The remote WAS client, or undefined when there is no remote backend. Used by
   * the sync controller to drive background replication against remote Collection
   * replicas (it signs with the same session key).
   */
  get wasClient(): WASRemoteStore['was'] | undefined {
    return this.#remoteStore?.was
  }

  /**
   * The remote Space URL, or undefined when there is no remote backend.
   */
  get spaceUrl(): string | undefined {
    return this.#remoteStore?.spaceUrl
  }

  /**
   * The remote Space's structural coordinates -- the storage server's base URL
   * and the Space id -- or undefined when there is no remote backend. Zcap
   * grant resolution takes the pair rather than the Space URL, so it forms
   * every target through was-client's path builders instead of parsing a URL
   * back apart.
   */
  get spaceLocation(): SpaceLocation | undefined {
    const remote = this.#remoteStore
    if (!remote) {
      return undefined
    }
    return { serverUrl: remote.storageServerUrl, spaceId: remote.spaceId }
  }

  /**
   * The world-readable URL the account's did:web projection resolves to, or
   * undefined when there is no remote backend. The projection is the
   * did:webvh document under its did:web id, written by the log's own
   * projection rather than minted separately, so a promoted account pointer
   * is what says a document stands there; this getter only names the URL.
   */
  get publishedDidUrl(): string | undefined {
    return this.#remoteStore?.didDocumentUrl()
  }

  /**
   * The remote WAS store, or undefined when there is no remote backend. Exposed
   * for the did:webvh rotation ceremony (`rotateWebvhUpdateKey`), which reads
   * and rewrites the `id` collection's `did.jsonl` / `did.json` and the
   * `key-map` collection's `keys.json` directly through it.
   */
  get remoteStore(): WASRemoteStore | undefined {
    return this.#remoteStore
  }

  /**
   * The live local RxDB collection backing one of the wallet's standard
   * logical collections. The one member of this facade typed in RxDB terms,
   * and the one caller is the sync binding, which puts it behind the injected
   * port the replication core reads its local end through.
   *
   * @param logicalKey {string} e.g. 'publicCredentials'.
   * @returns {RxCollection<SyncedDoc>}
   */
  localCollection(logicalKey: string): RxCollection<SyncedDoc> {
    if (!this.#localStore) {
      throw new Error(
        'This session has no local replica (replica-less remote-direct ' +
          'storage); nothing can replicate.'
      )
    }
    return this.#localStore.rxCollection(logicalKey)
  }

  /**
   * Builds the per-collection document ciphers for the encrypted standard
   * collections from a session's key material (the vault KAK and its resolver).
   * When a collection has a multi-recipient encryption descriptor (its `descriptors`
   * entry, keyed by WAS collection id), the cipher is built epoch-aware from
   * it; without one it is the single-key path, unchanged.
   *
   * @param options {object}
   * @param options.keyAgreementKey {IKeyAgreementKey}
   * @param options.keyResolver {IKeyResolver}
   * @param [options.descriptors] {Record<string, CollectionEncryption>}   per-
   *   collection encryption descriptors, keyed by WAS collection id
   * @param [options.metas] {Record<string, { custom?: unknown }>}   per-
   *   collection stored `/meta` values, keyed by WAS collection id; a
   *   collection whose descriptor declares a blinded-index key gets its
   *   persisted index schema installed from it, so wallet writes carry the
   *   same blinded `indexed` entries a Collection-handle write does
   * @param [options.refresh] {object}   the descriptor source and cache the
   *   contacts cipher's own unknown-epoch refresh re-reads through; absent
   *   when the session has no remote Space
   * @returns {Promise<Record<string, DocCipher>>}
   */
  static async #buildCiphers({
    keyAgreementKey,
    keyResolver,
    descriptors,
    metas,
    refresh
  }: {
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
    descriptors?: Record<string, CollectionEncryption>
    metas?: Record<string, { custom?: unknown }>
    refresh?: {
      source?: EncryptionDescriptorSource
      cache: EncryptionDescriptorCache
    }
  }) {
    const cipherEntries = await Promise.all(
      ENCRYPTED_STANDARD_COLLECTIONS.map(collection =>
        StorageManager.#buildCipher({
          collection,
          keyAgreementKey,
          keyResolver,
          descriptor: descriptors?.[collection.id],
          meta: metas?.[collection.id],
          refresh
        })
      )
    )
    return Object.fromEntries(cipherEntries)
  }

  /**
   * Builds one standard encrypted collection's cipher, as the logical-key /
   * cipher pair the cipher map is keyed by. The per-collection half of
   * {@link StorageManager.#buildCiphers}, so the whole-map rebuild and the
   * single-collection one cannot drift.
   *
   * @param options {object}
   * @param options.collection {object}   the collection's spec entry
   * @param options.collection.key {string}   its logical key
   * @param options.collection.id {string}   its WAS collection id
   * @param options.collection.idDerivation {IdDerivation}   its id mint
   * @param options.keyAgreementKey {IKeyAgreementKey}
   * @param options.keyResolver {IKeyResolver}
   * @param [options.descriptor] {CollectionEncryption}
   * @param [options.meta] {object}   the collection's stored `/meta` value
   * @param [options.refresh] {object}   the descriptor source and cache the
   *   contacts cipher's own unknown-epoch refresh re-reads through
   * @returns {Promise<[string, DocCipher]>}
   */
  static async #buildCipher({
    collection: { key, id, idDerivation },
    keyAgreementKey,
    keyResolver,
    descriptor,
    meta,
    refresh
  }: {
    collection: (typeof ENCRYPTED_STANDARD_COLLECTIONS)[number]
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
    descriptor?: CollectionEncryption
    meta?: { custom?: unknown }
    refresh?: {
      source?: EncryptionDescriptorSource
      cache: EncryptionDescriptorCache
    }
  }): Promise<[string, DocCipher]> {
    // Every encrypted collection carries its key epochs from
    // provisioning, so a missing (or epoch-less) descriptor -- an
    // unprovisioned or torn collection, or an offline session with
    // nothing cached -- gets a fail-closed cipher rather than none: an
    // absent cipher would fall through to the store's cipher-less
    // plaintext path, silently storing (and pushing) plaintext into an
    // encrypted collection, and an epoch-less descriptor would make the
    // whole rebuild throw, taking the healthy collections down with it.
    if (!descriptor?.epochs?.length) {
      return [key, StorageManager.#refusingCipher({ collectionId: id })]
    }
    // The contacts head is decrypted inside the sync driver's conflict
    // handler, out of reach of the session's read-level refresh guard, so
    // its cipher carries the unknown-epoch refresh itself. It declares no
    // blinded index, so the index-schema install below has nothing to
    // apply to it.
    if (id === CONTACTS_COLLECTION) {
      const cipher = await refreshingCollectionCipher({
        collectionId: id,
        idDerivation,
        descriptor,
        keyAgreementKey,
        keyResolver,
        ...refresh,
        onFetchError: warnDescriptorFetchError
      })
      return [key, cipher]
    }
    const cipher = await createEdvDocCipher({
      keyAgreementKey,
      keyResolver,
      collectionId: id,
      // The collection spec's id mint ('random' for the mutable
      // contacts head, 'content' for the content-addressed
      // collections), so a minted id follows the spec and can key
      // the row.
      idDerivation,
      encryption: descriptor
    })
    await StorageManager.#installIndexSchema({
      cipher,
      collectionId: id,
      meta
    })
    return [key, cipher]
  }

  /**
   * Installs a collection's persisted blinded-index schema onto a
   * freshly-built cipher, best-effort: indexing is auxiliary to encryption, so
   * a metadata value the cipher cannot decode (a stale cached copy sealed
   * under an epoch this descriptor no longer lists, say) degrades to the
   * schema-less cipher -- writes stay encrypted, they just carry no `indexed`
   * entries until the next refresh -- rather than failing the whole cipher
   * build. `applyMeta` itself is a no-op on a collection whose descriptor
   * declares no blinded-index key.
   *
   * @param options {object}
   * @param options.cipher {EdvDocCipher}
   * @param options.collectionId {string}
   * @param [options.meta] {object}   the collection's stored `/meta` value
   * @returns {Promise<void>}
   */
  static async #installIndexSchema({
    cipher,
    collectionId,
    meta
  }: {
    cipher: EdvDocCipher
    collectionId: string
    meta?: { custom?: unknown }
  }): Promise<void> {
    if (meta === undefined) {
      return
    }
    try {
      await cipher.applyMeta(meta)
    } catch (err) {
      log.warn(
        'Could not install the index schema for collection; writes will ' +
          'carry no blinded index entries until the metadata refreshes',
        { collectionId, err }
      )
    }
  }

  /**
   * A {@link DocCipher} that refuses every operation: the stand-in for an
   * encrypted collection whose descriptor could not be acquired. The refusal
   * clears when a descriptor refresh rebuilds the ciphers.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @returns {DocCipher}
   */
  static #refusingCipher({
    collectionId
  }: {
    collectionId: string
  }): DocCipher {
    const refuse = (): never => {
      throw new Error(
        `Collection "${collectionId}" has no encryption descriptor available ` +
          '(fetched or cached). Every encrypted collection carries its key ' +
          'epochs from provisioning; refusing to read or write without them.'
      )
    }
    return {
      encrypt: async () => refuse(),
      encryptUpdate: async () => refuse(),
      decrypt: async () => refuse()
    }
  }

  /**
   * The descriptor source and cache a self-refreshing cipher re-reads
   * through, resolved at each build since a login-time genesis can promote
   * the account after the session was built. Absent without a remote Space.
   *
   * @returns {object | undefined}
   */
  #cipherRefresh():
    | { source?: EncryptionDescriptorSource; cache: EncryptionDescriptorCache }
    | undefined {
    if (!this.#descriptorCache) {
      return undefined
    }
    const source = this.#descriptorLogsFor()?.source
    return { ...(source ? { source } : {}), cache: this.#descriptorCache }
  }

  /**
   * Rebuilds the per-collection ciphers from the current descriptors and the held
   * vault keys, then swaps them into the local store (and this facade). No-op
   * without vault keys.
   *
   * @returns {Promise<void>}
   */
  async #rebuildCiphers(): Promise<void> {
    if (!this.#vaultKeys) {
      return
    }
    const ciphers = await StorageManager.#buildCiphers({
      keyAgreementKey: this.#vaultKeys.keyAgreementKey,
      keyResolver: this.#vaultKeys.keyResolver,
      descriptors: this.#descriptors,
      metas: this.#metas,
      refresh: this.#cipherRefresh()
    })
    this.#ciphers = ciphers
    // Swap into the active backend (the local store in the normal case, the
    // remote-direct backend in the popup); both honor `setCiphers` for the
    // descriptor-refresh path.
    this.#store.setCiphers(ciphers)
  }

  /**
   * Rebuilds ONE standard encrypted collection's cipher from its current
   * descriptor and swaps the refreshed map into the backend -- what a share
   * or an unshare needs, each of which rotates a single collection. The
   * whole-map rebuild above stays the descriptor-refresh path's, which moves
   * every collection at once. A collection id that is not a standard
   * encrypted collection (an app-provisioned one, whose cipher is built
   * lazily per read) is a no-op, as is a session holding no vault keys.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id
   * @returns {Promise<void>}
   */
  async #rebuildCipherFor({
    collectionId
  }: {
    collectionId: string
  }): Promise<void> {
    if (!this.#vaultKeys) {
      return
    }
    const collection = ENCRYPTED_STANDARD_COLLECTIONS.find(
      ({ id }) => id === collectionId
    )
    if (!collection) {
      return
    }
    const [key, cipher] = await StorageManager.#buildCipher({
      collection,
      keyAgreementKey: this.#vaultKeys.keyAgreementKey,
      keyResolver: this.#vaultKeys.keyResolver,
      descriptor: this.#descriptors[collectionId],
      meta: this.#metas[collectionId],
      refresh: this.#cipherRefresh()
    })
    this.#ciphers = { ...this.#ciphers, [key]: cipher }
    this.#store.setCiphers(this.#ciphers)
  }

  /**
   * Refreshes every encrypted collection's descriptor -- and its stored
   * `/meta`, so an index schema declared mid-session reaches the rebuilt
   * ciphers -- from the remote store, caches them, and rebuilds + swaps the
   * ciphers. Called when a local read reports unknown-epoch rows -- a rekey
   * emits no change-feed entry, so the local cipher may be built from a stale
   * descriptor. No-op without a remote store or vault keys.
   *
   * @returns {Promise<void>}
   */
  async #refreshDescriptors(): Promise<void> {
    if (!this.#remoteStore || !this.#vaultKeys || !this.#descriptorCache) {
      return
    }
    const logs = this.#descriptorLogsFor()
    ;[this.#descriptors, this.#metas] = await Promise.all([
      acquireDescriptors({
        ...(logs ? { source: logs.source } : {}),
        cache: this.#descriptorCache,
        collectionIds: ENCRYPTED_COLLECTION_IDS,
        onFetchError: warnDescriptorFetchError
      }),
      acquireCollectionMetas({
        source: this.#remoteStore,
        cache: this.#metaCache,
        collectionIds: ENCRYPTED_COLLECTION_IDS
      })
    ])
    await this.#rebuildCiphers()
  }

  /**
   * Takes a rotated user key's vault key material without touching the
   * ciphers -- the in-band half of a rotation, which runs while every
   * collection still carries the epoch the rotation is about to retire.
   * Rebuilding there would ask the fresh key to open an epoch it is not yet a
   * recipient of, so the ciphers keep the material they were built from until
   * {@link adoptRotatedVaultKeys} (or
   * {@link refreshEncryptedDescriptors}) runs past the collection fan-out.
   *
   * @param options {object}
   * @param options.keyAgreementKey {IKeyAgreementKey}   the fresh user key's KAK
   * @param options.keyResolver {IKeyResolver}
   * @returns {void}
   */
  holdRotatedVaultKeys({
    keyAgreementKey,
    keyResolver
  }: {
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
  }): void {
    this.#vaultKeys = { keyAgreementKey, keyResolver }
  }

  /**
   * Adopts a rotated user key's vault keys into the live session's storage -- the
   * tail of the revocation cascade: once the roster and the collections have
   * moved to a fresh user key, the session that drove the rotation (it minted the
   * key, so it holds it) swaps its vault key material, refetches the rotated
   * descriptors, and rebuilds the ciphers, so it keeps reading and writing
   * without a re-login. The app-collection cipher caches are dropped too (they
   * were built from the old vault KAK) and rebuild lazily on next decrypt.
   *
   * Its one ordering rule: the collection fan-out must already have run, or
   * the refetched descriptors still name epochs the fresh key cannot open.
   * The in-band step that precedes the fan-out takes
   * {@link holdRotatedVaultKeys} instead.
   *
   * @param options {object}
   * @param options.keyAgreementKey {IKeyAgreementKey}   the fresh user key's KAK
   * @param options.keyResolver {IKeyResolver}
   * @returns {Promise<void>}
   */
  async adoptRotatedVaultKeys({
    keyAgreementKey,
    keyResolver
  }: {
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
  }): Promise<void> {
    this.holdRotatedVaultKeys({ keyAgreementKey, keyResolver })
    await this.refreshEncryptedDescriptors()
  }

  /**
   * Refetches every encrypted collection's descriptor and rebuilds + swaps
   * the ciphers under the vault keys already held -- the tail of the
   * cascade-completion sweep, which can move a collection's current epoch
   * (completing a cascade another client crashed partway through) AFTER this
   * session's ciphers were built at login: without the refresh, every later
   * write would stay sealed under the retired epoch the revoked party can
   * still decrypt. The app-collection cipher caches are dropped too and
   * rebuild lazily on next decrypt.
   *
   * @returns {Promise<void>}
   */
  async refreshEncryptedDescriptors(): Promise<void> {
    this.#appCiphers = {}
    this.#appDescriptors = {}
    if (this.#remoteStore && this.#descriptorCache) {
      await this.#refreshDescriptors()
    } else {
      await this.#rebuildCiphers()
    }
    this.#refreshPolicy.reset()
  }

  /**
   * Runs a read that reports whether it skipped unknown-epoch rows; on the first
   * such report for a collection this session, refreshes the descriptor (rebuilding
   * + swapping the ciphers) and re-reads once, via the shared
   * `DescriptorRefreshPolicy`. The single seam behind `listCredentials`,
   * `listHistoryItems`, and `decryptCollectionResource`, so a fresh-epoch
   * resource is never silently dropped after a rekey by another client -- for
   * either backend, since the remote-direct backend surfaces the same counts.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id
   * @param options.read {() => Promise<{ value: T; unknownEpoch: boolean }>}
   * @returns {Promise<T>}
   */
  async #readWithEpochRefresh<T>({
    collectionId,
    read
  }: {
    collectionId: string
    read: () => Promise<{ value: T; unknownEpoch: boolean }>
  }): Promise<T> {
    // A refresh needs a remote store and the vault keys; without them, serve
    // the single read as-is (and leave the policy's guard unspent).
    if (!this.#remoteStore || !this.#vaultKeys) {
      return (await read()).value
    }
    return this.#refreshPolicy.readWithRefresh({ collectionId, read })
  }

  static async initStorageClients({
    user,
    session,
    serviceDescription,
    isGuest = false,
    remoteDirect = false,
    storage: rxStorage,
    descriptorLogs: suppliedDescriptorLogs,
    signerCheck
  }: {
    user: User
    // The profile the clients sign as, and the session's persistence
    // strategy: it decides whether a local replica is built, carries the
    // descriptor/meta caches, and pins the chain heads.
    session: SessionCore
    // The service description this login discovered, threaded in so nothing
    // below re-probes. Absent when the server could not be reached: the
    // remote store is still built (its clients discover at their first
    // request), so a remembered login keeps running off the local replica
    // offline.
    serviceDescription?: ServiceDescription
    isGuest?: boolean
    // Route credential + history operations straight to the remote WAS
    // collections (the CHAPI popup path, whose local IndexedDB is partitioned).
    remoteDirect?: boolean
    // An explicit RxDB storage for the local active replica, in place of the
    // default IndexedDB/Dexie one (the unit tests' memory storage).
    storage?: RxStorage<unknown, unknown>
    // The per-collection descriptor logs, in place of the ones built from
    // the profile (the unit tests' in-memory stores).
    descriptorLogs?: DescriptorLogs
    // The verified account document's reading a grant revocation checks
    // against, resolved lazily from the session layer (which holds the
    // session this manager becomes part of); absent, no grant is skipped on
    // the document's reading.
    signerCheck?: () => Promise<AccountSignerCheck | undefined>
  }) {
    // Guest sessions never touch the remote WAS server -- they get no remote
    // replica. This keeps guest mode usable as a fallback even when the
    // configured WAS server is unreachable.
    const storageServerUrl = isGuest ? undefined : WAS_SERVER_URL
    log.info('Initializing storage clients', { storageServerUrl })

    const { profile, persistence } = session
    const { keyAgreementKey, keyResolver } = profile
    if (!keyAgreementKey || !keyResolver) {
      throw new Error('A full session profile requires the key material.')
    }

    // Build the remote store first (when configured), so its encryption descriptors
    // can be fetched before the ciphers are built: a shared collection encrypts
    // under its current key epoch, discovered from the Collection Description.
    let remoteStore: WASRemoteStore | undefined
    if (storageServerUrl) {
      ;({ remoteStore } = await WASRemoteStore.initClient({
        storageServerUrl,
        serviceDescription,
        user,
        session
      }))
    }
    // Fetch the current encryption descriptor -- and the stored `/meta`,
    // whose `custom` envelope carries the persisted blinded-index schema --
    // for each encrypted standard collection best-effort (concurrently --
    // login is not gated on a serial chain of describes), caching each
    // success and falling back to the cached copy on a fetch failure. A
    // collection whose descriptor cannot be acquired gets a fail-closed
    // refusing cipher below. With no remote store (guest / no-WAS) the
    // descriptors are minted locally instead -- every encrypted collection
    // carries its key epochs from birth, server or not -- and there is no
    // metadata to fetch (no index schema can have been declared).
    //
    // Each descriptor is the verified head of the collection's governing
    // log, read under the session's pins; a verifier refusal throws through
    // rather than serving the cached copy, and only a transport failure
    // falls back to it. A remote session whose pointer names no did:webvh
    // has no document to verify against, so it reads the cache alone.
    // Resolved at each use: a login-time genesis on this session can
    // promote the account after this point, and the refresh that follows
    // must then read the logs rather than the cache.
    let sessionLogs: DescriptorLogs | undefined
    const descriptorLogsFor = (): DescriptorLogs | undefined => {
      if (!remoteStore) {
        return undefined
      }
      if (suppliedDescriptorLogs) {
        return suppliedDescriptorLogs
      }
      if (isWebvhDid(profile.accountPointer?.did)) {
        return (sessionLogs ??= sessionDescriptorLogs({ session, remoteStore }))
      }
      return undefined
    }
    const descriptorLogs = descriptorLogsFor()
    if (remoteStore && !descriptorLogs) {
      log.warn(
        'The account pointer names no did:webvh; encryption descriptors are served from the cache alone'
      )
    }
    // The same handle-memoized instance the constructor binds below (one
    // cache pair per session in both variants), seeding the in-memory pair
    // at login in a transient session.
    const descriptorCache = remoteStore
      ? regressionWarningCache(
          persistence.descriptorCache({ scope: remoteStore.spaceId })
        )
      : undefined
    const [descriptors, metas] =
      remoteStore && descriptorCache
        ? await Promise.all([
            acquireDescriptors({
              ...(descriptorLogs ? { source: descriptorLogs.source } : {}),
              cache: descriptorCache,
              collectionIds: ENCRYPTED_COLLECTION_IDS,
              onFetchError: warnDescriptorFetchError
            }),
            acquireCollectionMetas({
              source: remoteStore,
              cache: persistence.metaCache({ scope: remoteStore.spaceId }),
              collectionIds: ENCRYPTED_COLLECTION_IDS
            })
          ])
        : [
            await localOnlyDescriptors({
              cache: persistence.descriptorCache({ scope: `local:${user.id}` }),
              keyAgreementKey
            }),
            {}
          ]

    // One document cipher per encrypted collection, built from the session's
    // passphrase-derived key material (guests included -- their random secret
    // encrypts just as well; it is merely unrecoverable after logout, like the
    // rest of a guest session) plus any multi-recipient descriptor. The local store
    // holds EDV envelopes for these collections and replication ships them
    // verbatim.
    const ciphers = await StorageManager.#buildCiphers({
      keyAgreementKey,
      keyResolver,
      descriptors,
      metas,
      ...(descriptorCache
        ? {
            refresh: {
              ...(descriptorLogs ? { source: descriptorLogs.source } : {}),
              cache: descriptorCache
            }
          }
        : {})
    })

    // The local store is the active replica -- for a session on the
    // browser-local strategy. A transient session is replica-less:
    // constructing a BrowserStore creates the per-user RxDB database (the
    // versioned open alone is a browser-local write), so none is built and
    // the remote-direct backend serves every synced-collection operation
    // instead.
    let localStore: BrowserStore | undefined
    if (isBrowserLocalSession(persistence)) {
      ;({ localStore } = await BrowserStore.initClient({
        user,
        storage: rxStorage,
        ciphers
      }))
    } else if (remoteStore) {
      // A replica-less session serves every synced-collection operation
      // remote-direct, and its preconditions guarantee a promoted account
      // the account-genesis ceremony already provisioned -- so bind the
      // collection map here (pure, no network) without provisioning twice.
      // A session with a local replica keeps its map bound by
      // `ensureUserCollections` at the right time: its first signup runs
      // before provisioning, where an unbound map is a real signal.
      remoteStore.bindCollectionMap()
    }
    let userExists = localStore ? await localStore.userExists() : false
    if (remoteStore) {
      // A returning user may be on a fresh browser (no local db yet) but have
      // an existing remote Space. A transient session skips the probe -- a
      // bare-Space-URL describe a transient session must not make -- and trusts the
      // account resolution that produced it (a transient login only ever
      // proceeds from a keyring hit naming the account).
      userExists =
        userExists ||
        !isBrowserLocalSession(persistence) ||
        (await remoteStore.userExists())
    }
    const storage = new StorageManager({
      localStore,
      remoteStore,
      ciphers,
      remoteDirect,
      vaultKeys: { keyAgreementKey, keyResolver },
      descriptors,
      metas,
      persistence,
      descriptorLogs: descriptorLogsFor,
      signerCheck
    })
    return { storage, userExists }
  }

  /**
   * Stores a credential and, when a row was actually inserted (a re-add of a
   * stored credential is a no-op), records its Create history entry. Routes to
   * the active backend (the local active replica, or the remote-direct popup
   * backend).
   *
   * This is the single door every credential coming from outside the wallet
   * goes through (the CHAPI store popup, the URL / QR / manual-paste import,
   * and the credentials half of a space import), so it is where a credential
   * presenting as an app key is refused outright, whether or not it binds to
   * its own seed: app keys are wallet-minted, never imported, and the mint
   * path has its own door ({@link addMintedAppKey}). The background sync pull
   * (the driver in `@interop/was-sync`) writes pulled rows into the local
   * replica without
   * passing through here, deliberately: it replicates the account's own
   * remote collections, which only the account's enrolled wallet clients can
   * write (`private-credentials` is a protected collection -- RP and share
   * grants on it are read-only), and each of those clients enforces this same
   * refusal at its own door; the pulled bodies are also EDV envelopes the
   * sync layer could not inspect. The match-time seed binding in
   * `@interop/wallet-request` remains the backstop for anything that
   * slips past.
   *
   * @param options {object}
   * @param options.credential {IVerifiableCredential}
   * @param options.user {User}   recorded as the history entry's actor
   * @returns {Promise<void>}
   */
  async addCredential({
    credential,
    user
  }: {
    credential: IVerifiableCredential
    user: User
  }) {
    assertStorableAppKey(credential)
    await this.#putCredential({ credential, user })
  }

  /**
   * The mint path's own store door: saves an app-key credential the wallet
   * itself just minted (`processAppConnect`), which {@link addCredential}
   * would refuse -- external ingest never stores a marker credential, so the
   * one legitimate producer gets its own entry point instead of a bypass flag
   * on the shared one. Still asserts the mint invariants (`assertMintedAppKey`
   * in `@interop/wallet-request`: marker present, subject DID derived
   * from the carried seed) so this door cannot be misused to store a foreign
   * app key either.
   *
   * The row lands in the dedicated `app-connections` collection, never in
   * `private-credentials`, and no credential-created activity is written: the
   * app-connect Login activity is the record of the connection, and an app key
   * is not a credential the user acquired.
   *
   * @param options {object}
   * @param options.credential {IVerifiableCredential}
   * @returns {Promise<void>}
   */
  async addMintedAppKey({ credential }: { credential: IVerifiableCredential }) {
    await assertMintedAppKey(credential)
    const cid = await cidFrom({ doc: credential })
    await this.#store.addAppKey({ cid, credential })
  }

  /**
   * The app-key credentials of the connected applications, out of the
   * dedicated `app-connections` collection -- the match path's input and the
   * Applications page's listing. Never mixed into {@link listCredentials}: the
   * credential-wide surfaces (the dashboard, public links, shares) must not be
   * able to reach an app's private seed.
   *
   * The skipped counts are captured inside the read, right after the scan that
   * produced the listing, and travel back with it: the match path has to
   * decide on exactly the scan it consumed, and counts read off the store
   * afterwards could describe an interleaved one.
   *
   * `skipped.unknownEpoch` counts what is still unreadable AFTER the one
   * refresh below, which is why it is reported rather than assumed resolved.
   *
   * @returns {Promise<{ appKeys: StoredCredential[]; skipped: {
   *   unknownEpoch: number; noEpochKey: number; undecryptable: number } }>}
   */
  async listAppKeys(): Promise<{
    appKeys: StoredCredential[]
    skipped: {
      unknownEpoch: number
      noEpochKey: number
      undecryptable: number
    }
  }> {
    // Unknown-epoch rows mean the cipher may be built from a stale descriptor
    // (a rekey emits no change-feed entry); refresh the descriptor once and
    // re-read, as the credential list does. Load-bearing here: an app key
    // missed by a stale cipher would read as "no key for this app" and mint a
    // second identity, orphaning what the app encrypted under the first.
    return this.#readWithEpochRefresh({
      collectionId: 'app-connections',
      read: async () => {
        const appKeys = await this.#store.listAppKeys()
        const skipped = {
          unknownEpoch: this.#store.unknownEpochAppKeys,
          noEpochKey: this.#store.noEpochKeyAppKeys,
          undecryptable: this.#store.undecryptableAppKeys
        }
        return {
          value: { appKeys, skipped },
          unknownEpoch: skipped.unknownEpoch > 0
        }
      }
    })
  }

  /**
   * Deletes one app-key credential by content cid (app revocation, and the
   * login-time sweep of app keys stranded in `private-credentials`).
   *
   * @param options {object}
   * @param options.cid {string}
   * @returns {Promise<void>}
   */
  async deleteAppKey({ cid }: { cid: string }): Promise<void> {
    await this.#store.deleteAppKey({ cid })
  }

  /**
   * The store step behind {@link addCredential}: content-cid derivation, the
   * idempotent insert into `private-credentials`, and the best-effort Create
   * history entry.
   *
   * @param options {object}
   * @param options.credential {IVerifiableCredential}
   * @param options.user {User}
   * @returns {Promise<void>}
   */
  async #putCredential({
    credential,
    user
  }: {
    credential: IVerifiableCredential
    user: User
  }) {
    // The credential's content cid is its page-facing identity (idempotence,
    // routes, history); the backend encrypts the VC into an EDV envelope keyed
    // by a content-derived envelope-hash id.
    const cid = await cidFrom({ doc: credential })
    const inserted = await this.#store.addCredential({ cid, credential })
    if (inserted) {
      // Best-effort: the credential is already stored, and losing a log
      // line beats reporting the whole store as failed (in remote-direct
      // mode the history entry is its own remote write and can fail alone).
      try {
        await this.addHistoryCredentialActivity({
          cid,
          title: credentialTitle(credential),
          user,
          verb: 'created'
        })
      } catch (err) {
        log.warn('Could not record the credential-created activity', { err })
      }
    }
  }

  async listCredentials(): Promise<Array<StoredCredential>> {
    // Unknown-epoch rows mean the cipher may be built from a stale descriptor (a
    // rekey emits no change-feed entry); the shared helper refreshes the descriptor
    // once and re-reads, uniformly for both backends.
    return this.#readWithEpochRefresh({
      collectionId: 'private-credentials',
      read: async () => ({
        value: await this.#store.listCredentials(),
        unknownEpoch: this.#store.unknownEpochCredentials > 0
      })
    })
  }

  async loadCredential({
    cid
  }: {
    cid: string
  }): Promise<IVerifiableCredential | undefined> {
    return await this.#store.loadCredential({ cid })
  }

  /**
   * Deletes a credential, retracting its world-readable public copy FIRST when
   * it has one. The order is load-bearing: once the private credential is gone
   * there is no wallet-side handle left to retract the public copy with, so
   * deleting it first can strand a world-readable orphan of a credential the
   * user believes is deleted.
   *
   * Retraction of a live public copy is therefore BLOCKING, not best-effort:
   * if the credential has a public copy that cannot be retracted, the delete
   * is refused with a {@link PublicCopyRetractionError} and the private
   * credential is left in place, so the user can retry once the retraction can
   * land. A credential with no public copy deletes normally, offline included.
   *
   * `keepPublicCopy` is the user's deliberate "keep the public link" choice
   * from the delete dialog: a retention the user was asked about and chose, as
   * distinct from the accidental orphan above. It skips the retraction (and
   * therefore the refusal) entirely.
   *
   * `consultRemote` makes the retraction check the remote `public-credentials`
   * collection as well (see {@link retractPublicCopy}). The interactive delete
   * leaves it off and decides on the local replica, so an offline delete of a
   * credential with no local public copy keeps working; the unattended app-key
   * sweep turns it on, since a seed-bearing copy the replica has not pulled
   * yet must not be left standing.
   *
   * @param options {object}
   * @param options.cid {string}
   * @param [options.keepPublicCopy] {boolean}
   * @param [options.consultRemote] {boolean}
   * @returns {Promise<void>}
   */
  async deleteCredential({
    cid,
    keepPublicCopy = false,
    consultRemote = false
  }: {
    cid: string
    keepPublicCopy?: boolean
    consultRemote?: boolean
  }): Promise<void> {
    if (!keepPublicCopy) {
      await this.retractPublicCopy({ cid, consultRemote })
    }
    await this.#store.deleteCredential({ cid })
  }

  /**
   * Removes a credential's world-readable public copy, if it has one, ahead of
   * deleting the credential itself. A failure to determine whether a public
   * copy exists is treated exactly like a failed retraction -- an unknown
   * public copy is indistinguishable from an unretracted one -- so both refuse
   * the delete with a {@link PublicCopyRetractionError}.
   *
   * With `consultRemote`, the remote collection is consulted first whenever
   * one is configured and this session carries the local replica. The local
   * `public-credentials` replica cannot prove the ABSENCE of a remote copy: a
   * freshly enrolled browser, or one whose `public-credentials` replication
   * sits in retry backoff, has not pulled the copy yet, and deciding
   * retraction on the local rows alone would let the world-readable copy
   * stand with no handle left to retract it. A remote that cannot be reached
   * then refuses. Without the option the decision is the local replica's, the
   * interactive delete's offline-tolerant behaviour. (In the replica-less
   * remote-direct variant the store's own `hasPublicCredential` /
   * `removePublicCredential` already go straight to the remote either way.)
   *
   * The local row is then removed as before. Its replication push is a
   * tombstone against a resource this call has already deleted remotely, which
   * the push path tolerates: a `DELETE` of an absent resource is the
   * tombstone's goal state, and a conditional delete refused on a vanished
   * master resolves as an ordinary delete/delete conflict (the push handler's
   * `deleteContent` and conflict assembler in `@interop/was-sync`).
   *
   * @param options {object}
   * @param options.cid {string}
   * @param [options.consultRemote] {boolean}
   * @returns {Promise<void>}
   */
  async retractPublicCopy({
    cid,
    consultRemote = false
  }: {
    cid: string
    consultRemote?: boolean
  }): Promise<void> {
    try {
      const remote =
        consultRemote && this.hasLocalReplica ? this.#remoteStore : undefined
      if (remote) {
        const body = await remote.getSyncedResource({
          logicalKey: 'publicCredentials',
          resourceId: cid
        })
        if (body !== undefined) {
          await remote.deleteSyncedResource({
            logicalKey: 'publicCredentials',
            resourceId: cid
          })
        }
      }
      if (await this.#store.hasPublicCredential({ cid })) {
        await this.#store.removePublicCredential({ cid })
      }
    } catch (err) {
      throw new PublicCopyRetractionError({ cid, cause: err })
    }
  }

  /**
   * Every world-readable public credential copy this session can see: the
   * local `public-credentials` replica's rows, unioned by cid with the remote
   * collection's resources when a remote store is configured and this session
   * carries the replica. The collection is plaintext and keyed by the
   * credential's content cid, so a row's id IS its cid.
   *
   * `skipCids` names the cids the caller does not need (the app-key sweep
   * already reaches those through `deleteCredential`, which retracts their
   * public copies). They are left out of the result. The remote collection
   * is read by paging its `changes` feed, so the sweep costs a page walk of
   * the public collection per login rather than a `GET` per public
   * credential.
   *
   * A remote listing failure throws: an unreadable remote collection is not
   * an empty one.
   *
   * @param options {object}
   * @param [options.skipCids] {Set<string>}
   * @returns {Promise<Array<StoredCredential>>}
   */
  async listPublicCredentials({
    skipCids
  }: {
    skipCids?: Set<string>
  } = {}): Promise<Array<StoredCredential>> {
    const wanted = (cid: string): boolean => !skipCids?.has(cid)
    const byCid = new Map<string, StoredCredential>()
    for (const entry of await this.#store.listPublicCredentials()) {
      if (wanted(entry.cid)) {
        byCid.set(entry.cid, entry)
      }
    }
    const remote = this.hasLocalReplica ? this.#remoteStore : undefined
    if (!remote) {
      return [...byCid.values()]
    }
    const resources = await remote.listSyncedDocuments({
      logicalKey: 'publicCredentials'
    })
    for (const { id: cid, data } of resources) {
      if (wanted(cid) && !byCid.has(cid)) {
        byCid.set(cid, { cid, vc: data as unknown as IVerifiableCredential })
      }
    }
    return [...byCid.values()]
  }

  /**
   * The count of local `private-credentials` rows the most recent
   * {@link listCredentials} read had to skip because their envelope would not
   * decrypt under the current vault KAK (corrupted, or written under a
   * mismatched KAK). Surfaced so the dashboard can warn the user without one
   * bad row bricking the list.
   *
   * @returns {number}
   */
  get undecryptableCredentials(): number {
    return this.#store.undecryptableCredentials
  }

  /**
   * Removes the local `private-credentials` rows that could not be decrypted,
   * so the user can clear rows that can never be shown. Returns the number of
   * rows removed.
   *
   * @returns {Promise<number>}
   */
  async purgeUndecryptableCredentials(): Promise<number> {
    return await this.#store.purgeUndecryptableCredentials()
  }

  /**
   * The count of `app-connections` rows the most recent {@link listAppKeys}
   * read had to skip because their envelope would not decrypt at all.
   * Surfaced on the Applications page beside its purge action.
   *
   * @returns {number}
   */
  get undecryptableAppKeys(): number {
    return this.#store.undecryptableAppKeys
  }

  /**
   * The count of `app-connections` rows the most recent {@link listAppKeys}
   * read had to skip because this wallet holds no key for their (known) key
   * epoch. Never purged: the row is an app's real identity, readable again
   * once the collection's epochs wrap a key this session holds.
   *
   * @returns {number}
   */
  get noEpochKeyAppKeys(): number {
    return this.#store.noEpochKeyAppKeys
  }

  /**
   * Removes the `app-connections` rows that could not be decrypted at all.
   * Returns the number of rows removed.
   *
   * @returns {Promise<number>}
   */
  async purgeUndecryptableAppKeys(): Promise<number> {
    return await this.#store.purgeUndecryptableAppKeys()
  }

  /**
   * Wipes the remote data Space only (a no-op without a remote store).
   * Account deletion's pivot: everything the ceremony still needs from the
   * account document happens before this call, and the local half is the
   * shared wipe enumeration's.
   *
   * A Space DELETE is governed by the server's exact-delete container rule.
   * A delegated capability passes only when the invoked capability targets
   * exactly the Space's canonical container URL and its `allowedAction` is
   * exactly `['DELETE']`. A transient session's generation delegation
   * targets that URL but carries a wider action set, so it supplies its own
   * single-verb DELETE capability and the client that capability names as
   * its delegatee.
   *
   * @param [options] {object}
   * @param [options.capability] {IZcap}   an explicit DELETE capability on
   *   the Space's own URL
   * @param [options.zcapClient] {ZcapClient}   the client invoking it
   * @returns {Promise<{ outcome: 'deleted' | 'not-found' }>}   `not-found`
   *   when the server answered 404 (absent OR unauthorized), or when there is
   *   no remote store to wipe
   */
  async wipeRemoteStorage({
    capability,
    zcapClient
  }: {
    capability?: IZcap
    zcapClient?: ZcapClient
  } = {}): Promise<{ outcome: 'deleted' | 'not-found' }> {
    if (!this.#remoteStore) {
      return { outcome: 'deleted' }
    }
    return await this.#remoteStore.wipeStorage({
      ...(capability ? { capability } : {}),
      ...(zcapClient ? { zcapClient } : {})
    })
  }

  /**
   * Wipes the local replica databases only (this client's prefix, with the
   * cross-tab teardown and verified completion the local store provides).
   * The shared wipe enumeration's replica stage. The result carries the
   * local store's own honesty about the deletion: `verified: false` when
   * this browser cannot enumerate its databases, so nothing could be
   * re-probed. A replica-less (transient) session has nothing to delete and
   * is verified by construction.
   *
   * @returns {Promise<{ verified: boolean }>}
   */
  async wipeLocalStorage(): Promise<{ verified: boolean }> {
    if (!this.#localStore) {
      return { verified: true }
    }
    return await this.#localStore.wipeStorage()
  }

  /**
   * Closes the local database without removing data. Called on logout.
   *
   * @returns {Promise<void>}
   */
  async close() {
    await this.#localStore?.close()
  }

  async getSpaceQuotas(): Promise<SpaceQuotaReport | null> {
    if (!this.#remoteStore) {
      return null
    }
    return await this.#remoteStore.getSpaceQuotas()
  }

  async exportSpace(): Promise<ReadableStream<Uint8Array>> {
    // Export needs no authority a transient session lacks; the gate is
    return await this.#requireRemote('Exporting a Space').exportSpace()
  }

  async importSpace({
    tarFile
  }: {
    tarFile: File
  }): Promise<ImportSpaceSummary> {
    return await this.#requireRemote('Importing a Space').importSpace({
      tarFile
    })
  }

  async listCollections(): Promise<Array<StorageCollection>> {
    if (!this.#remoteStore) {
      return []
    }
    return await this.#remoteStore.listCollections()
  }

  /**
   * Lean collection listing for grant resolution (the ids and their public
   * state, no per-collection description reads). Empty without a remote
   * store, like {@link listCollections}.
   *
   * @returns {Promise<Array<{ id: string, isPublic: boolean }>>}
   */
  async listCollectionPublicStates(): Promise<
    Array<{ id: string; isPublic: boolean }>
  > {
    if (!this.#remoteStore) {
      return []
    }
    return await this.#remoteStore.listCollectionPublicStates()
  }

  async listCollectionResources({
    collectionUrl
  }: {
    collectionUrl: string
  }): Promise<Array<StorageResource>> {
    if (!this.#remoteStore) {
      return []
    }
    return await this.#remoteStore.listCollectionResources({ collectionUrl })
  }

  async fetchCollectionResource(
    resource: StorageResource
  ): Promise<FetchedCollectionResource> {
    return await this.#requireRemote(
      'Fetching a storage resource'
    ).fetchCollectionResource(resource)
  }

  /**
   * Reads a Resource's metadata document (the storage browser's metadata
   * card). Resolves null on a 404, which the server answers both for a
   * missing target and for one this session may not read, and throws
   * `NotImplementedError` on a server without metadata support.
   *
   * @param options {object}
   * @param options.url {string}   the Resource URL
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async fetchResourceMeta({
    url
  }: {
    url: string
  }): Promise<Record<string, unknown> | null> {
    const read = await this.#requireRemote(
      'Reading resource metadata'
    ).fetchResourceMeta({ url })
    // The metadata card renders members generically, so the typed document is
    // widened here rather than at every call site.
    return read as Record<string, unknown> | null
  }

  /**
   * Reads a Collection's Metadata object, on the same terms as
   * {@link fetchResourceMeta}.
   *
   * @param options {object}
   * @param options.url {string}   the Collection URL
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async fetchCollectionMeta({
    url
  }: {
    url: string
  }): Promise<Record<string, unknown> | null> {
    const read = await this.#requireRemote(
      'Reading collection metadata'
    ).fetchCollectionMeta({ url })
    return read as Record<string, unknown> | null
  }

  /**
   * Whether a collection is encrypted, read from the verified head of its
   * governing log when this session can verify one, and from the served
   * Description member otherwise. The storage browser's metadata card asks
   * this at expand time rather than trusting the listing's host-served
   * member read at page load.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @returns {Promise<boolean>}
   */
  async isCollectionEncrypted({
    collectionId
  }: {
    collectionId: string
  }): Promise<boolean> {
    const descriptor = await this.#readGovernedDescriptor({ collectionId })
    return descriptor !== undefined
  }

  /**
   * Best-effort decryption of a fetched storage-browser resource body: when
   * the body is an EDV envelope from one of the encrypted standard
   * collections and this session holds that collection's cipher (unlocked
   * vault), returns the decrypted document. Returns undefined otherwise --
   * plaintext bodies, non-standard collections, a locked vault, or an
   * envelope that fails to decrypt (logged, not thrown), letting callers fall
   * back to showing the raw envelope. An `UnknownEpochError` (a rekey on
   * another client the cached descriptor has not caught up to) drives the same
   * one-time descriptor refresh + retry `listCredentials` / `listHistoryItems` use,
   * so a freshly-rekeyed resource is not rendered as raw JWE until re-login.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id (e.g.
   *   `private-credentials`)
   * @param options.data {Json}   the fetched JSON resource body
   * @returns {Promise<Json | undefined>}
   */
  async decryptCollectionResource({
    collectionId,
    data
  }: {
    collectionId: string
    data: Json
  }): Promise<Json | undefined> {
    if (!isEncryptedEnvelope(data)) {
      return undefined
    }
    const entry = WALLET_STANDARD_COLLECTIONS.find(
      collection => collection.id === collectionId && collection.encryption
    )
    if (!entry) {
      // A non-standard collection: an App Connect app-provisioned collection the
      // wallet decrypts as an ordinary recipient (vault KAK = recipient zero),
      // descriptor-driven from the fetched Collection Description.
      return this.#decryptAppCollectionResource({ collectionId, data })
    }
    return this.#readWithEpochRefresh({
      collectionId,
      read: async () => {
        // Re-fetch the cipher inside the read: a descriptor refresh rebuilds it.
        const cipher = this.#ciphers?.[entry.key]
        if (!cipher) {
          return { value: undefined, unknownEpoch: false }
        }
        return await decryptEnvelope({
          cipher,
          envelope: data,
          source: `collection "${collectionId}"`
        })
      }
    })
  }

  /**
   * Best-effort decrypt of an EDV envelope from a non-standard (App Connect
   * app-provisioned) encrypted collection, using the session's vault KAK as an
   * ordinary recipient (recipient zero). Lazily fetches the collection's
   * `encryption` descriptor, builds and caches a per-collection `DocCipher` from it
   * (only when the descriptor carries epochs -- a wallet with only its vault KAK can
   * decrypt an app collection only once it is provisioned multi-recipient with
   * the vault KAK as a recipient), and decrypts. On an `UnknownEpochError` (a
   * rekey the cached descriptor has not caught up to) it re-fetches the descriptor,
   * rebuilds the cipher, and retries once per session for that collection.
   * Returns undefined on any failure (no vault keys / no remote store / no epoch
   * descriptor / a decrypt error), letting the caller show the raw envelope.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id
   * @param options.data {Json}   the fetched EDV envelope
   * @returns {Promise<Json | undefined>}
   */
  async #decryptAppCollectionResource({
    collectionId,
    data
  }: {
    collectionId: string
    data: Json
  }): Promise<Json | undefined> {
    const remote = this.#remoteStore
    if (!remote || !this.#vaultKeys) {
      return undefined
    }
    const { keyAgreementKey, keyResolver } = this.#vaultKeys

    // The shared refresh policy guards the retry to once per collection per
    // session; its refresh drops the cached app descriptor and cipher, so the
    // re-read below rebuilds them from a fresh Description fetch.
    return this.#refreshPolicy.readWithRefresh({
      collectionId,
      read: async (): Promise<{
        value: Json | undefined
        unknownEpoch: boolean
      }> => {
        let cipher = this.#appCiphers[collectionId]
        if (!cipher) {
          let descriptor: CollectionEncryption | undefined =
            this.#appDescriptors[collectionId]
          if (!descriptor) {
            try {
              descriptor = await this.#readGovernedDescriptor({ collectionId })
            } catch (err) {
              // A verifier refusal is never read as "nothing to decrypt".
              if (isResourceLogRefusal(err)) {
                throw err
              }
              log.warn(
                'Could not fetch the encryption descriptor for app collection',
                { collectionId, err }
              )
            }
          }
          if (!descriptor?.epochs || descriptor.epochs.length === 0) {
            // No multi-recipient roster: the vault KAK is not (yet) a
            // recipient, so there is nothing this session can decrypt.
            return { value: undefined, unknownEpoch: false }
          }
          this.#appDescriptors[collectionId] = descriptor
          const built = await createEdvDocCipher({
            keyAgreementKey,
            keyResolver,
            collectionId,
            encryption: descriptor
          })
          // Install the collection's persisted blinded-index schema (its
          // stored `/meta`), best-effort like the descriptor fetch above, so
          // this cached cipher matches the standard-collection ones -- a
          // schema-less cipher still decrypts, it just could not emit
          // `indexed` entries.
          try {
            const meta = await remote.collectionMeta({ collectionId })
            await StorageManager.#installIndexSchema({
              cipher: built,
              collectionId,
              meta
            })
          } catch (err) {
            log.warn('Could not fetch the stored metadata for app collection', {
              collectionId,
              err
            })
          }
          cipher = built
          this.#appCiphers[collectionId] = cipher
        }
        return await decryptEnvelope({
          cipher,
          envelope: data,
          source: `app collection "${collectionId}"`
        })
      }
    })
  }

  async deleteCollectionResource(resource: StorageResource): Promise<void> {
    await this.#requireRemote(
      'Deleting a storage resource'
    ).deleteCollectionResource({
      relativeUrl: resource.url
    })
  }

  /**
   * Provisions an arbitrary plaintext collection on the remote WAS Space, for
   * a relying party's delegated capability. No local counterpart -- RP
   * collections are the RP's data, reached only over its zcap. Requires a
   * remote backend. With `isPublic`, the collection also gets a
   * collection-level world-readable (PublicCanRead) policy.
   *
   * `generator` and `generatorOrigin` are the collection's app attribution,
   * stamped on the create (see {@link WASRemoteStore.ensureCollection}).
   *
   * @param options {object}
   * @param options.id {string}
   * @param [options.name] {string}
   * @param [options.isPublic] {boolean}
   * @param [options.generator] {IDID}   the DID of the application this
   *   collection is provisioned for
   * @param [options.generatorOrigin] {string}   the Web origin that DID was
   *   bound to at provisioning time
   * @returns {Promise<void>}
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
  }): Promise<void> {
    await this.#requireRemote('Provisioning a collection').ensureCollection({
      id,
      name,
      isPublic,
      generator,
      generatorOrigin
    })
  }

  async deleteCollection({ id }: { id: string }): Promise<void> {
    await this.#requireRemote('Deleting a collection').deleteCollection({ id })
  }

  /**
   * Provisions an App Connect app-provisioned PRIVATE collection as a
   * multi-recipient EDV collection: the user's vault KAK is always recipient
   * zero (policy -- the user is a recipient of every encrypted collection in
   * their own Space) alongside the app's identity key-agreement key. The
   * collection is ensured to exist and declared `'edv'` without clobbering an
   * existing descriptor, then `ensureIndexedFirstEpoch` installs epoch[0]
   * wrapped to the owner alone, together with the collection's blinded-index
   * HMAC key -- create-if-absent, adopting a roster an earlier provision
   * landed, so every app collection carries its key epochs from birth (the
   * first-epoch mint runs only here, at provisioning). A collection whose
   * roster predates the blinded index is adopted as it stands, without an
   * HMAC key. The app is then always escrowed in by `addRecipient` (into every
   * epoch, and into the HMAC key's wrap set -- adds are cheap) unless the
   * current epoch already wraps to it (reconnect with no intervening revoke: a
   * no-op).
   *
   * The app never needs the vault KAK and the wallet never needs the app seed
   * at all (the recipient is derived from the app's controller DID, and the
   * roster kid is in the descriptor), so this is the only step that pairs the two
   * recipients. Requires the vault key material and a remote store (an App
   * Connect popup always has both).
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id to provision
   * @param options.appRecipient {RecipientPublicKey}   the app's identity
   *   public key-agreement key, the X25519 twin of its controller `did:key`
   *   (its `id` is the recipient `kid`)
   * @param [options.generator] {IDID}   the DID of the application this
   *   collection is provisioned for, stamped as the collection's attribution
   * @param [options.generatorOrigin] {string}   the Web origin that DID was
   *   bound to at provisioning time
   * @returns {Promise<CollectionEncryption>}   the current descriptor
   */
  async provisionAppCollection({
    collectionId,
    appRecipient,
    generator,
    generatorOrigin
  }: {
    collectionId: string
    appRecipient: RecipientPublicKey
    generator?: IDID
    generatorOrigin?: string
  }): Promise<CollectionEncryption> {
    const remote = this.#requireRemote('Provisioning an app collection')
    if (!this.#vaultKeys) {
      throw new Error(
        'Provisioning an app collection requires the vault key material.'
      )
    }
    const { keyAgreementKey } = this.#vaultKeys
    // Ensure the collection exists (a bare create; the server derives its
    // `encryption` member from the governing log), then install epoch[0]
    // (owner as recipient zero) as that log's genesis -- create-if-absent,
    // so an existing roster is adopted, never overwritten.
    await remote.ensureGovernedCollection({
      id: collectionId,
      generator,
      generatorOrigin
    })
    const store = await this.#collectionStore({
      collectionId,
      action: 'Provisioning an app collection'
    })
    const { descriptor: current } = await ensureIndexedFirstEpoch({
      store,
      recipients: [ownerRecipient({ keyAgreementKey })]
    })

    if (
      currentEpochRecipientKids({ descriptor: current }).includes(
        appRecipient.id
      )
    ) {
      // The app already reads the current epoch: nothing to do.
      return current
    }
    // First connect, or reconnect after a revoke rotated the epoch off the
    // app: escrow the app into every epoch (adds are cheap -- no rotation).
    const descriptor = await addRecipient({
      store,
      recipient: appRecipient,
      owner: { keyAgreementKey }
    })

    // Update the descriptor cache and the in-memory app-collection state, then drop
    // any stale app cipher so the wallet's own next read rebuilds under the new
    // descriptor (mirrors shareCollection's tail).
    await this.#descriptorCache?.writeDescriptor({ collectionId, descriptor })
    this.#appDescriptors[collectionId] = descriptor
    delete this.#appCiphers[collectionId]
    this.#refreshPolicy.reset({ collectionId })
    return descriptor
  }

  /**
   * Fires collection provisioning and records its promise for the read-readiness
   * contract (`ready()`), returning the same promise so a caller can await full
   * provisioning where a grant needs the remote Space to exist.
   *
   * @param options {object}
   * @param options.user {User}
   * @param [options.profile] {ControllerProfile}
   * @param [options.idb] {IDBFactory}   an explicit IndexedDB factory for the
   *   session-key caches (the pin stores), where the default first-party
   *   database is not the right home
   * @returns {Promise<void>}
   */
  ensureUserCollections({
    user,
    profile,
    idb
  }: {
    user: User
    profile?: ControllerProfile
    idb?: IDBFactory
  }): Promise<void> {
    // Provisioning is the browser-local bootstrap: it creates the local
    // replica and makes the bare-Space-URL reads and promotion PUTs a
    // transient session must not make. The transient login path never calls
    // this; the assert keeps that structural rather than convention.
    assertBrowserLocalSession({
      persistence: this.#persistence,
      ceremony: 'Provisioning storage'
    })
    this.#provisioning = this.#provisionUserCollections({ user, profile, idb })
    return this.#provisioning
  }

  /**
   * The keystore promotion this session fired, where one ran. Provisioning
   * fires it on every login of a pointer-promoted account and drops the
   * promise; the login block's tail reads it here, so the promotion that
   * actually ran is the one reported rather than the absence of a heal.
   *
   * @returns {Promise<MendOutcome> | undefined}
   */
  get keystorePromotion(): Promise<MendOutcome> | undefined {
    return this.#keystorePromotion
  }

  /**
   * Fires the keystore promotion and keeps its promise for the login block's
   * tail. One promotion per session: a second `ensurePromotedController`
   * (provisioning's, then the pointer heal's) would only run on an account
   * whose first call returned before firing one.
   *
   * @param options {object}
   * @param options.profile {ControllerProfile}
   * @param options.did {string}
   * @returns {Promise<MendOutcome>}
   */
  #fireKeystorePromotion({
    profile,
    did
  }: {
    profile: ControllerProfile
    did: string
  }): Promise<MendOutcome> {
    const promotion = promoteAccountKeystore({ profile, did })
    this.#keystorePromotion = promotion
    return promotion
  }

  /**
   * Promotes the account's Space (and keystore) controller to the published
   * did:webvh -- the last step of promotion by ordering: the Space was
   * created under this client's did:key, the log went into the
   * world-readable `id` collection, and this PUTs the Space Description
   * naming the did:webvh, authorized by the stored controller. Idempotent
   * across every state:
   *
   * - Fresh signup (store bound to the did:key): promote, then swap the
   *   session's signing -- `profile.zcapClient` and the remote store rebind
   *   to the `<did:webvh>#<multibase>` keyId, since under the current-key-set
   *   rule the did:key-signed form stops verifying the moment the promotion
   *   lands.
   * - Pointer-promoted login (store already bound to the did:webvh): confirm
   *   with one describe and return.
   * - Torn signup (pointer names the did:webvh but the promotion PUT never
   *   landed): the describe fails, and the promotion is retried signed by
   *   the stored did:key controller, then the store rebinds back to the
   *   session's did:webvh client.
   *
   * The keystore half runs after the Space half, non-fatally (KMS outages
   * must not fail provisioning): the keystore config's controller becomes
   * the did:webvh and the session's KeystoreAgent rebinds to invoke under
   * it. It is fired without await here and kept on the manager (the
   * `keystorePromotion` accessor above), so the login chain's block reports
   * its outcome without a second KMS round trip.
   *
   * @param options {object}
   * @param options.profile {ControllerProfile}
   * @returns {Promise<{ promoted: boolean }>}   whether a Space promotion
   *   was written here
   */
  async ensurePromotedController({
    profile
  }: {
    profile: ControllerProfile
  }): Promise<{ promoted: boolean }> {
    const remote = this.#remoteStore
    const did = profile.didWebvh?.did
    const { keyAgent } = profile
    if (!remote || !keyAgent || !isWebvhDid(did)) {
      return { promoted: false }
    }

    if (remote.controller === did) {
      // Already bound to the promoted controller (the pointer path): one
      // describe confirms the server agrees; a null answer (was-client maps
      // 404 -- the shape unauthorized reads take -- to null) means the
      // promotion PUT never landed, and the promotion is retried signed by
      // the stored did:key controller. A THROWN describe (a 5xx, a network
      // flake) is not evidence either way: re-PUTting with the demoted key
      // on a hiccup would be wrong, and this is the one provisioning step
      // awaited un-guarded -- so a transport failure warns and skips like
      // the neighbouring steps, and the next login re-checks.
      let description: SpaceMetadata | null
      try {
        description = await remote.spaceHandle().describe()
      } catch (err) {
        log.warn('Could not confirm the promoted Space controller', { err })
        return { promoted: false }
      }
      if (description?.controller === did) {
        // The server already agrees, so nothing was promoted here.
        this.#fireKeystorePromotion({ profile, did })
        return { promoted: false }
      }
      remote.rebindController({
        zcapClient: didKeyZcapClient({ keyAgent }),
        controller: keyAgent.id
      })
      try {
        // A non-null read is the description this method just made through
        // the same Space handle, so it rides along and `configure` skips its
        // own pre-merge describe. A null one does not: it came from a read
        // under the promoted signer, where an unauthorized answer is masked
        // as the same 404 an absent description returns, so the truthful
        // read is the one `configure` makes under the did:key client.
        await remote.promoteSpaceController({
          controller: did,
          ...(description !== null ? { current: description } : {})
        })
      } finally {
        remote.rebindController({
          zcapClient: profile.zcapClient,
          controller: did
        })
      }
      this.#fireKeystorePromotion({ profile, did })
      return { promoted: true }
    }

    // Fresh promotion: the PUT is authorized by the stored did:key
    // controller the store is still bound to; the swap follows.
    await remote.promoteSpaceController({ controller: did })
    const zcapClient = webvhZcapClient({ keyAgent, did })
    profile.zcapClient = zcapClient
    remote.rebindController({ zcapClient, controller: did })
    this.#fireKeystorePromotion({ profile, did })
    return { promoted: true }
  }

  async #provisionUserCollections({
    user,
    profile,
    idb
  }: {
    user: User
    profile?: ControllerProfile
    idb?: IDBFactory
  }) {
    const localStore = this.#localStore
    if (!localStore) {
      // Unreachable by construction: session creation fires provisioning only
      // for sessions on the browser-local strategy, which always carry the
      // local replica.
      throw new Error(
        'Storage provisioning requires the local replica; a replica-less ' +
          'session must not provision.'
      )
    }
    await localStore.ensureUserCollections({ user })
    if (this.#remoteStore) {
      // A pointer-promoted session signs with the did:webvh keyId from the
      // start; confirm the server agrees before any signed upsert runs, and
      // heal a signup that tore between the pointer backfill and the
      // promotion PUT (the requests below would otherwise all be refused).
      // Warn-and-continue like the neighbouring steps: an unpromoted
      // controller degrades the signed requests below, but a promotion
      // hiccup must not fail the whole login (the next login re-heals).
      if (profile && isWebvhDid(profile.accountPointer?.did)) {
        try {
          await this.ensurePromotedController({ profile })
        } catch (err) {
          log.warn('Space controller promotion failed', { err })
        }
      }
      const remoteStore = this.#remoteStore
      // Provision the account's one KMS-held `authentication` key (only when
      // a keystore agent is present) and record its binding in keys.json. On
      // the ceremony path below wallet-core starts this closure before the
      // Space is awaited and joins on it before the genesis entry, threading
      // the parsed keys.json (with any webvh block) into the did:webvh
      // genesis, so steady state stays one keys.json read total. The reduced
      // path calls it directly, with an already-resolved `spaceReady`: its
      // Space is up before the call. The concurrency wins nothing on either
      // of this method's paths -- the Space exists by the time a login gets
      // here, so the probe short-circuits -- and it costs nothing either.
      // Non-fatal like keystore provisioning: a KMS/WAS hiccup must not fail
      // login; the settings page surfaces the unprovisioned state, and the
      // idempotent flow resumes on the next login.
      const provideKmsAuthentication = async ({
        spaceReady
      }: {
        spaceReady: Promise<unknown>
      }): Promise<KmsAuthenticationBinding | undefined> => {
        // Defensive: both paths below already gate on the keystore agent.
        if (!profile?.keystoreAgent) {
          return undefined
        }
        const keystoreAgent = profile.keystoreAgent
        const binding = await ensureKmsAuthentication({
          // This session already holds its keystore agent, so both thunks
          // hand back the same one and neither reaches the KMS's create
          // route: the creating ensure ran at session init.
          lookupKeystoreAgent: async () => keystoreAgent,
          provideKeystoreAgent: async () => keystoreAgent,
          remoteStore,
          did: didWebFromSpace({
            wasServerUrl: remoteStore.storageServerUrl,
            spaceId: remoteStore.spaceId
          }),
          spaceReady
        })
        profile.kmsAuthentication = binding.keys.authentication
        return binding
      }
      // A fresh signup built this session's ciphers before the Space
      // existed, so every encrypted collection's descriptor was unavailable
      // and its cipher refuses. Once epoch[0] is installed, refresh the
      // descriptors and rebuild the ciphers -- only when a descriptor is
      // still missing its epochs, so an ordinary login (descriptors fetched
      // at session init) adds no requests.
      const refreshDescriptorsWithoutEpochs = async () => {
        if (
          ENCRYPTED_COLLECTION_IDS.some(
            collectionId => !this.#descriptors[collectionId]?.epochs?.length
          )
        ) {
          await this.refreshEncryptedDescriptors()
        }
      }
      if (
        profile?.keystoreAgent &&
        profile.clientWebvhKeys &&
        profile.keyAgent &&
        profile.clientKeyAgreementKey &&
        profile.userKey
      ) {
        // The full account-genesis ceremony, whose stage order lives in
        // `@interop/wallet-core/genesis` so both wallet apps encode it
        // identically: Space provisioning, did:web key map, did:webvh
        // genesis, the user key roster (strictly after the DID publication,
        // since the roster log's entry proofs anchor in the published
        // document), and key epoch[0] on every encrypted collection. Every
        // stage detects its own completion from durable state, so a torn run
        // heals by re-running at the next login.
        //
        // Controller promotion is NOT part of this call
        // (`promoteController: false`): freewallet's account pointer must
        // durably name the did:webvh before the controller PUT, so signup
        // promotes after its keyring re-bind (`backfillPointerAndPromote`)
        // and a pointer-promoted login heals at the head of this method.
        const { userKey, keyAgent, clientKeyAgreementKey } = profile
        // The account pointer's DID is what this run expects the published
        // log to resolve to -- but only once it is a webvh DID: a first
        // signup has none yet, and wallet-core then falls back to the
        // keys.json webvh block.
        const pointerDid = profile.accountPointer?.did
        // A signup torn between the log publication and the pointer backfill
        // heals here at a later login whose pointer still names no did:webvh
        // -- but the log WAS published in this browser, so the DID is known
        // locally and the read can still state an `expectedDid` (see
        // `saveAccountDidForSpace`).
        const knownDid = isWebvhDid(pointerDid)
          ? pointerDid
          : ((await loadAccountDidForSpace({
              spaceId: remoteStore.spaceId,
              idb
            })) ?? undefined)
        try {
          const result = await ensureAccountGenesis({
            was: remoteStore.was,
            wasServerUrl: remoteStore.storageServerUrl,
            spaceId: remoteStore.spaceId,
            keyAgent,
            clientKeyAgreementKey,
            userKey,
            updateKeys: profile.clientWebvhKeys,
            idStore: remoteStore.webvhIdStore(),
            provideKmsAuthentication,
            ...(knownDid ? { expectedDid: knownDid } : {}),
            // The provisioning read runs under the chain-head pin the id
            // store carries (the same slot the login-time account-log reads
            // use), so a truncated or substituted log is refused before any
            // entry is built on it.
            onDidPublished: async ({ did }) => {
              profile.didWebvh = { did }
              // Fired on both of the ceremony's branches -- the one that
              // published the genesis, and the one that adopted a log already
              // standing -- so the memo is kept when it already holds a
              // settled document for this same DID and dropped otherwise.
              invalidateVerifiedLogForPublish({ profile, did })
              // The DID is known from here on: record it against the Space so
              // a later pre-promotion heal can state an `expectedDid`.
              // Best-effort -- local continuity bookkeeping must not fail
              // provisioning.
              try {
                await saveAccountDidForSpace({
                  spaceId: remoteStore.spaceId,
                  accountDid: did,
                  idb
                })
              } catch (err) {
                log.warn('Could not record the published account DID locally', {
                  err
                })
              }
            },
            rosterStoreFor: ({ did }) =>
              accountRosterStore({
                zcapClient: profile.zcapClient,
                keyAgent,
                pointer: {
                  did,
                  spaceId: remoteStore.spaceId,
                  host: remoteStore.storageServerUrl
                },
                pinStore: this.#persistence.logPins,
                serviceDescription: remoteStore.serviceDescription
              }),
            // Each encrypted collection's log-governed store, the same
            // wiring: epoch[0] lands as the collection's governing-log
            // genesis, signed by this client's enrolled key.
            collectionStoreFor: ({ did }) =>
              accountCollectionStores({
                storageServerUrl: remoteStore.storageServerUrl,
                zcapClient: profile.zcapClient,
                spaceId: remoteStore.spaceId,
                did,
                pinStore: this.#persistence.logPins,
                signer: userKeyRosterLogSigner({ keyAgent }),
                serviceDescription: remoteStore.serviceDescription
              }),
            promoteController: false,
            // The ceremony's one stage boundary of its own: the
            // KMS-authentication join. Timed here so the plain-genesis heal
            // reports it like the credential-anchored establishment does.
            onStage: stageTimer({ log, ceremony: 'account-genesis' })
          })
          remoteStore.bindCollectionMap()
          // The stages the ceremony collects rather than throwing on: each
          // keeps the warn it had when this method sequenced the stages
          // itself, and each resumes on the next login.
          for (const { stage, error } of result.failed) {
            if (stage === 'kmsAuthentication') {
              log.warn('KMS authentication provisioning failed', { err: error })
            } else if (stage === 'roster') {
              log.warn('User key roster provisioning failed', { err: error })
            } else {
              log.warn('Collection key-epoch provisioning failed', {
                err: error
              })
            }
          }
          // Pin only an epoch this session already holds the key for: the
          // ensure serves an existing roster back without the continuity and
          // unwrap checks of the full login-time read, so a served epoch id
          // alone is not evidence. The session's own user key is -- it came
          // from the checked login-time read or the local client-key record
          // -- and the save itself is monotonic, so a rolled-back descriptor
          // can never drag the pin backward.
          // The DID the ceremony published (stamped on the profile by
          // `onDidPublished` above) keys the epoch pin -- including on a
          // first signup, whose pointer named none when this call started.
          const descriptor = result.rosterDescriptor
          const publishedDid = profile.didWebvh?.did
          if (
            descriptor &&
            publishedDid &&
            descriptor.currentEpoch === userKey.id
          ) {
            await this.#persistence.epochPins.saveFromDescriptor({
              accountDid: publishedDid,
              epochId: descriptor.currentEpoch,
              descriptor
            })
          }
          if (result.epochs) {
            await refreshDescriptorsWithoutEpochs()
          }
        } catch (err) {
          // The Space itself never came up: nothing downstream has anywhere
          // to write, so this stays fatal exactly as the standalone
          // `ensureUserCollections` was -- login's `storageReady` rejects
          // rather than warning. Matched on `err.name` for the same reason
          // the continuity refusal below is.
          if (
            (err as { name?: unknown } | null)?.name ===
            'AccountGenesisSpaceError'
          ) {
            throw err
          }
          // A continuity refusal other than a rollback is a security signal,
          // not a hiccup: the served log forked or switched identity against
          // this browser's pinned head. Provisioning stays non-fatal (login
          // must not break here), but the refusal is logged as an error --
          // the later account-log reads in the same login run the same pin
          // and surface it to the user. A rollback may be no more than
          // replication lag (nothing rolled back was adopted), so it warns
          // like everything else. Matched on `err.name` rather than
          // `instanceof`: the refusal is raised inside wallet-core, whose
          // copy here can differ from the one this file imports (a linked
          // checkout, or a duplicate through the dependency tree).
          if (
            (err as { name?: unknown } | null)?.name ===
              'ResourceLogContinuityError' &&
            (err as { reason?: unknown }).reason !== 'rollback'
          ) {
            log.error('did:webvh provisioning refused', { err })
          } else {
            log.warn('did:webvh provisioning failed', { err })
          }
        }
      } else {
        // No did:webvh in this session (no keystore agent, or this client
        // holds no update-key seeds / identity keys / user key), so the
        // genesis and roster stages have nothing to run on: provision the
        // Space, install the key epochs, and record the KMS binding on their
        // own. Nothing publishes a `did.json` here, so this deployment
        // presents did:key only.
        await remoteStore.ensureUserCollections({ user })
        // The provisioning two-step's EDV-bearing second half: install key
        // epoch[0] on every encrypted roster collection, wrapped to the
        // account's user key -- create-if-absent, adopting whatever an
        // earlier provisioner landed. Runs before login completes (and so
        // before replication starts), keeping the
        // descriptor-before-first-content-push invariant. Warn-and-continue:
        // without epochs the affected collections' ciphers refuse
        // fail-closed (nothing leaks plaintext), and the idempotent ensure
        // resumes on the next login.
        // Each epoch[0] is a governing-log genesis signed by this client's
        // key, so the account must already have a did:webvh that lists it;
        // a session with none skips the install and its ciphers stay
        // refusing until a login that can publish one.
        const pointer = profile?.accountPointer
        if (profile?.userKey && profile.keyAgent && isWebvhDid(pointer?.did)) {
          try {
            await remoteStore.ensureSpaceEpochs({
              userKey: profile.userKey,
              storeFor: accountCollectionStores({
                storageServerUrl: remoteStore.storageServerUrl,
                zcapClient: profile.zcapClient,
                spaceId: remoteStore.spaceId,
                did: pointer.did,
                pinStore: this.#persistence.logPins,
                signer: userKeyRosterLogSigner({ keyAgent: profile.keyAgent }),
                serviceDescription: remoteStore.serviceDescription
              })
            })
            await refreshDescriptorsWithoutEpochs()
          } catch (err) {
            log.warn('Collection key-epoch provisioning failed', { err })
          }
        } else if (profile?.userKey) {
          // The collections were created bare, so without this stage they
          // carry no epochs and every encrypted collection's cipher refuses
          // fail-closed until a login that publishes a did:webvh.
          log.warn(
            'Skipping collection key-epoch provisioning: the account has no did:webvh to anchor the descriptor logs in, and its encrypted collections stay unusable until one is published'
          )
        }
        if (profile?.keystoreAgent) {
          try {
            // The Space is already up on this path, so the stage's own
            // `spaceReady` join is a no-op.
            await provideKmsAuthentication({ spaceReady: Promise.resolve() })
          } catch (err) {
            log.warn('KMS authentication provisioning failed', { err })
          }
        }
      }
    }
  }

  /**
   * Mints the activity id and writes the built activity to the local
   * `wallet-activity` collection -- the shared body of every `addHistory*`
   * method below.
   *
   * A locally-minted, time-monotonic `uuidv7` is injected as the activity id
   * (rather than the builder's random default) so it doubles as the record's
   * resource id: on the guest / offline path that id is the RxDB primary key,
   * and its monotonicity keeps history ordering stable when two writes share
   * an `updatedAt` millisecond.
   *
   * @param build {function}   builds the activity from the minted id
   * @returns {Promise<void>}
   */
  async #recordActivity(build: (id: string) => WalletActivity): Promise<void> {
    const resourceId = uuidv7()
    await this.#store.addHistoryItem({
      resourceId,
      activity: build(resourceId)
    })
  }

  /**
   * Records the GenerationCollect activity -- annex GC's owner-side
   * digest, written before the collected generation's delete. Unlike every
   * other `addHistory*` method, the activity id is the generation id
   * VERBATIM rather than a minted `uuidv7`: the deterministic payload id is
   * what lets a torn re-run's second row collapse at read time, and readers
   * must not assume activity ids are UUIDs.
   *
   * @param options {object}
   * @param options.user {User}
   * @param options.generationId {string}
   * @param [options.firstEntry] {string}   the collected log's first entry
   *   `versionTime`, verbatim
   * @param [options.lastEntry] {string}   the collected log's last entry
   *   `versionTime`, verbatim
   * @param [options.entryCount] {number}   total log entries, genesis
   *   included
   */
  async addHistoryGenerationCollected({
    user,
    generationId,
    firstEntry,
    lastEntry,
    entryCount
  }: {
    user: User
    generationId: string
    firstEntry?: string
    lastEntry?: string
    entryCount?: number
  }) {
    await this.#store.addHistoryItem({
      resourceId: generationId,
      activity: buildHistoryGenerationCollected({
        user,
        generationId,
        firstEntry,
        lastEntry,
        entryCount
      })
    })
  }

  /**
   * Records (in the `wallet-activity` collection) the Create activity for
   * the bootstrap did:key DID.
   */
  async addHistoryNewAccount({ user }: { user: User }) {
    await this.#recordActivity(id => buildHistoryNewAccount({ user, id }))
  }

  /**
   * Records (in the `wallet-activity` collection) the Create activity for
   * the storage collections created (and, when a remote replica is
   * configured, the remote Space).
   */
  async addHistorySpaceCreated({ user }: { user: User }) {
    const remote = this.#remoteStore
    const object = remote
      ? [
          { type: ['Space'], id: remote.spaceUrl },
          ...WALLET_STANDARD_COLLECTIONS.map(({ key }) => ({
            type: ['Collection'],
            id: remote.collectionUrl(key)
          }))
        ]
      : WALLET_STANDARD_COLLECTIONS.map(({ id }) => ({
          type: ['Collection'],
          id
        }))
    await this.#recordActivity(id =>
      buildHistorySpaceCreated({
        actor: user.id,
        object,
        remote: !!remote,
        id
      })
    )
  }

  /**
   * Records (in the `wallet-activity` collection) one credential activity,
   * carrying the credential's display title into the shared builder so the
   * History page can render a title link without re-deriving it from the
   * (possibly already-deleted) credential.
   *
   * @param options {object}
   * @param options.cid {string}   CID of the credential (the history object id)
   * @param options.title {string}   display title of the credential at the
   *   time of the event (captured before deletion, for a delete)
   * @param options.user {User}   session user (recorded as the object actor)
   * @param options.verb {CredentialActivityVerb}   which activity to record
   * @returns {Promise<void>}
   */
  async addHistoryCredentialActivity({
    cid,
    title,
    user,
    verb
  }: {
    cid: string
    title: string
    user: User
    verb: CredentialActivityVerb
  }) {
    const buildActivity = CREDENTIAL_ACTIVITY_BUILDERS[verb]
    await this.#recordActivity(id => buildActivity({ cid, title, user, id }))
  }

  /**
   * Records (in the `wallet-activity` collection) a Login activity: the user
   * logged in to a relying party via "Login with Wallet", granting the listed
   * capabilities. The recorded zcap ids are the hook for a revocation UI: the
   * WAS server now exposes a Space-scoped revocation endpoint, so a grant can
   * be retired before its expiry.
   *
   * @param options {object}
   * @param options.user {User}
   * @param options.origin {string}   the relying party's origin
   * @param options.grants {Array<{ id: string; target: string;
   *   allowedActions: string[]; expires: string; zcap?: IZcap }>}   each grant
   *   carries its display summary plus, when available, the full delegated
   *   capability document (`zcap`) kept verbatim so it can be revoked later
   * @param [options.appConnect] {{ name: string; firstRun: boolean;
   *   appUrl?: string }}   set for an App Connect login: the app's display
   *   name, whether the app key was minted on this connect (first run) or
   *   matched (returning), and the validated request's `appUrl` -- what tells
   *   two apps sharing an origin apart
   * @param [options.actor] {{ name: string }}   the requester's self-declared
   *   display name on a standalone capability request, recorded as
   *   `object.actor`
   * @returns {Promise<void>}
   */
  async addHistoryLogin({
    user,
    origin,
    grants,
    appConnect,
    actor
  }: {
    user: User
    origin: string
    grants: Array<{
      id: string
      target: string
      allowedActions: string[]
      expires: string
      zcap?: IZcap
    }>
    appConnect?: { name: string; firstRun: boolean; appUrl?: string }
    actor?: { name: string }
  }) {
    await this.#recordActivity(id =>
      buildHistoryLogin({ user, origin, grants, appConnect, actor, id })
    )
  }

  /**
   * Records (in the `wallet-activity` collection) the Login activity for a
   * local sign-in: the user opened their own wallet, no relying party
   * involved. `addHistoryLogin` above stays the RP-login builder (an origin
   * and its grants); this one carries only the actor, so both wallets record
   * the same summary for the same event.
   *
   * @param options {object}
   * @param options.user {User}
   * @returns {Promise<void>}
   */
  async addHistoryWalletLogin({ user }: { user: User }) {
    await this.#recordActivity(id => buildHistoryWalletLogin({ user, id }))
  }

  /**
   * Records (in the `wallet-activity` collection) a Revoke activity: the user
   * revoked a connected app's access, retiring its app-key credential and its
   * storage grants. The recorded origin and app name are the audit trail for
   * the Applications settings section; the deletion of the app-key credential
   * itself is a separate credential activity.
   *
   * @param options {object}
   * @param options.user {User}
   * @param options.origin {string}   the connected app's origin
   * @param options.name {string}   the connected app's display name
   * @param [options.cid] {string}   the retired app-key credential's cid
   * @param [options.revoked] {number}   how many storage grants were revoked
   * @param [options.skipped] {number}   how many grants needed no revocation
   *   (legacy summary-only records, already-expired, or already-revoked)
   * @returns {Promise<void>}
   */
  async addHistoryAppRevoke({
    user,
    origin,
    name,
    cid,
    revoked,
    skipped
  }: {
    user: User
    origin: string
    name: string
    cid?: string
    revoked?: number
    skipped?: number
  }) {
    await this.#recordActivity(id =>
      buildHistoryAppRevoke({ user, origin, name, cid, revoked, skipped, id })
    )
  }

  /**
   * Records (in the `wallet-activity` collection) a Revoke activity for an
   * agent grant: the user revoked the storage grants answered from an
   * interaction-URL request. The recorded controller is the grantee did:key
   * the Applications listing joins its agent rows on, so writing this row is
   * what takes the agent out of the listing.
   *
   * @param options {object}
   * @param options.user {User}
   * @param options.origin {string}   the recorded origin marker
   * @param options.controller {string}   the grantee did:key
   * @param [options.zcaps] {Array<{ id: string }>}   the revoked capability ids
   * @param [options.actor] {{ name: string }}   the agent's self-declared name
   * @param [options.revoked] {number}   how many grants were revoked
   * @param [options.skipped] {number}   how many grants needed no revocation
   * @param [options.created] {string}   the `created` stamp, when the caller
   *   needs a specific one (the agent revocation floors it past the Login it
   *   retires, so a clock behind the granting client still hides the row)
   * @returns {Promise<void>}
   */
  async addHistoryAgentRevoke({
    user,
    origin,
    controller,
    zcaps,
    actor,
    revoked,
    skipped,
    created
  }: {
    user: User
    origin: string
    controller: string
    zcaps?: Array<{ id: string }>
    actor?: { name: string }
    revoked?: number
    skipped?: number
    created?: string
  }) {
    await this.#recordActivity(id =>
      buildHistoryAgentRevoke({
        user,
        origin,
        controller,
        zcaps,
        actor,
        revoked,
        skipped,
        id,
        created
      })
    )
  }

  /**
   * Records (in the `wallet-activity` collection) a ClientRevoke activity: an
   * enrolled wallet client was disconnected -- the revocation cascade's audit
   * record.
   *
   * @param options {object}
   * @param options.user {User}
   * @param options.signingKeyMultibase {string}   the revoked client's signing
   *   key multibase
   * @param [options.label] {string}
   * @param [options.rotated] {number}   collections that took a fresh epoch
   * @param [options.failed] {number}   collections the cascade could not
   *   rotate (the completion sweep's remainder)
   * @returns {Promise<void>}
   */
  async addHistoryClientRevoked({
    user,
    signingKeyMultibase,
    label,
    rotated,
    failed
  }: {
    user: User
    signingKeyMultibase: string
    label?: string
    rotated?: number
    failed?: number
  }) {
    await this.#recordActivity(id =>
      buildHistoryClientRevoked({
        user,
        signingKeyMultibase,
        label,
        rotated,
        failed,
        id
      })
    )
  }

  /**
   * Revokes the storage grants a connected app received through App Connect.
   * Scans the `Login` activities for App Connect records matching the app's
   * `origin`, collects the full delegated capabilities recorded on them that
   * were delegated to the app's `subjectDid`, and revokes each one via the
   * Space's root capability (the Space controller can revoke anything it
   * delegated). The app never receives decryption key material, so unlike a
   * collection un-share this rotates no epoch and touches no recipient roster.
   *
   * Per capability, `#revokeZcaps`'s contract: a grant the verified account
   * document already reads as dead (expired, orphaned, or chained under a
   * parent delegation that has rotted) is skipped without a POST, the server's
   * `AlreadyRevokedError` counts as skipped, and any other failure -- a plain
   * `ValidationError` included -- is thrown after every POST settles, so the
   * caller keeps the credential and retries rather than recording a
   * revocation the server never accepted. Legacy records that stored only a
   * display summary (no full zcap) are nothing to revoke -- expiry is their
   * backstop -- and count as skipped. A no-op returning zero counts when no
   * remote store is configured.
   *
   * @param options {object}
   * @param options.origin {string}   the connected app's origin
   * @param options.subjectDid {string}   the app-key credential's subject DID,
   *   the controller the grants were delegated to
   * @param [options.items] {Array<{ id: string; doc: WalletActivity }>}   a
   *   pre-fetched history scan, when the caller already holds one
   * @returns {Promise<{ revoked: number; skipped: number }>}
   */
  async revokeAppGrants({
    origin,
    subjectDid,
    items
  }: {
    origin: string
    subjectDid: string
    items?: Array<{ id: string; doc: WalletActivity }>
  }): Promise<{ revoked: number; skipped: number }> {
    const remote = this.#remoteStore
    if (!remote) {
      return { revoked: 0, skipped: 0 }
    }
    // Scan the history once and pass it through, so the grant lookup does not
    // re-await and re-scan it. A caller that already holds the history (the
    // revoke orchestration, which drives several of these) passes it in.
    const { zcaps, skipped: nonRevocable } = this.#recordedGrantZcaps({
      matches: object => object.origin === origin && !!object.appConnect,
      controller: subjectDid,
      items: items ?? (await this.listHistoryItems())
    })
    const outcome = await this.#revokeZcaps({ zcaps })
    return {
      revoked: outcome.revoked,
      skipped: outcome.skipped + nonRevocable
    }
  }

  /**
   * Revokes a set of recorded capabilities on the WAS server, one POST each
   * through wallet-core's `revokeRecordedGrant`, whose policy each POST
   * follows: the one local skip is a capability expired beyond the
   * revocation clock-skew margin; everything else is POSTed, whatever the
   * verified document says about its signer; was-client's
   * `AlreadyRevokedError` counts as skipped; a plain `ValidationError` is
   * read against the document and counts as skipped when the client can say
   * why the chain no longer verifies (expired, an orphaned account-signed
   * grant, a parent delegation whose signer left the document, or a
   * generation the document no longer points at), and is thrown otherwise,
   * as is every other failure. The POSTs are independent, so they run
   * together and all of them settle before the outcome is folded in the
   * order the capabilities were given. Once every POST has settled the
   * first failure is thrown verbatim, `err.name` intact, so the caller
   * neither deletes the credential nor records the Revoke and a retry re-runs
   * the set; the ids that did land, and the reasons the rest were skipped,
   * ride the warn logged before the throw, since the caller records nothing.
   * `revokedIds` names only the capabilities whose POST succeeded, which is
   * what an agent revocation records as its audit trail.
   *
   * The verified document's reading is resolved here, once per set and only
   * when the set is non-empty, through the session-layer resolver bound at
   * construction; best-effort, so a read that throws is logged and read as
   * no check, and every unexpired grant is POSTed.
   *
   * @param options {object}
   * @param options.zcaps {IDelegatedZcap[]}
   * @returns {Promise<{ revoked: number; skipped: number; revokedIds: string[] }>}
   */
  async #revokeZcaps({ zcaps }: { zcaps: IDelegatedZcap[] }): Promise<{
    revoked: number
    skipped: number
    revokedIds: string[]
  }> {
    const remote = this.#remoteStore
    if (!remote) {
      return { revoked: 0, skipped: 0, revokedIds: [] }
    }
    if (zcaps.length === 0) {
      return { revoked: 0, skipped: 0, revokedIds: [] }
    }
    const space = remote.spaceHandle()
    const signerCheck = await this.#readSignerCheck()
    const now = Date.now()
    const outcomes = await Promise.allSettled(
      zcaps.map(zcap =>
        revokeRecordedGrant({
          revoke: delegation => space.revoke(delegation),
          zcap,
          signerCheck,
          now
        })
      )
    )
    const revokedIds: string[] = []
    const skipped: Array<{ id: string; reason: string }> = []
    const failed: Array<{ id: string; err: unknown }> = []
    outcomes.forEach((outcome, index) => {
      const { id } = zcaps[index]
      if (outcome.status === 'rejected') {
        failed.push({ id, err: outcome.reason })
      } else if (outcome.value === 'revoked') {
        revokedIds.push(id)
      } else {
        skipped.push({ id, reason: outcome.value })
      }
    })
    if (failed.length > 0) {
      // The ids that DID land, and why the rest were skipped, are
      // diagnosable here and nowhere else: the throw carries the first
      // failure alone, and the caller records nothing.
      log.warn('Could not revoke every recorded grant; none recorded', {
        failed: failed.map(entry => entry.id),
        revokedIds,
        skipped
      })
      throw failed[0].err
    }
    return { revoked: revokedIds.length, skipped: skipped.length, revokedIds }
  }

  /**
   * The verified account document's reading, best-effort: a resolver that
   * throws (the log cannot be fetched or verified right now) is logged and
   * read as no check, so the revocation degrades to POSTing every unexpired
   * grant rather than failing.
   *
   * @returns {Promise<AccountSignerCheck | undefined>}
   */
  async #readSignerCheck(): Promise<AccountSignerCheck | undefined> {
    try {
      return await this.#signerCheckFor()
    } catch (err) {
      log.warn(
        'Could not read the account key set for the grant revocation; posting every unexpired grant',
        { err }
      )
      return undefined
    }
  }

  /**
   * Revokes the storage grants recorded for a connected agent: the
   * capabilities delegated to `controller` on the interaction-URL request
   * page's Login activities. There is no app key and no epoch roster involved
   * -- an agent is a grantee only. Per capability this is `#revokeZcaps`'s
   * contract: a grant the verified document reads as dead is skipped without
   * a POST, `AlreadyRevokedError` counts as skipped, and any other failure is
   * thrown after every POST settles, so the caller records no Revoke and the
   * row stays listed for a retry.
   *
   * @param options {object}
   * @param options.controller {string}   the grantee did:key
   * @param [options.items] {Array<{ id: string; doc: WalletActivity }>}   a
   *   pre-fetched history scan, when the caller already holds one
   * @returns {Promise<{ revoked: number; skipped: number; revokedIds: string[] }>}
   */
  async revokeAgentGrants({
    controller,
    items
  }: {
    controller: string
    items?: Array<{ id: string; doc: WalletActivity }>
  }): Promise<{ revoked: number; skipped: number; revokedIds: string[] }> {
    if (!this.#remoteStore) {
      return { revoked: 0, skipped: 0, revokedIds: [] }
    }
    const { zcaps, skipped: nonRevocable } = this.#recordedGrantZcaps({
      matches: object =>
        object.origin === EXTERNAL_REQUEST_ORIGIN && !object.appConnect,
      controller,
      items: items ?? (await this.listHistoryItems())
    })
    const outcome = await this.#revokeZcaps({ zcaps })
    return {
      revoked: outcome.revoked,
      skipped: outcome.skipped + nonRevocable,
      revokedIds: outcome.revokedIds
    }
  }

  /**
   * The WAS collection id a grant zcap targets, when its `invocationTarget`
   * addresses a Collection of the given Space, classified by was-client's path
   * grammar. Returns undefined for anything else -- a whole-Space target, a
   * resource or reserved sub-endpoint, another Space, or a foreign URL.
   *
   * @param options {object}
   * @param options.invocationTarget {string}
   * @param options.serverUrl {string}   the storage server's base URL
   * @param options.spaceId {string}
   * @returns {string | undefined}
   */
  static #collectionIdFromTarget({
    invocationTarget,
    serverUrl,
    spaceId
  }: {
    invocationTarget: string
    serverUrl: string
    spaceId: string
  }): string | undefined {
    const parsed = parseSpaceTarget({ serverUrl, target: invocationTarget })
    if (parsed?.kind !== 'collection' || parsed.spaceId !== spaceId) {
      return undefined
    }
    return parsed.collectionId
  }

  /**
   * Whether a collection id names a protected wallet collection -- a standard
   * collection, or one of the account's system collections
   * (`SYSTEM_COLLECTIONS`: `id`, `key-map`, `unlock-methods`). Never an
   * app-provisioned one, so it is excluded from recipient-removal on
   * revocation.
   *
   * @param collectionId {string}
   * @returns {boolean}
   */
  static #isProtectedCollection(collectionId: string): boolean {
    return (
      SYSTEM_COLLECTIONS.some(entry => entry.id === collectionId) ||
      WALLET_STANDARD_COLLECTIONS.some(entry => entry.id === collectionId)
    )
  }

  /**
   * The key-rotation half of revoking a connected app's access: for each
   * app-provisioned encrypted collection the app was granted, removes every
   * non-owner recipient entry from the current epoch in ONE was-client
   * `removeRecipient` call (which rotates the epoch FIRST, then runs the pull
   * axis -- indivisible), so a revoked app cannot decrypt future writes.
   * However many non-owner entries retire, the collection gains one epoch and
   * its pull-axis zcaps are revoked once. The owner (the vault KAK) stays
   * recipient zero; for
   * these collections every non-owner entry is the app's, and removal needs no
   * seed (the roster kid is in the descriptor), so it works even for an
   * orphaned state.
   *
   * The candidate collections come from the recorded grant zcaps'
   * `invocationTarget`s (standard / protected collections and whole-Space grants
   * excluded); only those whose current-epoch roster still carries a non-owner
   * entry are rotated, and the collections rotate in parallel. Best-effort per
   * collection: a failure is logged and the rest proceed, so one stuck
   * collection does not strand the whole revocation. A no-op (zero counts)
   * without a remote store or vault keys. The honest limitation stands:
   * ciphertext the app already fetched stays readable to it.
   *
   * @param options {object}
   * @param options.origin {string}   the connected app's origin
   * @param options.subjectDid {string}   the app-key credential's subject DID
   * @param [options.items] {Array<{ id: string; doc: WalletActivity }>}   a
   *   pre-fetched history scan, when the caller already holds one
   * @returns {Promise<{ collections: number; rotated: number; failed: number }>}
   */
  async revokeAppCollectionRecipients({
    origin,
    subjectDid,
    items
  }: {
    origin: string
    subjectDid: string
    items?: Array<{ id: string; doc: WalletActivity }>
  }): Promise<{ collections: number; rotated: number; failed: number }> {
    const remote = this.#remoteStore
    if (!remote || !this.#vaultKeys) {
      return { collections: 0, rotated: 0, failed: 0 }
    }
    const ownerKid = this.#vaultKeys.keyAgreementKey.id
    const { zcaps } = this.#recordedGrantZcaps({
      matches: object => object.origin === origin && !!object.appConnect,
      controller: subjectDid,
      items: items ?? (await this.listHistoryItems())
    })

    // Group the pull-axis zcaps by the app-provisioned collection they target,
    // dropping whole-Space and protected-collection grants.
    const byCollection = new Map<string, IDelegatedZcap[]>()
    for (const zcap of zcaps) {
      const collectionId = StorageManager.#collectionIdFromTarget({
        invocationTarget: zcap.invocationTarget,
        serverUrl: remote.storageServerUrl,
        spaceId: remote.spaceId
      })
      if (
        !collectionId ||
        StorageManager.#isProtectedCollection(collectionId)
      ) {
        continue
      }
      const existing = byCollection.get(collectionId)
      if (existing) {
        existing.push(zcap)
      } else {
        byCollection.set(collectionId, [zcap])
      }
    }

    // Each collection's rotation is independent of the others, so they run
    // together; the outcomes are folded below into the same counts a
    // sequential pass produced.
    const outcomes = await Promise.all(
      [...byCollection].map(async ([collectionId, revoke]) => {
        try {
          const descriptor = await this.#readGovernedDescriptor({
            collectionId
          })
          if (!descriptor?.epochs?.length || !descriptor.currentEpoch) {
            return 'skipped' as const
          }
          const nonOwner = currentEpochRecipientKids({ descriptor, ownerKid })
          if (nonOwner.length === 0) {
            return 'skipped' as const
          }
          const newDescriptor = await removeRecipient({
            store: await this.#collectionStore({
              collectionId,
              action: 'Revoking an app collection recipient'
            }),
            space: remote.spaceHandle(),
            revoke,
            recipientId: nonOwner
          })
          await this.#descriptorCache?.writeDescriptor({
            collectionId,
            descriptor: newDescriptor
          })
          this.#appDescriptors[collectionId] = newDescriptor
          delete this.#appCiphers[collectionId]
          this.#refreshPolicy.reset({ collectionId })
          return 'rotated' as const
        } catch (err) {
          log.warn(
            'Could not rotate the epoch for app collection during revocation',
            {
              collectionId,
              err
            }
          )
          return 'failed' as const
        }
      })
    )
    const rotated = outcomes.filter(outcome => outcome === 'rotated').length
    const failed = outcomes.filter(outcome => outcome === 'failed').length
    return { collections: byCollection.size, rotated, failed }
  }

  /**
   * The full delegated zcaps recorded for one grantee, scanned from the
   * `Login` history activities `matches` accepts: those whose recorded `zcap`
   * was delegated to `controller` and has not already expired by its own
   * `expires` (wallet-core's `delegationExpired`, beyond the revocation
   * clock-skew margin; an absent or unparseable
   * value is not expired). Deduplicated by capability id. `skipped` counts
   * the entries that carry no revocable capability (legacy summary-only
   * records, a different controller, or an already-expired grant). The predicate is what tells the two grantee kinds
   * apart: an App Connect app (an origin plus an `appConnect` member) and an
   * agent (the interaction-URL origin marker and no `appConnect`).
   *
   * @param options {object}
   * @param options.matches {Function}   the Login-object predicate
   * @param options.controller {string}   the grantee the grants were
   *   delegated to
   * @param options.items {Array<{ id: string; doc: WalletActivity }>}   the
   *   pre-fetched history, so this need not re-scan it
   * @returns {{ zcaps: IDelegatedZcap[]; skipped: number }}
   */
  #recordedGrantZcaps({
    matches,
    controller,
    items
  }: {
    matches: (object: {
      origin?: string
      appConnect?: unknown
      zcaps?: unknown
    }) => boolean
    controller: string
    items: Array<{ id: string; doc: WalletActivity }>
  }): { zcaps: IDelegatedZcap[]; skipped: number } {
    const zcaps: IDelegatedZcap[] = []
    const seen = new Set<string>()
    const now = Date.now()
    let skipped = 0
    for (const { doc } of items) {
      if (!doc.type?.includes('Login')) {
        continue
      }
      const object = doc.object as
        { origin?: string; appConnect?: unknown; zcaps?: unknown } | undefined
      if (!object || !matches(object)) {
        continue
      }
      if (!Array.isArray(object.zcaps)) {
        continue
      }
      for (const entry of object.zcaps) {
        const zcap = ((entry ?? {}) as { zcap?: IZcap }).zcap
        // A legacy summary-only entry has no revocable capability; expiry is
        // the backstop.
        if (!zcap || !('parentCapability' in zcap)) {
          skipped += 1
          continue
        }
        // Only revoke capabilities delegated to this grantee's key.
        const controllers = Array.isArray(zcap.controller)
          ? zcap.controller
          : [zcap.controller]
        if (!controllers.includes(controller)) {
          skipped += 1
          continue
        }
        if (seen.has(zcap.id)) {
          continue
        }
        seen.add(zcap.id)
        // The one expiry reading every revocation path shares: the zcap's
        // own `expires`, and an absent or unparseable one is NOT expired.
        if (delegationExpired({ zcap, now })) {
          skipped += 1
          continue
        }
        zcaps.push(zcap)
      }
    }
    return { zcaps, skipped }
  }

  /**
   * Whether public links (sharing) are available this session. A public link
   * only means something as a world-readable URL on the remote WAS server, so
   * sharing requires a remote replica to be configured.
   */
  get canShare(): boolean {
    return !!this.#remoteStore
  }

  /**
   * The public URL a credential would resolve to once shared, or `undefined`
   * when there is no remote backend.
   */
  publicLinkUrl({ cid }: { cid: string }): string | undefined {
    return this.#remoteStore?.publicCredentialUrl(cid)
  }

  /**
   * Creates a world-readable public link for a credential and returns its URL.
   * The public copy is plaintext and content-addressed (keyed by the
   * credential's cid, a hash of its content). It is written to the local
   * `public-credentials` collection; background replication mirrors it to the
   * remote WAS Collection, where the returned URL resolves.
   *
   * @param credential {IVerifiableCredential}
   * @returns {Promise<string>}
   */
  async createPublicLink({
    credential
  }: {
    credential: IVerifiableCredential
  }): Promise<string> {
    const remote = this.#requireRemote('Creating a public link')
    const cid = await cidFrom({ doc: credential })
    await this.#store.addPublicCredential({ cid, credential })
    return remote.publicCredentialUrl(cid)
  }

  /**
   * Revokes a credential's public link by removing its copy from the local
   * `public-credentials` collection (replication pushes the delete to the
   * remote Collection).
   *
   * @param cid {string}
   * @returns {Promise<void>}
   */
  async removePublicLink({ cid }: { cid: string }): Promise<void> {
    await this.#store.removePublicCredential({ cid })
  }

  async isShared({ cid }: { cid: string }): Promise<boolean> {
    return await this.#store.hasPublicCredential({ cid })
  }

  /**
   * Lists the items in the `wallet-activity` history collection.
   */
  async listHistoryItems(): Promise<
    Array<{ id: string; doc: WalletActivity }>
  > {
    // Same stale-descriptor refresh as `listCredentials`, once per session.
    return this.#readWithEpochRefresh({
      collectionId: 'wallet-activity',
      read: async () => ({
        value: await this.#store.listHistoryItems(),
        unknownEpoch: this.#store.unknownEpochHistory > 0
      })
    })
  }

  /**
   * Shares one of the wallet's encrypted collections with another reader,
   * doing BOTH halves of a share as one procedure: the read axis (an epoch-key
   * recipient entry, so the reader can decrypt) and the pull axis (a read-only
   * Collection zcap delegated to the grantee, so the server serves it
   * ciphertext). Requires a passphrase session (the root key delegates and the
   * recipient operations rewrite the Collection Description) with an unlocked
   * vault and a remote store.
   *
   * The read axis is always `addRecipient`: every encrypted collection
   * carries its key epochs from provisioning (epoch[0] wrapped to the user
   * key; the first-epoch mint runs only there), so a share escrows the reader
   * into every existing epoch (no rotation -- adds are cheap) and an
   * epoch-less descriptor is refused fail-closed rather than seeded here (it
   * can only mean an unprovisioned or torn collection). The delegated zcap
   * (the full document, needed later for revocation) is recorded in a
   * `CollectionShare` history activity, and the refreshed descriptor is cached and
   * swapped into the local ciphers.
   *
   * @param options {object}
   * @param options.profile {ControllerProfile}   the passphrase session profile
   *   (root `zcapClient` + vault KAK)
   * @param options.user {User}   recorded as the share activity's actor
   * @param options.collectionId {string}   the WAS collection id to share
   * @param options.recipient {RecipientPublicKey}   the grantee's public
   *   key-agreement key (its `id` is the recipient `kid`)
   * @param options.controller {string}   the grantee's DID (the zcap controller)
   * @param [options.expires] {Date}   the pull zcap's expiry; defaults to the
   *   read-only grant TTL
   * @param [options.app] {{ name: string, origin: string }}   the connected app
   *   the share was granted to, when the grantee is one; recorded on the share
   *   activity so the settings panel can name it instead of showing a bare DID
   * @returns {Promise<{ descriptor: CollectionEncryption, zcap: IDelegatedZcap }>}
   *   the new descriptor and the delegated pull-axis capability (the caller embeds
   *   it in its response -- the grantee needs both axes)
   */
  async shareCollection({
    profile,
    user,
    collectionId,
    recipient,
    controller,
    expires,
    app
  }: {
    profile: ControllerProfile
    user: User
    collectionId: string
    recipient: RecipientPublicKey
    controller: string
    expires?: Date
    app?: { name: string; origin: string }
  }): Promise<{ descriptor: CollectionEncryption; zcap: IDelegatedZcap }> {
    const remote = this.#requireRemote('Sharing a collection')
    const { keyAgreementKey, keyResolver, zcapClient } = profile
    if (!keyAgreementKey || !keyResolver) {
      throw new Error('Sharing a collection requires the vault key material.')
    }
    if (!profile.keyAgent) {
      throw new Error('Sharing a collection requires a passphrase session.')
    }

    // Read axis: escrow the reader into the existing epochs (epoch[0] exists
    // from provisioning, wrapped to the owner -- recipient zero), one signed
    // append on the collection's governing log.
    const descriptor = await addRecipient({
      store: await this.#collectionStore({
        collectionId,
        action: 'Sharing a collection'
      }),
      recipient,
      owner: { keyAgreementKey }
    })

    // Pull axis: delegate a read-only (GET/HEAD) zcap on the collection URL to
    // the grantee, rooted at the Space root capability (targets outside the
    // Space are unsatisfiable by construction) -- or, in a transient session,
    // chained under the generation delegation the session's authority rides,
    // with the expiry clamped to the delegation's own.
    const spaceUrl = remote.spaceUrl
    const spaceRootCapability = rootCapabilityId(spaceUrl)
    // The store's own canonical form: the grant's target must match the URL
    // the grantee's request addresses byte for byte.
    const collectionUrl = remote.collectionTargetUrl(collectionId)
    const now = Date.now()
    const requestedExpires = expires ?? new Date(now + RP_ZCAP_TTL_MS)
    const expiresAt = profile.invocationCapability
      ? clampGrantExpires({
          ttlMs: requestedExpires.getTime() - now,
          delegation: profile.invocationCapability,
          now
        })
      : requestedExpires
    const zcap = (await zcapClient.delegate({
      capability: profile.invocationCapability ?? spaceRootCapability,
      invocationTarget: collectionUrl,
      controller,
      allowedActions: ['GET', 'HEAD'],
      expires: expiresAt
    })) as unknown as IDelegatedZcap

    // Record the share -- the full delegated zcap document is the revocation
    // hook `unshareCollection` reads back.
    await this.#recordActivity(id =>
      buildHistoryCollectionShared({
        user,
        collectionId,
        recipientId: recipient.id,
        controller,
        zcap,
        expires: expiresAt.toISOString(),
        app,
        id
      })
    )

    // Update the descriptor cache and rebuild + swap the ciphers under it.
    await this.#adoptCollectionDescriptor({
      collectionId,
      descriptor,
      vaultKeys: { keyAgreementKey, keyResolver }
    })
    return { descriptor, zcap }
  }

  /**
   * Stops sharing one of the wallet's encrypted collections with a reader,
   * doing BOTH halves of an un-share indivisibly via was-client's
   * `removeRecipient`: it rotates the epoch to the remaining current-epoch
   * roster (the read axis; prospective) THEN revokes the recorded zcap(s) (the
   * pull axis; immediate). freewallet never exposes a rotate-only or
   * revoke-only path. Requires a passphrase session with a remote store.
   *
   * Every zcap recorded for this `(collectionId, recipientId)` is looked up
   * from the `CollectionShare` history activities and passed to `revoke`; an
   * empty set is acceptable (e.g. all grants already expired) -- the rotation
   * still happens. A `CollectionUnshare` activity is recorded (no zcap), and
   * the rotated descriptor is cached and swapped into the local ciphers.
   *
   * @param options {object}
   * @param options.profile {ControllerProfile}   the passphrase session profile
   * @param options.user {User}   recorded as the unshare activity's actor
   * @param options.collectionId {string}
   * @param options.recipientId {string}   the removed reader's key-agreement
   *   key id (`kid`)
   * @returns {Promise<CollectionEncryption>}   the new descriptor
   */
  async unshareCollection({
    profile,
    user,
    collectionId,
    recipientId
  }: {
    profile: ControllerProfile
    user: User
    collectionId: string
    recipientId: string
  }): Promise<CollectionEncryption> {
    const remote = this.#requireRemote('Unsharing a collection')
    const { keyAgreementKey, keyResolver } = profile
    if (!keyAgreementKey || !keyResolver) {
      throw new Error('Unsharing a collection requires the vault key material.')
    }
    if (!profile.keyAgent) {
      throw new Error('Unsharing a collection requires a passphrase session.')
    }

    // Gather every zcap recorded for this recipient, to revoke as the pull-axis
    // half of the removal. Scan the history once and pass it through.
    const items = await this.listHistoryItems()
    const revoke = this.#recordedShareZcaps({
      collectionId,
      recipientId,
      items
    })
    const descriptor = await removeRecipient({
      store: await this.#collectionStore({
        collectionId,
        action: 'Unsharing a collection'
      }),
      space: remote.spaceHandle(),
      recipientId,
      revoke
    })

    await this.#recordActivity(id =>
      buildHistoryCollectionUnshared({ user, collectionId, recipientId, id })
    )

    await this.#adoptCollectionDescriptor({
      collectionId,
      descriptor,
      vaultKeys: { keyAgreementKey, keyResolver }
    })
    return descriptor
  }

  /**
   * Adopts a freshly rotated collection descriptor into this session: cached,
   * swapped into the in-memory descriptor map, the refresh policy reset, and
   * this one collection's cipher rebuilt under the given vault keys. The
   * shared tail of `shareCollection` and `unshareCollection`, each of which
   * rotates exactly one collection, so the other five ciphers are left
   * standing rather than rebuilt from the descriptors they already hold.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.descriptor {CollectionEncryption}
   * @param options.vaultKeys {object}
   * @param options.vaultKeys.keyAgreementKey {IKeyAgreementKey}
   * @param options.vaultKeys.keyResolver {IKeyResolver}
   * @returns {Promise<void>}
   */
  async #adoptCollectionDescriptor({
    collectionId,
    descriptor,
    vaultKeys
  }: {
    collectionId: string
    descriptor: CollectionEncryption
    vaultKeys: { keyAgreementKey: IKeyAgreementKey; keyResolver: IKeyResolver }
  }): Promise<void> {
    await this.#descriptorCache?.writeDescriptor({ collectionId, descriptor })
    this.#descriptors = { ...this.#descriptors, [collectionId]: descriptor }
    this.#refreshPolicy.reset()
    this.#vaultKeys = vaultKeys
    await this.#rebuildCipherFor({ collectionId })
  }

  /**
   * The delegated zcap documents recorded for a `(collectionId, recipientId)`
   * pair, scanned from the `CollectionShare` history activities -- the pull-axis
   * capabilities `unshareCollection` revokes.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.recipientId {string}
   * @param options.items {Array<{ id: string; doc: WalletActivity }>}   the
   *   pre-fetched history, so this need not re-scan it
   * @returns {IDelegatedZcap[]}
   */
  #recordedShareZcaps({
    collectionId,
    recipientId,
    items
  }: {
    collectionId: string
    recipientId: string
    items: Array<{ id: string; doc: WalletActivity }>
  }): IDelegatedZcap[] {
    const zcaps: IDelegatedZcap[] = []
    for (const { doc } of items) {
      if (!doc.type?.includes('CollectionShare')) {
        continue
      }
      const object = doc.object as
        | {
            collectionId?: string
            recipientId?: string
            zcap?: IDelegatedZcap
          }
        | undefined
      if (
        object?.collectionId === collectionId &&
        object?.recipientId === recipientId &&
        object?.zcap
      ) {
        zcaps.push(object.zcap)
      }
    }
    return zcaps
  }

  /**
   * Lists the readers a collection is currently shared with, derived from the
   * descriptor's `currentEpoch` roster minus the owner's own key (the cryptographic
   * truth), joined best-effort with the `CollectionShare` / `CollectionUnshare`
   * history for each reader's controller DID, grant expiry, and -- when the
   * reader is a connected app -- its name and origin. Backs the settings UI.
   * Returns an empty list for a collection with no epochs (never shared) or
   * when the descriptor cannot be resolved.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param [options.items] {Array<{ id: string; doc: WalletActivity }>}   a
   *   pre-fetched history scan, when the caller already holds one (the
   *   settings panel lists every shareable collection off one read)
   * @returns {Promise<Array<{ recipientId: string; controller?: string;
   *   expires?: string; appName?: string; appOrigin?: string }>>}
   */
  async listCollectionShares({
    collectionId,
    items
  }: {
    collectionId: string
    items?: Array<{ id: string; doc: WalletActivity }>
  }): Promise<
    Array<{
      recipientId: string
      controller?: string
      expires?: string
      appName?: string
      appOrigin?: string
    }>
  > {
    const remote = this.#remoteStore
    let descriptor: CollectionEncryption | undefined =
      this.#descriptors[collectionId]
    if (!descriptor && remote && this.#descriptorCache) {
      const logs = this.#descriptorLogsFor()
      descriptor = await acquireDescriptor({
        ...(logs ? { source: logs.source } : {}),
        cache: this.#descriptorCache,
        collectionId
      })
    }
    if (!descriptor?.currentEpoch || !descriptor.epochs) {
      return []
    }
    // The owner's own key-agreement key is recipient zero on every epoch; drop
    // it so the list is only the other readers.
    const recipientIds = currentEpochRecipientKids({
      descriptor,
      ownerKid: this.#vaultKeys?.keyAgreementKey.id
    })
    if (recipientIds.length === 0) {
      return []
    }

    // Best-effort labels from history: the latest CollectionShare per recipient
    // for its controller / expiry.
    const labels = new Map<
      string,
      {
        controller?: string
        expires?: string
        appName?: string
        appOrigin?: string
      }
    >()
    for (const { doc } of items ?? (await this.listHistoryItems())) {
      if (!doc.type?.includes('CollectionShare')) {
        continue
      }
      const object = doc.object as
        | {
            collectionId?: string
            recipientId?: string
            controller?: string
            expires?: string
            appName?: string
            appOrigin?: string
          }
        | undefined
      if (object?.collectionId === collectionId && object?.recipientId) {
        labels.set(object.recipientId, {
          controller: object.controller,
          expires: object.expires,
          appName: object.appName,
          appOrigin: object.appOrigin
        })
      }
    }
    return recipientIds.map(recipientId => ({
      recipientId,
      ...labels.get(recipientId)
    }))
  }

  /**
   * Lists the stored contacts. Unknown-epoch rows mean the contacts cipher
   * may be built from a stale descriptor (a rekey emits no change-feed
   * entry), so the shared helper refreshes the descriptor once and re-reads,
   * uniformly for both backends -- the same seam `listCredentials` rides.
   *
   * @returns {Promise<Array<StoredContact>>}
   */
  async listContacts(): Promise<Array<StoredContact>> {
    return this.#readWithEpochRefresh({
      collectionId: 'contacts',
      read: async () => ({
        value: await this.#store.listContacts(),
        unknownEpoch: this.#store.unknownEpochContacts > 0
      })
    })
  }

  /**
   * @param options {object}
   * @param options.id {string}
   * @returns {Promise<StoredContact | undefined>}
   */
  async loadContact({
    id
  }: {
    id: string
  }): Promise<StoredContact | undefined> {
    return await this.#store.loadContact({ id })
  }

  /**
   * Adds a contact and appends its `create` revision to `contacts-history`
   * (best-effort: the contact is already stored either way).
   *
   * @param options {object}
   * @param options.contact {ContactData}
   * @returns {Promise<StoredContact>}
   */
  async addContact({
    contact
  }: {
    contact: ContactData
  }): Promise<StoredContact> {
    const writerId = this.#persistence.getWriterId()
    const stored = await this.#store.addContact({ contact, writerId })
    await this.#recordContactRevision({
      contactId: stored.contactId,
      action: 'create',
      snapshot: contact,
      writerId
    })
    return stored
  }

  /**
   * Rewrites a contact's row in place and appends its `update` revision.
   *
   * Restoring an earlier version is the same write with `action: 'restore'`:
   * the snapshot replaces the contact wholesale and the appended revision
   * records which of the two it was.
   *
   * @param options {object}
   * @param options.id {string}
   * @param options.contact {ContactData}
   * @param [options.action] {'update' | 'restore'}
   * @returns {Promise<StoredContact>}
   */
  async updateContact({
    id,
    contact,
    action = 'update'
  }: {
    id: string
    contact: ContactData
    action?: 'update' | 'restore'
  }): Promise<StoredContact> {
    const writerId = this.#persistence.getWriterId()
    const stored = await this.#store.updateContact({
      id,
      contact,
      writerId
    })
    await this.#recordContactRevision({
      contactId: stored.contactId,
      action,
      snapshot: contact,
      writerId
    })
    return stored
  }

  /**
   * Deletes a contact and appends a `delete` revision carrying its last known
   * snapshot (read before the row is removed).
   *
   * @param options {object}
   * @param options.id {string}
   * @returns {Promise<void>}
   */
  async deleteContact({ id }: { id: string }): Promise<void> {
    const existing = await this.#store.loadContact({ id })
    await this.#store.deleteContact({ id })
    if (existing) {
      await this.#recordContactRevision({
        contactId: existing.contactId,
        action: 'delete',
        snapshot: existing.contact,
        writerId: this.#persistence.getWriterId()
      })
    }
  }

  /**
   * Best-effort revision write shared by `addContact`/`updateContact`/
   * `deleteContact`: the contact mutation itself has already landed, so a
   * failure here (e.g. a transient encryption hiccup) is logged rather than
   * thrown -- losing one history line beats reporting the whole save/delete
   * as failed.
   *
   * @param options {object}
   * @param options.contactId {string}
   * @param options.action {ContactRevisionPayload['action']}
   * @param options.snapshot {ContactData}
   * @param options.writerId {string}
   * @returns {Promise<void>}
   */
  async #recordContactRevision({
    contactId,
    action,
    snapshot,
    writerId
  }: {
    contactId: string
    action: ContactRevisionPayload['action']
    snapshot: ContactData
    writerId: string
  }): Promise<void> {
    try {
      await this.#store.addContactRevision({
        revision: {
          contactId,
          action,
          timestamp: new Date().toISOString(),
          writerId,
          snapshot
        }
      })
    } catch (err) {
      log.warn('Could not record the contact revision', { action, err })
    }
  }

  /**
   * Lists a contact's revision history, most recent first. Keyed by the
   * LOGICAL contact id (`StoredContact.contactId`, the id inside the head
   * payload that every replica's revisions refer to), not the row id --
   * for mobile-authored contacts the two differ.
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
    return await this.#store.listContactRevisions({ contactId })
  }
}

/**
 * The keystore half of controller promotion, non-fatal by design (no wallet
 * feature hard-depends on the keystore): promotes the keystore config's
 * controller to the did:webvh -- retrying once with the did:key identity
 * when the bound agent's invocation is refused (a keystore not yet
 * promoted, invoked as the did:webvh) -- and rebinds the session's
 * KeystoreAgent to invoke under the promoted identity.
 *
 * Fired without await from the Space promotion path: the keystore's
 * promotion has no ordering dependency on anything that follows, and a KMS
 * hiccup only surfaces as the same warn a failed keystore provisioning
 * does. It never rejects: the outcome is the value, so the login chain's
 * pointer heal can report it beside the two Space-side predicates it
 * converges.
 *
 * @param options {object}
 * @param options.profile {ControllerProfile}
 * @param options.did {string}   the account's did:webvh DID
 * @returns {Promise<MendOutcome>}   `noop` when this session holds no
 *   keystore to promote and when the keystore already named the account,
 *   `clean` when a promotion was written here, `failed` (with the error's
 *   name alone) otherwise
 */
export async function promoteAccountKeystore({
  profile,
  did
}: {
  profile: ControllerProfile
  did: string
}): Promise<MendOutcome> {
  const { keystoreAgent, keyAgent } = profile
  if (!keystoreAgent || !keyAgent) {
    return { outcome: 'noop' }
  }
  try {
    let promoted: boolean
    try {
      promoted = await promoteKeystoreController({
        keystoreAgent,
        controller: did
      })
    } catch {
      // The bound identity could not read/update the config -- a keystore
      // still under the did:key invoked as the did:webvh. Retry as the
      // did:key.
      const didKeyBound = rebindKeystoreAgent({
        keystoreAgent,
        capabilityAgent: keyAgent
      })
      promoted = await promoteKeystoreController({
        keystoreAgent: didKeyBound,
        controller: did
      })
    }
    profile.keystoreAgent = rebindKeystoreAgent({
      keystoreAgent,
      capabilityAgent: webvhCapabilityAgent({ keyAgent, did })
    })
    return { outcome: promoted ? 'clean' : 'noop' }
  } catch (err) {
    log.warn('Keystore controller promotion failed', { err })
    return { outcome: 'failed', errorName: errorNameOf(err) }
  }
}
