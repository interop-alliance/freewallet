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
  IKeyAgreementKey,
  IKeyResolver,
  IVerifiableCredential,
  IZcap
} from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import {
  CONTACTS_COLLECTION,
  isUnlinkedSeedTwin,
  upgradeContactHeadPayload,
  upgradeContactRevisionPayload,
  type ContactData,
  type ContactHeadPayload,
  type ContactRevisionPayload
} from '@interop/social-core'
import type { RxCollection, RxStorage } from 'rxdb/plugins/core'
import {
  KeyUnwrapError,
  isGovernedDescriptor,
  type CollectionEncryption,
  type CollectionGenerator,
  type IDelegatedZcap,
  type IndexSchema,
  type ServiceDescription,
  type SpaceMetadata
} from '@interop/was-client'
import {
  acquireDescriptor,
  acquireDescriptors,
  addRecipient,
  DescriptorRefreshPolicy,
  removeRecipient,
  trustRosterDidKeys,
  x25519RecipientFromDidKey,
  type EncryptionDescriptorCache,
  type EncryptionDescriptorSource,
  type EncryptionDescriptorStore,
  type RecipientPublicKey
} from '@interop/was-client/edv'
import { rootCapabilityId } from '@interop/was-client/paths'
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
import { cidFrom, contentCid } from '@interop/was-client/sync'
import { equalBytes } from '@noble/ciphers/utils.js'
import { classifyDecryptFailure } from '@/lib/decryptFailure'
import { refreshingCollectionCipher } from '@/stores/refreshingCollectionCipher'
import {
  ENCRYPTED_STANDARD_COLLECTIONS,
  RP_ZCAP_TTL_MS,
  isProtectedCollection,
  WALLET_STANDARD_COLLECTIONS,
  WAS_SERVER_URL
} from '@/app.config'
import {
  assertMintedAppKey,
  assertStorableAppKey,
  presentsAsAppKey
} from '@interop/wallet-request'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { SEED_CONTACT_NAMES } from '@/fixtures/defaultContacts'
import { WALK_STOPPING_ERROR_NAME } from '@interop/wallet-backup'
import type {
  HeldAppResources,
  HeldContent,
  ImportOutcome
} from '@/types/migration'
import { didWebFromSpace } from '@/lib/didWeb'
import { ensureKmsAuthentication } from '@/lib/kms'
import { collectionIdFromTarget } from '@/lib/zcap'
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
import { isAgentActivityObject } from '@/lib/walletRequest/externalRequest'
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

/**
 * What rotating one grantee off its collections' key epochs did:
 * `collections` counts the candidates, `rotated` the collections re-keyed,
 * `failed` the ones that could not be (plus an unreadable listing), and
 * `revokedIds` the capabilities the rotation's pull axis revoked. A
 * collection whose rotation landed counts as rotated even when its pull
 * failed: `failed` counts only where the grantee may still hold a recipient
 * entry, and the capabilities the pull missed are left to the grant stage.
 */
export type RecipientRotationOutcome = {
  collections: number
  rotated: number
  failed: number
  revokedIds: string[]
}

/**
 * The activity history as {@link StorageManager.listHistoryItems} lists it:
 * one entry per `wallet-activity` Resource, keyed by its resource id, plus
 * the count of `wallet-activity` Resources that read skipped for any reason.
 */
export type HistoryItems = {
  entries: Array<{ id: string; doc: WalletActivity }>
  unreadable: number
}

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
 * Whether a descriptor strands this reader: it carries key epochs, and no
 * recipient entry in any of them names the reader's key-agreement key. That
 * is what a user key rotation torn mid-fan-out leaves on a collection it had
 * not reached yet. A reader named in some epoch is not stranded, even when
 * its entry there fails to unwrap.
 *
 * @param options {object}
 * @param options.descriptor {CollectionEncryption}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the reader's own KAK
 * @returns {boolean}
 */
function strandsReader({
  descriptor,
  keyAgreementKey
}: {
  descriptor: CollectionEncryption
  keyAgreementKey: IKeyAgreementKey
}): boolean {
  const epochs = descriptor.epochs ?? []
  return (
    epochs.length > 0 &&
    !epochs.some(epoch =>
      epoch.recipients.some(
        recipient => recipient.header.kid === keyAgreementKey.id
      )
    )
  )
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
 * @param options.id {string}   the resource id the envelope was read under,
 *   which the decrypt verifies the stored body against
 * @param options.envelope {Json}
 * @param options.source {string}   how the failure names the collection, e.g.
 *   `collection "private-credentials"`
 * @returns {Promise<{ value: Json | undefined, unknownEpoch: boolean }>}
 */
async function decryptEnvelope({
  cipher,
  id,
  envelope,
  source
}: {
  cipher: DocCipher
  id: string
  envelope: Json
  source: string
}): Promise<{ value: Json | undefined; unknownEpoch: boolean }> {
  try {
    return {
      // Every synced collection stores JSON, which decrypts to JSON. A binary
      // or text payload decrypts to a `Blob`, and no synced Resource is
      // sealed from one.
      value: (await cipher.decrypt({ id, envelope })) as Json,
      unknownEpoch: false
    }
  } catch (err) {
    return decryptFailure({ err, source })
  }
}

/**
 * The `{ value, unknownEpoch }` result of a failed decrypt, as
 * {@link decryptEnvelope} states it: an `UnknownEpochError` is the refresh
 * signal, and every other failure is logged and yields no value.
 *
 * @param options {object}
 * @param options.err {unknown}   what the decrypt threw
 * @param options.source {string}   how the log names the collection
 * @returns {{ value: undefined, unknownEpoch: boolean }}
 */
function decryptFailure({ err, source }: { err: unknown; source: string }): {
  value: undefined
  unknownEpoch: boolean
} {
  const failure = classifyDecryptFailure(err)
  if (failure === 'unknown-epoch') {
    return { value: undefined, unknownEpoch: true }
  }
  if (failure === 'no-epoch-key') {
    log.warn('This wallet is not a recipient of the key epoch of a resource', {
      source,
      err
    })
    return { value: undefined, unknownEpoch: false }
  }
  if (failure === 'integrity') {
    // The host served a body that does not verify against the id it was read
    // under. No refresh can help, and the read yields nothing rather than
    // another resource's content.
    log.warn('Refusing a resource whose body failed its integrity check', {
      source,
      err
    })
    return { value: undefined, unknownEpoch: false }
  }
  log.warn('Could not decrypt resource envelope', { source, err })
  return { value: undefined, unknownEpoch: false }
}

/**
 * Decrypts one held envelope of an encrypted app collection for the content
 * migration's snapshot, without reading a chunk. The decrypt is handed a
 * chunk source that holds nothing, so a complete chunked Resource throws
 * `NotFoundError` at its first chunk and is reported as a bytes Resource. A
 * small binary or text Resource decrypts to a `Blob` and is reported the same
 * way. Neither is reassembled or read. Every other failure is stated as
 * {@link decryptFailure} states it.
 *
 * @param options {object}
 * @param options.cipher {EdvDocCipher}
 * @param options.id {string}   the resource id the envelope was read under
 * @param options.envelope {Json}
 * @param options.source {string}   how a failure names the collection
 * @returns {Promise<{ value: Json | undefined; bytes: boolean; unknownEpoch: boolean }>}
 */
async function decryptHeldAppResource({
  cipher,
  id,
  envelope,
  source
}: {
  cipher: EdvDocCipher
  id: string
  envelope: Json
  source: string
}): Promise<{
  value: Json | undefined
  bytes: boolean
  unknownEpoch: boolean
}> {
  try {
    const value = await cipher.decrypt({
      id,
      envelope,
      chunkSource: async () => undefined
    })
    if (value instanceof Blob) {
      return { value: undefined, bytes: true, unknownEpoch: false }
    }
    return { value: value as Json, bytes: false, unknownEpoch: false }
  } catch (err) {
    if (errorNameOf(err) === 'NotFoundError') {
      return { value: undefined, bytes: true, unknownEpoch: false }
    }
    return { ...decryptFailure({ err, source }), bytes: false }
  }
}

/**
 * A standing app collection's metadata as the content migration checks it:
 * its `encryption` member, its `custom` value, and its attribution.
 */
type StandingAppCollection = NonNullable<
  Awaited<ReturnType<WASRemoteStore['collectionMetadata']>>
>

/**
 * The refusal message for an app collection encrypted under a client-written
 * descriptor, which no governing log can take over.
 *
 * @param collectionId {string}
 * @returns {string}
 */
function clientWrittenDescriptorMessage(collectionId: string): string {
  return (
    `The collection "${collectionId}" is encrypted under a descriptor no ` +
    'governing log owns, so an archived collection cannot be imported into it.'
  )
}

/**
 * An encrypted app collection Resource's identity, as the content migration
 * dedupes on it. A JSON Resource is identified by its payload's own string `id`
 * (was-react's Resources carry one), or else by the payload's content cid. A
 * bytes Resource (one that decrypts to a `Blob`, chunked or not) is identified
 * by its resource id. The three kinds are prefixed apart, so no value of one
 * kind can match another.
 *
 * @param resource {{ json: Json; cid: string } | { resourceId: string }}   the
 *   decrypted JSON payload with its content cid, or a bytes Resource's id
 * @returns {string}
 */
function appResourceIdentity(
  resource: { json: Json; cid: string } | { resourceId: string }
): string {
  if ('resourceId' in resource) {
    return `resource:${resource.resourceId}`
  }
  const { json, cid } = resource
  const id =
    typeof json === 'object' && json !== null && !Array.isArray(json)
      ? (json as Record<string, unknown>).id
      : undefined
  return typeof id === 'string' ? `id:${id}` : `cid:${cid}`
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
 * configured). Every encrypted collection still carries a key-epoch roster from
 * birth, so each collection gets a local one-epoch descriptor wrapped to the
 * session's vault KAK alone -- minted on first use and persisted in the
 * session's descriptor cache, scoped by the user's DID in place of a Space id,
 * so a returning local login rebuilds the same epoch and keeps decrypting its
 * own resource replicas. A guest's identity is random per session and its data
 * dies with it, so a guest's persistence strategy supplies an in-memory cache
 * and its descriptors die with the session.
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
 * Thrown when the content migration meets an app collection the account
 * already holds in a different shape than the archived one: encrypted where
 * the archive is plaintext or the reverse, encrypted under a client-written
 * descriptor no log governs, public where a plaintext archive is private or
 * the reverse, or empty with no marker that it was made plaintext. The
 * standing collection is left as it is, and its Resources are not imported. See
 * {@link StorageManager.ensureImportedAppCollection}.
 */
export class AppCollectionMismatchError extends Error {
  collectionId: string

  constructor({
    collectionId,
    message,
    cause
  }: {
    collectionId: string
    message: string
    cause?: unknown
  }) {
    super(message, { cause })
    this.name = 'AppCollectionMismatchError'
    this.collectionId = collectionId
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
  // The WAS ids of the encrypted collections whose current cipher refuses
  // because no key epoch names the vault KAK (see `strandsReader`). Rewritten
  // at every cipher (re)build, so it always describes the installed ciphers.
  #strandedCollectionIds: string[]
  // Told, fire-and-forget and with no argument, whenever a cipher rebuild
  // records a stranded collection. Set by the session binding after
  // construction (see `setOnStranded`), since the static factory runs before
  // the session exists.
  #onStranded?: () => unknown
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
  #vaultKeys: {
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
  // The kids of the account's user key generations, read from the verified
  // head of the user key roster log, oldest first. Resolved lazily from the
  // session layer, and only when a rotation meets a roster entry no recorded
  // admission names. Resolves an empty list when the session supplies none.
  #userKeyGenerationKids: () => Promise<string[]>
  // The once-per-collection-per-session unknown-epoch refresh guard, shared by
  // the standard and the app-provisioned encrypted collections, so a genuinely
  // foreign envelope cannot drive a refresh loop. Its `reset` re-arms a
  // collection whenever a share / unshare / recipient rotation installs a
  // fresh descriptor.
  #refreshPolicy = new DescriptorRefreshPolicy({
    refresh: async ({ collectionId }) => {
      if (ENCRYPTED_COLLECTION_IDS.includes(collectionId)) {
        await this.#refreshDescriptors({ refuseStranded: true })
      } else {
        // An app-provisioned collection: drop the cached descriptor and cipher so
        // the re-read rebuilds them from a fresh Description fetch.
        delete this.#appDescriptors[collectionId]
        delete this.#appCiphers[collectionId]
        this.#importCiphers.delete(collectionId)
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
  // The encrypted app collections the content migration has ensured this
  // session, by WAS collection id. A Set, since the ids come from a bundle.
  #importCollections = new Set<string>()
  // The ciphers the content migration reads and writes those collections'
  // Resources through, keyed by WAS collection id, each beside the verified
  // descriptor it was built from. Each carries the collection's index schema
  // as it stands, so its writes carry the blinded index entries. An
  // unknown-epoch refresh drops the entry, and the next use rebuilds it from
  // the verified descriptor. A write rebuilds it too, when the collection's
  // current epoch has moved since the build.
  #importCiphers = new Map<
    string,
    { cipher: EdvDocCipher; descriptor: CollectionEncryption }
  >()
  // The session's typed persistence strategy: the writer id and the cache
  // pair come from it, so their storage tier is the strategy's rather than a
  // flag here.
  #persistence: SessionPersistence

  constructor({
    localStore,
    remoteStore,
    ciphers,
    strandedCollectionIds,
    remoteDirect = false,
    vaultKeys,
    descriptors,
    metas,
    persistence,
    descriptorLogs,
    signerCheck,
    userKeyGenerationKids
  }: {
    localStore?: BrowserStore
    remoteStore?: WASRemoteStore
    ciphers?: Record<string, DocCipher>
    strandedCollectionIds?: string[]
    remoteDirect?: boolean
    vaultKeys: {
      keyAgreementKey: IKeyAgreementKey
      keyResolver: IKeyResolver
    }
    descriptors?: Record<string, CollectionEncryption>
    metas?: Record<string, { custom?: unknown }>
    persistence: SessionPersistence
    descriptorLogs?: DescriptorLogs | (() => DescriptorLogs | undefined)
    signerCheck?: () => Promise<AccountSignerCheck | undefined>
    userKeyGenerationKids?: () => Promise<string[]>
  }) {
    this.#localStore = localStore
    this.#remoteStore = remoteStore
    this.#ciphers = ciphers
    this.#strandedCollectionIds = strandedCollectionIds ?? []
    this.#vaultKeys = vaultKeys
    this.#descriptors = descriptors ?? {}
    this.#metas = metas ?? {}
    this.#persistence = persistence
    this.#descriptorLogsFor =
      typeof descriptorLogs === 'function'
        ? descriptorLogs
        : () => descriptorLogs
    this.#signerCheckFor = signerCheck ?? (async () => undefined)
    this.#userKeyGenerationKids = userKeyGenerationKids ?? (async () => [])
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
   * The WAS ids of the encrypted collections whose installed cipher refuses
   * because no key epoch names the current user key: collections a torn user
   * key rotation left on a retired generation. The login's collection fan-out
   * reads it to decide whether the ciphers need a rebuild once it has run.
   *
   * @returns {string[]}
   */
  get strandedCollectionIds(): string[] {
    return [...this.#strandedCollectionIds]
  }

  /**
   * Sets, replaces, or clears the callback a cipher rebuild calls when it
   * records a stranded collection. The call is fire-and-forget, takes no
   * argument, and runs after the rebuild has installed its ciphers; a
   * callback reads {@link strandedCollectionIds} for the candidates. A
   * throwing or rejecting callback is logged and does not reach the rebuild.
   *
   * Strands recorded before a callback is set are not replayed here: the
   * static factory builds the first ciphers before any session exists. The
   * binding that sets the callback reads {@link strandedCollectionIds} to
   * learn of them.
   *
   * @param callback {Function | undefined}   `() => unknown`, or `undefined`
   *   to clear it
   * @returns {void}
   */
  setOnStranded(callback: (() => unknown) | undefined): void {
    this.#onStranded = callback
  }

  /**
   * Tells the stranded callback, when one is set, that a rebuild just
   * recorded a stranded collection. Deferred to a microtask so the callback
   * never runs inside the rebuild that reported it.
   *
   * @returns {void}
   */
  #reportStranded(): void {
    const callback = this.#onStranded
    if (!callback) {
      return
    }
    void Promise.resolve()
      .then(() => callback())
      .catch((err: unknown) => {
        log.warn('The stranded-collection callback failed', { err })
      })
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
   * Whether this session can create an app collection: it needs remote
   * storage, and for an encrypted one the descriptor logs of a promoted
   * account to write the collection's governing log through. A guest and a
   * no-WAS session have neither.
   */
  get canProvisionAppCollections(): boolean {
    return !!this.#remoteStore && this.#descriptorLogsFor() !== undefined
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
   * @param options.refuseStranded {boolean}   see
   *   {@link StorageManager.#buildCipher}
   * @returns {Promise<{ ciphers: Record<string, DocCipher>,
   *   strandedCollectionIds: string[] }>}   the cipher map, keyed by logical
   *   key, and the WAS ids of the collections given a stranded refusing cipher
   */
  static async #buildCiphers({
    keyAgreementKey,
    keyResolver,
    descriptors,
    metas,
    refresh,
    refuseStranded
  }: {
    keyAgreementKey: IKeyAgreementKey
    keyResolver: IKeyResolver
    descriptors?: Record<string, CollectionEncryption>
    metas?: Record<string, { custom?: unknown }>
    refresh?: {
      source?: EncryptionDescriptorSource
      cache: EncryptionDescriptorCache
    }
    refuseStranded: boolean
  }): Promise<{
    ciphers: Record<string, DocCipher>
    strandedCollectionIds: string[]
  }> {
    const built = await Promise.all(
      ENCRYPTED_STANDARD_COLLECTIONS.map(collection =>
        StorageManager.#buildCipher({
          collection,
          keyAgreementKey,
          keyResolver,
          descriptor: descriptors?.[collection.id],
          meta: metas?.[collection.id],
          refresh,
          refuseStranded
        })
      )
    )
    return {
      ciphers: Object.fromEntries(
        built.map(({ key, cipher }) => [key, cipher])
      ),
      strandedCollectionIds: ENCRYPTED_STANDARD_COLLECTIONS.filter(
        (_collection, index) => built[index].stranded
      ).map(({ id }) => id)
    }
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
   * @param options.refuseStranded {boolean}   true gives a collection whose
   *   epochs name no vault KAK (see `strandsReader`) a refusing cipher; false
   *   lets its build throw `KeyUnwrapError`, as the post-rotation adoption
   *   needs
   * @returns {Promise<{ key: string, cipher: DocCipher, stranded: boolean }>}
   */
  static async #buildCipher({
    collection: { key, id, idDerivation },
    keyAgreementKey,
    keyResolver,
    descriptor,
    meta,
    refresh,
    refuseStranded
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
    refuseStranded: boolean
  }): Promise<{ key: string; cipher: DocCipher; stranded: boolean }> {
    // Every encrypted collection carries its key epochs from
    // provisioning, so a missing (or epoch-less) descriptor -- an
    // unprovisioned or torn collection, or an offline session with
    // nothing cached -- gets a fail-closed cipher rather than none: an
    // absent cipher would fall through to the store's cipher-less
    // plaintext path, silently storing (and pushing) plaintext into an
    // encrypted collection, and an epoch-less descriptor would make the
    // whole rebuild throw, taking the healthy collections down with it.
    if (!descriptor?.epochs?.length) {
      return {
        key,
        cipher: StorageManager.#refusingCipher({ collectionId: id }),
        stranded: false
      }
    }
    if (refuseStranded && strandsReader({ descriptor, keyAgreementKey })) {
      // No epoch names the current user key: a user key rotation torn
      // mid-fan-out left this collection on a retired generation. It gets a
      // refusing cipher rather than one built from the retired key, so this
      // session writes nothing under an epoch the retired party can open,
      // and the rest of the session is built. The login's collection
      // fan-out re-epochs it and the descriptor refresh behind that rebuilds
      // this cipher.
      log.warn(
        'No key epoch of this collection names the current user key; ' +
          'refusing its reads and writes until the collection is re-epoched',
        { collectionId: id }
      )
      return {
        key,
        cipher: StorageManager.#refusingCipher({
          collectionId: id,
          reason: 'stranded'
        }),
        stranded: true
      }
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
      return { key, cipher, stranded: false }
    }
    const cipher = await createEdvDocCipher({
      keyAgreementKey,
      keyResolver,
      collectionId: id,
      // The collection spec's id mint ('random' for the mutable
      // contacts head, 'content' for the content-addressed
      // collections), so a minted id follows the spec and can key
      // the Resource.
      idDerivation,
      encryption: descriptor
    })
    await StorageManager.#installIndexSchema({
      cipher,
      collectionId: id,
      meta
    })
    return { key, cipher, stranded: false }
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
   * encrypted collection whose descriptor could not be acquired, or whose
   * epochs name no current user key generation (`stranded`). The refusal clears
   * when a descriptor refresh rebuilds the ciphers. A stranded refusal is a
   * `KeyUnwrapError`, so a list read skips the collection's Resources as
   * not-a-recipient rather than collecting them for the undecryptable purge,
   * which would delete them from the server.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param [options.reason] {'stranded'}   omitted for a missing descriptor
   * @returns {DocCipher}
   */
  static #refusingCipher({
    collectionId,
    reason
  }: {
    collectionId: string
    reason?: 'stranded'
  }): DocCipher {
    const refuse = (): never => {
      if (reason === 'stranded') {
        throw new KeyUnwrapError(
          `Collection "${collectionId}" has no key epoch naming the ` +
            'current user key; refusing to read or write until it is ' +
            're-epoched onto it.'
        )
      }
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
   * vault keys, then swaps them into the local store (and this facade).
   *
   * @param options {object}
   * @param options.refuseStranded {boolean}   see
   *   {@link StorageManager.#buildCipher}
   * @returns {Promise<void>}
   */
  async #rebuildCiphers({
    refuseStranded
  }: {
    refuseStranded: boolean
  }): Promise<void> {
    const { ciphers, strandedCollectionIds } =
      await StorageManager.#buildCiphers({
        keyAgreementKey: this.#vaultKeys.keyAgreementKey,
        keyResolver: this.#vaultKeys.keyResolver,
        descriptors: this.#descriptors,
        metas: this.#metas,
        refresh: this.#cipherRefresh(),
        refuseStranded
      })
    this.#ciphers = ciphers
    this.#strandedCollectionIds = strandedCollectionIds
    // Swap into the active backend (the local store in the normal case, the
    // remote-direct backend in the popup); both honor `setCiphers` for the
    // descriptor-refresh path.
    this.#store.setCiphers(ciphers)
    if (strandedCollectionIds.length > 0) {
      this.#reportStranded()
    }
  }

  /**
   * Rebuilds ONE standard encrypted collection's cipher from its current
   * descriptor and swaps the refreshed map into the backend -- what a share
   * or an unshare needs, each of which rotates a single collection. The
   * whole-map rebuild above stays the descriptor-refresh path's, which moves
   * every collection at once. A collection id that is not a standard
   * encrypted collection (an app-provisioned one, whose cipher is built
   * lazily per read) is a no-op.
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
    const collection = ENCRYPTED_STANDARD_COLLECTIONS.find(
      ({ id }) => id === collectionId
    )
    if (!collection) {
      return
    }
    const { key, cipher, stranded } = await StorageManager.#buildCipher({
      collection,
      keyAgreementKey: this.#vaultKeys.keyAgreementKey,
      keyResolver: this.#vaultKeys.keyResolver,
      descriptor: this.#descriptors[collectionId],
      meta: this.#metas[collectionId],
      refresh: this.#cipherRefresh(),
      refuseStranded: true
    })
    this.#ciphers = { ...this.#ciphers, [key]: cipher }
    this.#strandedCollectionIds = [
      ...this.#strandedCollectionIds.filter(id => id !== collectionId),
      ...(stranded ? [collectionId] : [])
    ]
    this.#store.setCiphers(this.#ciphers)
    if (stranded) {
      this.#reportStranded()
    }
  }

  /**
   * Refreshes every encrypted collection's descriptor -- and its stored
   * `/meta`, so an index schema declared mid-session reaches the rebuilt
   * ciphers -- from the remote store, caches them, and rebuilds + swaps the
   * ciphers. Called when a local read reports unknown-epoch resource replicas
   * -- a rekey emits no change-feed entry, so the local cipher may be built
   * from a stale descriptor. No-op without a remote store.
   *
   * @param options {object}
   * @param options.refuseStranded {boolean}   see
   *   {@link StorageManager.#buildCipher}
   * @returns {Promise<void>}
   */
  async #refreshDescriptors({
    refuseStranded
  }: {
    refuseStranded: boolean
  }): Promise<void> {
    if (!this.#remoteStore || !this.#descriptorCache) {
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
    await this.#rebuildCiphers({ refuseStranded })
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
   * {@link holdRotatedVaultKeys} instead. A collection the fan-out did not
   * reach throws `KeyUnwrapError` here rather than getting a refusing
   * cipher, so the caller learns the adoption did not land.
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
    await this.#refreshEncrypted({ refuseStranded: false })
  }

  /**
   * Refetches every encrypted collection's descriptor and rebuilds + swaps
   * the ciphers under the vault keys already held -- the tail of the
   * cascade-completion sweep, which can move a collection's current epoch
   * (completing a cascade another client crashed partway through) AFTER this
   * session's ciphers were built at login: without the refresh, every later
   * write would stay sealed under the retired epoch the revoked party can
   * still decrypt. The app-collection cipher caches are dropped too and
   * rebuild lazily on next decrypt. A collection still stranded (see
   * {@link strandedCollectionIds}) keeps a refusing cipher.
   *
   * @returns {Promise<void>}
   */
  async refreshEncryptedDescriptors(): Promise<void> {
    await this.#refreshEncrypted({ refuseStranded: true })
  }

  /**
   * The shared body of {@link refreshEncryptedDescriptors} and
   * {@link adoptRotatedVaultKeys}, which differ only in how a stranded
   * collection is treated.
   *
   * @param options {object}
   * @param options.refuseStranded {boolean}   see
   *   {@link StorageManager.#buildCipher}
   * @returns {Promise<void>}
   */
  async #refreshEncrypted({
    refuseStranded
  }: {
    refuseStranded: boolean
  }): Promise<void> {
    this.#appCiphers = {}
    this.#appDescriptors = {}
    this.#importCiphers.clear()
    if (this.#remoteStore && this.#descriptorCache) {
      await this.#refreshDescriptors({ refuseStranded })
    } else {
      await this.#rebuildCiphers({ refuseStranded })
    }
    this.#refreshPolicy.reset()
  }

  /**
   * Runs a read that reports whether it skipped unknown-epoch Resources; on the
   * first such report for a collection this session, refreshes the descriptor
   * (rebuilding + swapping the ciphers) and re-reads once, via the shared
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
    // A refresh needs a remote store; without one, serve the single read
    // as-is (and leave the policy's guard unspent).
    if (!this.#remoteStore) {
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
    signerCheck,
    userKeyGenerationKids
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
    // The kids of the account's user key generations, read from the verified
    // user key roster, resolved lazily from the session layer like
    // `signerCheck`; absent, a rotation keeps no earlier generation.
    userKeyGenerationKids?: () => Promise<string[]>
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
    const { ciphers, strandedCollectionIds } =
      await StorageManager.#buildCiphers({
        keyAgreementKey,
        keyResolver,
        descriptors,
        metas,
        // A collection a torn rotation left behind gets a refusing cipher, so
        // the session is built and the login's fan-out can re-epoch it.
        refuseStranded: true,
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
      strandedCollectionIds,
      remoteDirect,
      vaultKeys: { keyAgreementKey, keyResolver },
      descriptors,
      metas,
      persistence,
      descriptorLogs: descriptorLogsFor,
      signerCheck,
      userKeyGenerationKids
    })
    return { storage, userExists }
  }

  /**
   * Stores a credential and, when a Resource was actually inserted (a re-add of
   * a stored credential is a no-op), records its Create history entry. Routes
   * to the active backend (the local active replica, or the remote-direct popup
   * backend).
   *
   * This is the single entry point every credential coming from outside the
   * wallet goes through (the CHAPI store popup, the URL / QR / manual-paste
   * import, and the credentials half of a space import), so it is where a
   * credential presenting as an app key is refused outright, whether or not
   * it binds to its own seed: app keys are wallet-minted, never imported, and
   * the mint path has its own store method ({@link addMintedAppKey}). The
   * background sync pull
   * (the driver in `@interop/was-sync`) stores pulled Resources as resource
   * replicas in the local replica without
   * passing through here, deliberately: it replicates the account's own
   * remote collections, which only the account's enrolled wallet clients can
   * write (`private-credentials` is a protected collection -- RP and share
   * grants on it are read-only), and each of those clients enforces this same
   * refusal at its own entry point; the pulled bodies are also EDV envelopes the
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
   * The mint path's own store method: saves an app-key credential the wallet
   * itself just minted (`processAppConnect`), which {@link addCredential}
   * would refuse -- external ingest never stores a marker credential, so the
   * one legitimate producer gets its own entry point instead of a bypass flag
   * on the shared one. Still asserts the mint invariants (`assertMintedAppKey`
   * in `@interop/wallet-request`: marker present, subject DID derived
   * from the carried seed) so this method cannot be misused to store a foreign
   * app key either.
   *
   * The app key lands in the dedicated `app-connections` collection, never in
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
   *   unknownEpoch: number; noEpochKey: number; undecryptable: number;
   *   integrity: number } }>}
   */
  async listAppKeys(): Promise<{
    appKeys: StoredCredential[]
    skipped: {
      unknownEpoch: number
      noEpochKey: number
      undecryptable: number
      integrity: number
    }
  }> {
    // Unknown-epoch Resources mean the cipher may be built from a stale
    // descriptor (a rekey emits no change-feed entry); refresh the descriptor once and
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
          undecryptable: this.#store.undecryptableAppKeys,
          integrity: this.#store.integrityAppKeys
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
   * The write half both credential store methods share: the content-cid
   * derivation and the idempotent insert into `private-credentials`. Each
   * caller screens app keys its own way before reaching here:
   * {@link addCredential} refuses, {@link importCredential} skips.
   *
   * @param options {object}
   * @param options.credential {IVerifiableCredential}
   * @returns {Promise<{ cid: string; inserted: boolean }>}   `inserted` is
   *   false when the cid was already held
   */
  async #storeCredential({
    credential
  }: {
    credential: IVerifiableCredential
  }): Promise<{ cid: string; inserted: boolean }> {
    // The credential's content cid is its page-facing identity (idempotence,
    // routes, history); the backend encrypts the VC into an EDV envelope keyed
    // by a content-derived envelope-hash id.
    const cid = await cidFrom({ doc: credential })
    const inserted = await this.#store.addCredential({ cid, credential })
    return { cid, inserted }
  }

  /**
   * The store step behind {@link addCredential}: the shared write half, plus
   * the best-effort Create history entry an interactive add always records.
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
    const { cid, inserted } = await this.#storeCredential({ credential })
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
    // Unknown-epoch Resources mean the cipher may be built from a stale
    // descriptor (a rekey emits no change-feed entry); the shared helper
    // refreshes the descriptor once and re-reads, uniformly for both backends.
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
   * With `consultRemote`, the remote collection is consulted first whenever one
   * is configured and this session carries the local replica. The local
   * `public-credentials` replica cannot prove the ABSENCE of a remote copy: a
   * freshly enrolled browser, or one whose `public-credentials` replication
   * sits in retry backoff, has not pulled the copy yet, and deciding retraction
   * on the local resource replicas alone would let the world-readable copy
   * stand with no handle left to retract it. A remote that cannot be reached
   * then refuses. Without the option the decision is the local replica's, the
   * interactive delete's offline-tolerant behaviour. (In the replica-less
   * remote-direct variant the store's own `hasPublicCredential` /
   * `removePublicCredential` already go straight to the remote either way.)
   *
   * The local resource replica is then removed as before. Its replication push
   * is a tombstone against a resource this call has already deleted remotely,
   * which the push path tolerates: a `DELETE` of an absent resource is the
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
   * resource replicas in the local `public-credentials` replica, unioned by
   * cid with the remote collection's resources when a remote store is
   * configured and this session carries the replica. The collection is
   * plaintext and keyed by the credential's content cid, so a resource id IS
   * its cid.
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
   * The count of local `private-credentials` resource replicas the most recent
   * {@link listCredentials} read had to skip because their envelope would not
   * decrypt under the current vault KAK (corrupted, or written under a
   * mismatched KAK). Surfaced so the dashboard can warn the user without one
   * bad resource replica bricking the list.
   *
   * @returns {number}
   */
  get undecryptableCredentials(): number {
    return this.#store.undecryptableCredentials
  }

  /**
   * The count of `private-credentials` Resources the most recent
   * {@link listCredentials} read had to skip because their body failed its
   * integrity check: the envelope did not authenticate, or the host served it
   * under an id it was not sealed for. Surfaced on the dashboard separately
   * from {@link undecryptableCredentials}, and never purgeable -- producing
   * such a Resource takes no keys, so removing it would let a host present
   * recoverable data as garbage and have the wallet destroy it.
   *
   * @returns {number}
   */
  get integrityCredentials(): number {
    return this.#store.integrityCredentials
  }

  /**
   * Removes the local `private-credentials` resource replicas that could not
   * be decrypted, so the user can clear what can never be shown. Returns the
   * number of resource replicas removed.
   *
   * @returns {Promise<number>}
   */
  async purgeUndecryptableCredentials(): Promise<number> {
    return await this.#store.purgeUndecryptableCredentials()
  }

  /**
   * The count of `app-connections` Resources the most recent
   * {@link listAppKeys} read had to skip because their envelope would not
   * decrypt at all.
   * Surfaced on the Applications page beside its purge action.
   *
   * @returns {number}
   */
  get undecryptableAppKeys(): number {
    return this.#store.undecryptableAppKeys
  }

  /**
   * The count of `app-connections` Resources the most recent
   * {@link listAppKeys} read had to skip because their body failed its
   * integrity check. Never
   * purged, and load-bearing on the match path: a skipped app key read as
   * absent would mint a second identity for the app.
   *
   * @returns {number}
   */
  get integrityAppKeys(): number {
    return this.#store.integrityAppKeys
  }

  /**
   * The count of `app-connections` Resources the most recent
   * {@link listAppKeys} read had to skip because this wallet holds no key for
   * their (known) key epoch. Never purged: the Resource is an app's real
   * identity, readable again once the collection's epochs wrap a key this
   * session holds.
   *
   * @returns {number}
   */
  get noEpochKeyAppKeys(): number {
    return this.#store.noEpochKeyAppKeys
  }

  /**
   * Removes the `app-connections` Resources that could not be decrypted at
   * all. Returns the number of Resources removed.
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
    // Export needs no authority a transient session lacks; the gate is the
    // remote store alone, so a session with one exports whatever its
    // capability reaches.
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

  /**
   * One collection's app attribution off its Collection Metadata object:
   * `generator`, the application it was provisioned for (its did:key, and
   * the Web origin and canonical app URL that DID was bound to). Beside it,
   * `encrypted` says whether the same object carries an `encryption`
   * descriptor. One signed read per call; the lean listing above carries none
   * of the three. Resolves `undefined` without a remote store, and for a
   * collection that is missing or not visible. Network errors throw through.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @returns {Promise<{ generator?: CollectionGenerator, encrypted: boolean }
   *   | undefined>}
   */
  async collectionAttribution({
    collectionId
  }: {
    collectionId: string
  }): Promise<
    { generator?: CollectionGenerator; encrypted: boolean } | undefined
  > {
    const metadata = await this.#remoteStore?.collectionMetadata({
      collectionId
    })
    if (!metadata) {
      return undefined
    }
    const { generator, encryption } = metadata
    return { generator, encrypted: Boolean(encryption) }
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
   * @param options.resourceId {string}   the id the resource was fetched
   *   under, which the decrypt verifies the stored envelope against
   * @param options.data {Json}   the fetched JSON resource body
   * @returns {Promise<Json | undefined>}
   */
  async decryptCollectionResource({
    collectionId,
    resourceId,
    data
  }: {
    collectionId: string
    resourceId: string
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
      return this.#decryptAppCollectionResource({
        collectionId,
        resourceId,
        data
      })
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
          id: resourceId,
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
   * Returns undefined on any failure (no remote store / no epoch descriptor /
   * a decrypt error), letting the caller show the raw envelope.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id
   * @param options.resourceId {string}   the id the resource was fetched under
   * @param options.data {Json}   the fetched EDV envelope
   * @returns {Promise<Json | undefined>}
   */
  async #decryptAppCollectionResource({
    collectionId,
    resourceId,
    data
  }: {
    collectionId: string
    resourceId: string
    data: Json
  }): Promise<Json | undefined> {
    const remote = this.#remoteStore
    if (!remote) {
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
          id: resourceId,
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
   * `generator` is the collection's app attribution, stamped on the create (see {@link WASRemoteStore.ensureCollection}).
   *
   * @param options {object}
   * @param options.id {string}
   * @param [options.name] {string}
   * @param [options.isPublic] {boolean}
   * @param [options.generator] {CollectionGenerator}   the application this
   *   collection is provisioned for
   * @returns {Promise<void>}
   */
  async ensureCollection({
    id,
    name,
    isPublic,
    generator
  }: {
    id: string
    name?: string
    isPublic?: boolean
    generator?: CollectionGenerator
  }): Promise<void> {
    await this.#requireRemote('Provisioning a collection').ensureCollection({
      id,
      name,
      isPublic,
      generator
    })
  }

  async deleteCollection({ id }: { id: string }): Promise<void> {
    await this.#requireRemote('Deleting a collection').deleteCollection({ id })
  }

  /**
   * Provisions a grantee's PRIVATE collection as a multi-recipient EDV
   * collection: the user's vault KAK is always recipient zero (policy -- the
   * user is a recipient of every encrypted collection in their own Space)
   * alongside the grantee's identity key-agreement key. The grantee is an App
   * Connect app, an agent, or any other `did:key` a standalone
   * `#private-collection` grant names. The collection is ensured to exist and
   * declared `'edv'` without clobbering an existing descriptor, then
   * `ensureIndexedFirstEpoch` installs epoch[0] wrapped to the owner alone,
   * together with the collection's blinded-index HMAC key -- create-if-absent,
   * adopting a roster an earlier provision landed, so every provisioned
   * collection carries its key epochs from birth (the first-epoch mint runs
   * only here, at provisioning). A collection whose roster predates the
   * blinded index is adopted as it stands, without an HMAC key. The grantee is
   * then always escrowed in by `addRecipient` (into every epoch, and into the
   * HMAC key's wrap set -- adds are cheap) unless the current epoch already
   * wraps to it (a re-grant with no intervening revoke: a no-op). With no
   * grantee, the provision is owner-only: the content migration re-creates an
   * app collection this way, and the app is admitted when it reconnects.
   *
   * The grantee never needs the vault KAK and the wallet never needs the
   * grantee's secret at all (the recipient is derived from the grantee's
   * controller DID, and the roster kid is in the descriptor), so this is the
   * only step that pairs the two recipients. Requires a remote store.
   *
   * A collection that already stands without an encryption descriptor and
   * holds resources is refused with a plain `Error` before anything is
   * written. It is never converted in place.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id to provision
   * @param [options.recipient] {RecipientPublicKey}   the grantee's identity
   *   public key-agreement key, the X25519 twin of its controller `did:key`
   *   (its `id` is the recipient `kid`); omitted for an owner-only provision,
   *   which ends at the first epoch
   * @param [options.generator] {CollectionGenerator}   the application this
   *   collection is provisioned for, stamped as the collection's attribution
   * @returns {Promise<CollectionEncryption>}   the current descriptor
   */
  async provisionEncryptedCollection({
    collectionId,
    recipient,
    generator
  }: {
    collectionId: string
    recipient?: RecipientPublicKey
    generator?: CollectionGenerator
  }): Promise<CollectionEncryption> {
    const remote = this.#requireRemote('Provisioning an encrypted collection')
    await this.#refuseStandingPlaintextCollection({ remote, collectionId })
    // Ensure the collection exists (a bare create; the server derives its
    // `encryption` member from the governing log), then install epoch[0].
    await remote.ensureGovernedCollection({
      id: collectionId,
      generator
    })
    return await this.#installFirstEpoch({ collectionId, recipient })
  }

  /**
   * The second half of {@link provisionEncryptedCollection}, over a
   * collection already ensured: installs epoch[0] (owner as recipient zero)
   * as the governing log's genesis, then escrows the grantee when one is
   * given. The genesis is create-if-absent, so an existing roster is
   * adopted as it stands.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param [options.recipient] {RecipientPublicKey}   the grantee's identity
   *   public key-agreement key; omitted for an owner-only provision
   * @returns {Promise<CollectionEncryption>}   the current descriptor
   */
  async #installFirstEpoch({
    collectionId,
    recipient
  }: {
    collectionId: string
    recipient?: RecipientPublicKey
  }): Promise<CollectionEncryption> {
    const { keyAgreementKey } = this.#vaultKeys
    const store = await this.#collectionStore({
      collectionId,
      action: 'Provisioning an encrypted collection'
    })
    const { descriptor: current } = await ensureIndexedFirstEpoch({
      store,
      recipients: [ownerRecipient({ keyAgreementKey })]
    })

    if (
      recipient === undefined ||
      currentEpochRecipientKids({ descriptor: current }).includes(recipient.id)
    ) {
      // No grantee (an owner-only provision), or the grantee already reads the
      // current epoch: nothing to do.
      return current
    }
    // First grant, or a re-grant after a revoke rotated the epoch off the
    // grantee: escrow it into every epoch (adds are cheap -- no rotation).
    const descriptor = await addRecipient({
      store,
      recipient,
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
   * Refuses to provision over a collection that already stands without an
   * `encryption` descriptor and holds resources. Declaring such a collection
   * encrypted would mint epoch[0] over its plaintext Resources, and no reader
   * could open them afterward. Provisioning never converts a collection.
   *
   * A standing collection with no descriptor and no resources is let
   * through. That is the state a provision torn between the collection
   * create and the first epoch leaves behind, and finishing it makes no Resource
   * unreadable.
   *
   * @param options {object}
   * @param options.remote {WASRemoteStore}
   * @param options.collectionId {string}
   * @returns {Promise<void>}
   */
  async #refuseStandingPlaintextCollection({
    remote,
    collectionId
  }: {
    remote: WASRemoteStore
    collectionId: string
  }): Promise<void> {
    const metadata = await remote.collectionMetadata({ collectionId })
    if (!metadata || metadata.encryption !== undefined) {
      return
    }
    const listing = await remote.collectionHandle({ collectionId }).list()
    if ((listing?.items ?? []).length === 0) {
      return
    }
    throw new Error(
      `Collection "${collectionId}" already holds unencrypted resources, so ` +
        'it cannot be provisioned as an encrypted collection.'
    )
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
      let read: { description: SpaceMetadata; etag?: string } | null
      try {
        read = await remote.spaceHandle().describeWithEtag()
      } catch (err) {
        log.warn('Could not confirm the promoted Space controller', { err })
        return { promoted: false }
      }
      if (read?.description.controller === did) {
        // The server already agrees, so nothing was promoted here.
        this.#fireKeystorePromotion({ profile, did })
        return { promoted: false }
      }
      remote.rebindController({
        zcapClient: didKeyZcapClient({ keyAgent }),
        controller: keyAgent.id
      })
      try {
        // A read with its validator is the description this method just made
        // through the same Space handle, so it rides along and `configure`
        // skips its own pre-merge describe. Two answers do not ride along. A
        // null one came from a read under the promoted signer, where an
        // unauthorized answer is masked as the same 404 an absent
        // description returns, so the truthful read is the one `configure`
        // makes under the did:key client. And a read carrying no `ETag` is
        // no compare-and-swap baseline at all -- was-client refuses such a
        // write rather than sending it unconditionally -- so it is dropped
        // for the same reason, leaving `configure` its own read.
        const current =
          read !== null && read.etag !== undefined
            ? { ...read.description, etag: read.etag }
            : undefined
        await remote.promoteSpaceController({
          controller: did,
          ...(current !== undefined ? { current } : {})
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
   * @returns {Promise<string>}   the minted activity id
   */
  async #recordActivity(
    build: (id: string) => WalletActivity
  ): Promise<string> {
    const resourceId = uuidv7()
    await this.#store.addHistoryItem({
      resourceId,
      activity: build(resourceId)
    })
    return resourceId
  }

  /**
   * Records the GenerationCollect activity -- annex GC's owner-side
   * digest, written before the collected generation's delete. Unlike every
   * other `addHistory*` method, the activity id is the generation id
   * VERBATIM rather than a minted `uuidv7`: the deterministic payload id is
   * what lets a torn re-run's second Resource collapse at read time, and readers
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
   * @returns {Promise<string>}   the recorded activity's id, which
   *   `deleteHistoryActivity` takes to remove it again
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
  }): Promise<string> {
    return await this.#recordActivity(id =>
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
   * @param [options.revoked] {number}   how many storage grants were revoked,
   *   counting one the server answered `AlreadyRevokedError`
   * @param [options.skipped] {number}   how many grants needed no revocation
   *   (legacy summary-only records, already-expired, or a dead chain)
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
   * the Applications listing joins its agent rows on, so writing this
   * activity is what takes the agent out of the listing.
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
   * Per capability, `#revokeZcaps`'s contract: only a grant already past
   * its own `expires` by more than the revocation clock-skew margin is
   * skipped without a POST. Every other unexpired grant is POSTed. The
   * server's `AlreadyRevokedError` counts as revoked. A plain refusal --
   * a `ValidationError`, or the server's masked `NotFoundError` on a grant
   * whose chain no longer verifies -- counts as skipped when the verified
   * account document explains it (expired, orphaned, or chained under a
   * parent delegation that has rotted); any other failure is thrown after
   * every POST settles, so the caller keeps the credential and retries rather
   * than recording a revocation the server never accepted. Legacy records
   * that stored only a display summary (no full zcap) are nothing to revoke
   * -- expiry is their backstop -- and count as skipped. A capability the
   * rotation stage already revoked (`revokedByRotation`) is counted as
   * revoked without a second POST. `withdrawn` counts only the POSTs that
   * landed on this call:
   * a grant answered `AlreadyRevokedError`, or revoked by the rotation
   * stage, counts in `revoked` and not in `withdrawn`. A no-op returning
   * zero counts when no remote store is configured.
   *
   * @param options {object}
   * @param options.origin {string}   the connected app's origin
   * @param options.subjectDid {string}   the app-key credential's subject DID,
   *   the controller the grants were delegated to
   * @param [options.items] {HistoryItems}   a
   *   pre-fetched history scan, when the caller already holds one
   * @param [options.revokedByRotation] {string[]}   the capability ids the
   *   rotation stage already revoked on its pull axis: counted as revoked
   *   and not POSTed again
   * @returns {Promise<{ revoked: number; withdrawn: number; skipped: number }>}
   */
  async revokeAppGrants({
    origin,
    subjectDid,
    items,
    revokedByRotation
  }: {
    origin: string
    subjectDid: string
    items?: HistoryItems
    revokedByRotation?: readonly string[]
  }): Promise<{ revoked: number; withdrawn: number; skipped: number }> {
    const remote = this.#remoteStore
    if (!remote) {
      return { revoked: 0, withdrawn: 0, skipped: 0 }
    }
    // Scan the history once and pass it through, so the grant lookup does not
    // re-await and re-scan it. A caller that already holds the history (the
    // revoke orchestration, which drives several of these) passes it in.
    const { zcaps, skipped: nonRevocable } = this.#recordedGrantZcaps({
      matches: object => object.origin === origin && !!object.appConnect,
      controller: subjectDid,
      items: items ?? (await this.listHistoryItems())
    })
    const outcome = await this.#revokeZcaps({ zcaps, revokedByRotation })
    return {
      revoked: outcome.revoked,
      withdrawn: outcome.withdrawn,
      skipped: outcome.skipped + nonRevocable
    }
  }

  /**
   * Revokes a set of recorded capabilities on the WAS server, one POST each
   * through {@link #postRevocations}, which holds the per-POST policy.
   * A capability named in `revokedByRotation` was already revoked by the
   * rotation stage's pull axis, which ran the same policy, so it is not
   * POSTed again. It counts as revoked and is named in `revokedIds`.
   * `revokedIds` names those and the capabilities the POSTs confirmed
   * revoked, in the order given, which is what an agent revocation records
   * as its audit trail. The server's `AlreadyRevokedError` counts as
   * revoked too: the capability is dead on the server, and an earlier
   * attempt that landed it and then failed elsewhere recorded nothing, so a
   * retry is where it reaches the trail. Once every POST has settled the
   * first failure is thrown verbatim, `err.name` intact, so the caller
   * neither deletes the credential nor records the Revoke and a retry re-runs
   * the set; the ids that did land, and the reasons the rest were skipped,
   * ride the warn logged before the throw, since the caller records nothing.
   *
   * The verified document's reading is resolved here, once per set and only
   * when something is left to POST, through the session-layer resolver bound
   * at construction; best-effort, so a read that throws is logged and read as
   * no check, and every unexpired grant is POSTed.
   *
   * @param options {object}
   * @param options.zcaps {IDelegatedZcap[]}
   * @param [options.revokedByRotation] {string[]}   capability ids already
   *   revoked by the rotation stage
   * @returns {Promise<{ revoked: number; withdrawn: number; skipped: number;
   *   revokedIds: string[] }>}   `withdrawn` counts the POSTs that landed on
   *   this call, leaving out the ones answered `AlreadyRevokedError` and the
   *   ones the rotation stage revoked
   */
  async #revokeZcaps({
    zcaps,
    revokedByRotation = []
  }: {
    zcaps: IDelegatedZcap[]
    revokedByRotation?: readonly string[]
  }): Promise<{
    revoked: number
    withdrawn: number
    skipped: number
    revokedIds: string[]
  }> {
    if (!this.#remoteStore) {
      return { revoked: 0, withdrawn: 0, skipped: 0, revokedIds: [] }
    }
    const rotated = new Set(revokedByRotation)
    const toPost = zcaps.filter(zcap => !rotated.has(zcap.id))
    // The signer read is skipped when nothing is left to POST.
    const posts =
      toPost.length > 0
        ? await this.#postRevocations({
            zcaps: toPost,
            signerCheck: await this.#readSignerCheck()
          })
        : { revokedIds: [], landedIds: [], skipped: [], failed: [] }
    const posted = new Set(posts.revokedIds)
    const revokedIds = zcaps
      .filter(zcap => rotated.has(zcap.id) || posted.has(zcap.id))
      .map(zcap => zcap.id)
    if (posts.failed.length > 0) {
      // The ids that DID land, and why the rest were skipped, are
      // diagnosable here and nowhere else: the throw carries the first
      // failure alone, and the caller records nothing.
      log.warn('Could not revoke every recorded grant; none recorded', {
        failed: posts.failed.map(entry => entry.id),
        revokedIds,
        skipped: posts.skipped
      })
      throw posts.failed[0].err
    }
    return {
      revoked: revokedIds.length,
      withdrawn: posts.landedIds.length,
      skipped: posts.skipped.length,
      revokedIds
    }
  }

  /**
   * POSTs the revocation of each recorded capability through wallet-core's
   * `revokeRecordedGrant`, whose policy each POST follows: the one local skip
   * is a capability expired beyond the revocation clock-skew margin;
   * everything else is POSTed, whatever the verified document says about its
   * signer; was-client's `AlreadyRevokedError` is a confirmed revocation; a
   * plain `ValidationError` is read against the document and counts as
   * skipped when the client can say why the chain no longer verifies
   * (expired, an orphaned account-signed grant, a parent delegation whose
   * signer left the document, or a generation the document no longer points
   * at), and is a failure otherwise, as is every other error. The POSTs are
   * independent, so they run together, and every one settles before this
   * returns. Nothing is thrown: the caller decides what a failure means.
   *
   * @param options {object}
   * @param options.zcaps {IDelegatedZcap[]}
   * @param [options.signerCheck] {AccountSignerCheck}   the verified
   *   document's reading, for classifying a refusal
   * @returns {Promise<object>}   `revokedIds`, the ids confirmed revoked (a
   *   landed POST or `AlreadyRevokedError`) in the order given; `landedIds`,
   *   the subset whose POST landed on this call; `skipped`, the ids left
   *   alone with the reason; `failed`, the ids whose POST failed with the
   *   error
   */
  async #postRevocations({
    zcaps,
    signerCheck
  }: {
    zcaps: IDelegatedZcap[]
    signerCheck?: AccountSignerCheck
  }): Promise<{
    revokedIds: string[]
    landedIds: string[]
    skipped: Array<{ id: string; reason: string }>
    failed: Array<{ id: string; err: unknown }>
  }> {
    const space = this.#requireRemote('Revoking a recorded grant').spaceHandle()
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
    const landedIds: string[] = []
    const skipped: Array<{ id: string; reason: string }> = []
    const failed: Array<{ id: string; err: unknown }> = []
    outcomes.forEach((outcome, index) => {
      const { id } = zcaps[index]
      if (outcome.status === 'rejected') {
        failed.push({ id, err: outcome.reason })
      } else if (outcome.value === 'revoked') {
        revokedIds.push(id)
        landedIds.push(id)
      } else if (outcome.value === 'already-revoked') {
        revokedIds.push(id)
      } else {
        skipped.push({ id, reason: outcome.value })
      }
    })
    return { revokedIds, landedIds, skipped, failed }
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
   * page's Login activities. There is no app key to delete; the epoch
   * rotation off the agent's recipient key is the separate
   * {@link revokeAgentCollectionRecipients} stage. Per capability this is `#revokeZcaps`'s
   * contract: a grant the verified document reads as dead is skipped without
   * a POST, `AlreadyRevokedError` counts as revoked, and any other failure is
   * thrown after every POST settles, so the caller records no Revoke and the
   * row stays listed for a retry. A capability the rotation stage already
   * revoked (`revokedByRotation`) is counted as revoked and named in
   * `revokedIds` without a second POST. `withdrawn` counts only the POSTs
   * that landed on this call.
   *
   * @param options {object}
   * @param options.controller {string}   the grantee did:key
   * @param [options.items] {HistoryItems}   a
   *   pre-fetched history scan, when the caller already holds one
   * @param [options.revokedByRotation] {string[]}   the capability ids the
   *   rotation stage already revoked on its pull axis: counted as revoked
   *   and not POSTed again
   * @returns {Promise<{ revoked: number; withdrawn: number; skipped: number;
   *   unrevocable: number; revokedIds: string[] }>}   `unrevocable` counts
   *   the grantee's recorded grants with no capability to POST, which end
   *   only at their own expiry
   */
  async revokeAgentGrants({
    controller,
    items,
    revokedByRotation
  }: {
    controller: string
    items?: HistoryItems
    revokedByRotation?: readonly string[]
  }): Promise<{
    revoked: number
    withdrawn: number
    skipped: number
    unrevocable: number
    revokedIds: string[]
  }> {
    if (!this.#remoteStore) {
      return {
        revoked: 0,
        withdrawn: 0,
        skipped: 0,
        unrevocable: 0,
        revokedIds: []
      }
    }
    const {
      zcaps,
      skipped: nonRevocable,
      unrevocable
    } = this.#recordedGrantZcaps({
      matches: isAgentActivityObject,
      controller,
      items: items ?? (await this.listHistoryItems())
    })
    const outcome = await this.#revokeZcaps({ zcaps, revokedByRotation })
    return {
      revoked: outcome.revoked,
      withdrawn: outcome.withdrawn,
      skipped: outcome.skipped + nonRevocable,
      unrevocable,
      revokedIds: outcome.revokedIds
    }
  }

  /**
   * The key-rotation half of revoking a connected app's access: for each
   * app-provisioned encrypted collection the app was granted, removes the
   * app's own recipient entry from the current epoch in ONE was-client
   * `removeRecipient` call (which rotates the epoch FIRST, then runs the pull
   * axis -- indivisible), so a revoked app cannot decrypt future writes. The
   * collection gains one epoch and its pull-axis zcaps are revoked once. The
   * owner (the vault KAK) stays recipient zero, and so does any other grantee
   * co-admitted to the same collection: the retiring kid is derived from this
   * app's subject DID (`x25519RecipientFromDidKey`), the same derivation
   * provisioning writes the roster entry with. An app-key subject is always a
   * seed-derived did:key, so a subject the derivation refuses is a malformed
   * caller, and it throws rather than reporting an empty rotation. Removal
   * needs no seed (the roster kid is in the descriptor), so it works even for
   * an orphaned state.
   *
   * The candidate collections are the union of two sources, because a grant
   * expires on its own while a recipient entry does not. The first is the
   * Space's collection listing: every collection whose Collection Metadata
   * names this app's subject DID as its `generator.id`, the attribution stamped
   * at App Connect provisioning. The second is the recorded grant zcaps'
   * `invocationTarget`s, expired grants included, which reaches a collection
   * the app was admitted to but did not provision. Standard / protected
   * collections are excluded from both, and so is a collection the listing
   * reports public, which carries no key-epoch roster. The unexpired grants still supply the
   * zcaps the rotation revokes on its pull axis; a candidate reached only
   * through the listing or through an expired grant rotates with nothing to
   * revoke.
   *
   * The pull axis POSTs each capability under the grant stage's own policy
   * ({@link #postRevocations}), in place of was-client's default revoke, which
   * reads every `ValidationError` as already revoked. `revokedIds` names only
   * the capabilities that policy confirmed revoked, so the grant stage does
   * not POST them again. A capability it skipped (a dead chain) or could not
   * revoke is left to the grant stage, which reaches the same answer and
   * throws on a failure. A pull that fails does not fail its collection: the
   * rotation is durable before the pull runs, so the collection counts as
   * rotated, this session adopts the rotated descriptor, and the ids the
   * pull did confirm ride `revokedIds`.
   *
   * Only candidates whose current-epoch roster still carries the app's own
   * entry are rotated, and the collections rotate in parallel. Best-effort per
   * collection: a failure is logged, counted in `failed`, and the rest
   * proceed, so one stuck collection does not strand the whole revocation. A
   * collection listing that cannot be read counts as one failure too, since
   * the caller cannot then tell a rotated app from one still holding a
   * recipient entry; a caller that supplies its own listing cannot hit that
   * failure. A no-op (zero counts) without a remote store. The honest limitation stands: ciphertext the app already fetched
   * stays readable to it.
   *
   * @param options {object}
   * @param options.origin {string}   the connected app's origin
   * @param options.subjectDid {string}   the app-key credential's subject DID
   * @param [options.items] {HistoryItems}   a pre-fetched history scan, when
   *   the caller already holds one
   * @param [options.collections] {Array<StorageCollection>}   a pre-fetched
   *   Space collection listing, when the caller already holds one
   * @returns {Promise<RecipientRotationOutcome>}
   */
  async revokeAppCollectionRecipients({
    origin,
    subjectDid,
    items,
    collections
  }: {
    origin: string
    subjectDid: string
    items?: HistoryItems
    collections?: Array<StorageCollection>
  }): Promise<RecipientRotationOutcome> {
    if (!this.#remoteStore) {
      return { collections: 0, rotated: 0, failed: 0, revokedIds: [] }
    }
    return this.#rotateCollectionsOffGrantee({
      matches: object => object.origin === origin && !!object.appConnect,
      controller: subjectDid,
      granteeKid: x25519RecipientFromDidKey({ did: subjectDid }).id,
      items,
      // The collections provisioned for this app, whatever its grants now
      // say. This is the source that survives every grant expiring.
      listing: {
        read: async () => collections ?? (await this.listCollections()),
        attributedTo: subjectDid
      }
    })
  }

  /**
   * The key-rotation half of revoking a connected agent's access, with the
   * same contract as {@link revokeAppCollectionRecipients}: each private
   * collection the agent's recorded grants target, expired grants included,
   * is rotated off the agent's recipient key in one `removeRecipient` call
   * that also revokes the unexpired pull-axis grants. Every listed private
   * collection whose `generator.id` is the agent's did:key is a candidate
   * beside the recorded grants' targets, so a collection whose Login activity
   * is gone is still rotated. The retiring kid is derived from the agent's
   * `did:key` controller, as provisioning derived it, so the revoke needs
   * nothing the agent holds. A controller the derivation refuses was never
   * escrowed, so it rotates nothing. The Space's collection listing is read
   * once, for those stamps and to leave out the targets it reports public. A
   * listing that cannot be read counts as one failure, as on the app path,
   * so the revocation throws and the row stays for a retry.
   *
   * @param options {object}
   * @param options.controller {string}   the grantee did:key
   * @param [options.items] {HistoryItems}   a pre-fetched history scan, when
   *   the caller already holds one
   * @returns {Promise<RecipientRotationOutcome>}
   */
  async revokeAgentCollectionRecipients({
    controller,
    items
  }: {
    controller: string
    items?: HistoryItems
  }): Promise<RecipientRotationOutcome> {
    const granteeKid = StorageManager.#granteeRosterKid(controller)
    if (!this.#remoteStore || !granteeKid) {
      return { collections: 0, rotated: 0, failed: 0, revokedIds: [] }
    }
    return this.#rotateCollectionsOffGrantee({
      matches: isAgentActivityObject,
      controller,
      granteeKid,
      items,
      // The collections provisioned for this agent, stamped with its did:key,
      // whether or not a Login activity still records the grant.
      listing: { read: () => this.listCollections(), attributedTo: controller }
    })
  }

  /**
   * The shared body of the two recipient revocations: collects the candidate
   * collections for one grantee, then rotates each whose current epoch still
   * carries the grantee's roster kid (see
   * {@link revokeAppCollectionRecipients} for the contract). `matches` picks
   * the grantee's Login activities. `listing.read` reads the Space's
   * collection listing, read once only when there is a candidate to filter
   * or `attributedTo` names a grantee. A collection the listing reports
   * public is no candidate, since a public collection carries no key-epoch
   * roster, and that saves a governed-log read per public target. With
   * `attributedTo`, every listed collection whose `generator.id` is that DID is
   * a further candidate. A listing that cannot be read is logged and counted
   * as one failure, with or without `attributedTo`: the public targets can
   * no longer be told apart, and a public target's governed-log read throws.
   * The remaining candidates are still attempted, so the retry has less
   * left to do.
   *
   * @param options {object}
   * @param options.matches {Function}   the Login-object predicate
   * @param options.controller {string}   the grantee did:key
   * @param options.granteeKid {string}   the grantee's roster kid
   * @param [options.items] {HistoryItems}
   * @param options.listing {object}
   * @param options.listing.read {Function}   reads the collection listing
   * @param [options.listing.attributedTo] {string}   the DID whose
   *   `generator`-attributed collections are candidates too
   * @returns {Promise<RecipientRotationOutcome>}
   */
  async #rotateCollectionsOffGrantee({
    matches,
    controller,
    granteeKid,
    items,
    listing
  }: {
    matches: (object: {
      origin?: string
      appConnect?: unknown
      zcaps?: unknown
    }) => boolean
    controller: string
    granteeKid: string
    items?: HistoryItems
    listing: {
      read: () => Promise<
        Array<Pick<StorageCollection, 'id' | 'isPublic' | 'generator'>>
      >
      attributedTo?: string
    }
  }): Promise<RecipientRotationOutcome> {
    const history = items ?? (await this.listHistoryItems())
    const { zcaps, expired } = this.#recordedGrantZcaps({
      matches,
      controller,
      items: history
    })

    // Group the pull-axis zcaps by the collection they target. Only the
    // unexpired ones are worth a revocation POST, so they alone land here.
    const byCollection = new Map<string, IDelegatedZcap[]>()
    const candidates = new Set<string>()
    for (const zcap of zcaps) {
      const collectionId = this.#rotatableCollectionOf(zcap.invocationTarget)
      if (!collectionId) {
        continue
      }
      candidates.add(collectionId)
      const existing = byCollection.get(collectionId)
      if (existing) {
        existing.push(zcap)
      } else {
        byCollection.set(collectionId, [zcap])
      }
    }
    // An expired grant names a collection the grantee may still be a
    // recipient of; it is a candidate to rotate, with no capability left to
    // revoke.
    for (const zcap of expired) {
      const collectionId = this.#rotatableCollectionOf(zcap.invocationTarget)
      if (collectionId) {
        candidates.add(collectionId)
      }
    }

    let listingFailed = false
    if (candidates.size > 0 || listing.attributedTo) {
      try {
        const listed = await listing.read()
        for (const collection of listed) {
          if (
            listing.attributedTo &&
            collection.generator?.id === listing.attributedTo &&
            !isProtectedCollection(collection.id)
          ) {
            candidates.add(collection.id)
          }
        }
        for (const collection of listed) {
          if (collection.isPublic) {
            candidates.delete(collection.id)
          }
        }
      } catch (err) {
        // Without the listing a public target cannot be told apart, and an
        // app's attributed collections cannot be found, so the grantee may
        // still hold a recipient entry somewhere: one failure either way.
        listingFailed = true
        log.warn(
          'Could not list the collections of the grantee being revoked',
          { controller, err }
        )
      }
    }

    // The verified document's reading, read once for every collection's pull
    // and only when some pull has a capability to POST.
    let signerCheck: Promise<AccountSignerCheck | undefined> | undefined
    const readSignerCheck = () => (signerCheck ??= this.#readSignerCheck())
    // The account's user key generations, likewise read at most once.
    const readGenerations = this.#userKeyGenerationsReader()

    // Each collection's rotation is independent of the others, so they run
    // together; the outcomes are summed below into the same counts a
    // sequential pass produced.
    const outcomes = await Promise.all(
      [...candidates].map(async collectionId => {
        const revoke = byCollection.get(collectionId) ?? []
        try {
          if (
            !(await this.#currentEpochLists({
              collectionId,
              recipientId: granteeKid
            }))
          ) {
            return { status: 'skipped' as const, revokedIds: [] }
          }
          const rotation = await this.#rotateOffRecipient({
            collectionId,
            recipientId: granteeKid,
            revoke,
            items: history,
            readSignerCheck,
            readGenerations,
            action: 'Revoking a collection recipient'
          })
          // The rotation is durable whatever the pull did, so the session
          // adopts it before the pull's outcome is weighed.
          await this.#descriptorCache?.writeDescriptor({
            collectionId,
            descriptor: rotation.descriptor
          })
          this.#appDescriptors[collectionId] = rotation.descriptor
          delete this.#appCiphers[collectionId]
          this.#refreshPolicy.reset({ collectionId })
          if (rotation.failed.length > 0) {
            // The rotation landed, so the grantee is off this roster. The
            // capabilities the pull could not revoke are not in
            // `revokedIds`, so the grant stage POSTs them again and throws
            // if they still fail. The collection counts as rotated.
            log.warn(
              'Could not revoke every grant on a rotated collection during revocation; left to the grant stage',
              {
                collectionId,
                revokedIds: rotation.revokedIds,
                failed: rotation.failed.map(entry => entry.id),
                err: rotation.failed[0].err
              }
            )
          }
          return { status: 'rotated' as const, revokedIds: rotation.revokedIds }
        } catch (err) {
          log.warn(
            'Could not rotate the epoch for a granted collection during revocation',
            {
              collectionId,
              err
            }
          )
          return { status: 'failed' as const, revokedIds: [] }
        }
      })
    )
    const rotated = outcomes.filter(
      outcome => outcome.status === 'rotated'
    ).length
    const failed =
      outcomes.filter(outcome => outcome.status === 'failed').length +
      (listingFailed ? 1 : 0)
    const revokedIds = outcomes.flatMap(outcome => outcome.revokedIds)
    return { collections: candidates.size, rotated, failed, revokedIds }
  }

  /**
   * Rotates one collection's current key epoch off a recipient through
   * was-client's `removeRecipient`, with the pull axis POSTing each recorded
   * capability under {@link #postRevocations}'s policy in place of
   * was-client's default revoke, which reads every `ValidationError` as
   * already revoked. The shared step of an unshare and of the app and agent
   * recipient revocations, so all three pull under one policy.
   *
   * The pull reports rather than throws, so `removeRecipient` returns the
   * rotated descriptor whenever the rotation landed, and the caller adopts
   * it whatever the pull did. A rotation that does not land throws, with
   * nothing pulled. `failed` names the capabilities whose POST failed, each
   * with its error, and the caller decides what that means.
   *
   * The fresh epoch is wrapped only to the recipients
   * {@link #admittedRecipientResolver} vouches for, so a roster entry this
   * wallet has no record of admitting is left out of it.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.recipientId {string}   the retiring recipient's kid
   * @param options.revoke {IDelegatedZcap[]}   the pull-axis capabilities
   * @param options.items {HistoryItems}   the pre-fetched history, read for
   *   the recipients this wallet admitted to the collection
   * @param options.readGenerations {Function}   reads the account's user
   *   key generation kids, from {@link #userKeyGenerationsReader}
   * @param options.readSignerCheck {Function}   reads the verified
   *   document's reading, called only when there is something to POST
   * @param options.action {string}   names the operation in a refusal
   * @returns {Promise<object>}   `descriptor`, the rotated descriptor;
   *   `revokedIds`, `skipped`, and `failed`, the pull's outcome as
   *   {@link #postRevocations} reports it
   */
  async #rotateOffRecipient({
    collectionId,
    recipientId,
    revoke,
    items,
    readSignerCheck,
    readGenerations,
    action
  }: {
    collectionId: string
    recipientId: string
    revoke: IDelegatedZcap[]
    items: HistoryItems
    readSignerCheck: () => Promise<AccountSignerCheck | undefined>
    readGenerations: () => Promise<Set<string>>
    action: string
  }): Promise<{
    descriptor: CollectionEncryption
    revokedIds: string[]
    skipped: Array<{ id: string; reason: string }>
    failed: Array<{ id: string; err: unknown }>
  }> {
    let posts: {
      revokedIds: string[]
      skipped: Array<{ id: string; reason: string }>
      failed: Array<{ id: string; err: unknown }>
    } = { revokedIds: [], skipped: [], failed: [] }
    const admission = this.#admittedRecipientResolver({
      collectionId,
      items,
      readGenerations
    })
    const descriptor = await removeRecipient({
      store: await this.#collectionStore({ collectionId, action }),
      recipientId,
      resolveRecipientKey: admission.resolve,
      pull: async () => {
        if (revoke.length === 0) {
          return
        }
        try {
          posts = await this.#postRevocations({
            zcaps: revoke,
            signerCheck: await readSignerCheck()
          })
        } catch (err) {
          // Nothing is known to have landed, so every capability counts as
          // failed with this error.
          posts = {
            revokedIds: [],
            skipped: [],
            failed: revoke.map(zcap => ({ id: zcap.id, err }))
          }
        }
      }
    })
    // The admitted set came from a history read that skipped Resources, so a
    // reader whose one admission sits in such a Resource was left out. The
    // rotation still lands, since a revocation must not wait on history.
    if (items.unreadable > 0) {
      log.warn(
        'Rotated a collection key from a history with unreadable resources; a reader admitted only there was left out',
        {
          collectionId,
          unreadableHistory: items.unreadable,
          dropped: [...admission.dropped]
        }
      )
    }
    return { descriptor, ...posts }
  }

  /**
   * A reader of the account's user key generation kids that reads the
   * verified roster at most once, on its first call, so the rotations of
   * one operation share one read.
   *
   * @returns {Function}
   */
  #userKeyGenerationsReader(): () => Promise<Set<string>> {
    let generations: Promise<Set<string>> | undefined
    return () =>
      (generations ??= this.#userKeyGenerationKids().then(
        kids => new Set(kids)
      ))
  }

  /**
   * The `resolveRecipientKey` a rotation of one collection hands
   * was-client's `removeRecipient`. It vouches only for the recipients this
   * wallet admitted to the collection, and resolves `null` for any other kid
   * the roster lists, so a junk entry receives no wrap of the fresh epoch
   * key. The admitted set is the owner (this session's vault KAK), every
   * grantee a recorded Login grant targeting the collection was delegated
   * to, expired grants included since a recipient entry outlives its grant,
   * and every reader a recorded `CollectionShare` names for it, unless a
   * `CollectionUnshare` for the pair supersedes that share
   * ({@link #shareReaders}). The history is sealed under the account's own key, so the host can withhold
   * an admission from it but cannot add one.
   *
   * The account's earlier user key generations are admitted too. A user key
   * rotation torn before this collection's re-epoch leaves a generation
   * other than the current one as the owner entry, and dropping it would
   * seal the fresh epoch away from the account. The generations are read
   * from the verified user key roster, and only when a kid is otherwise
   * unadmitted.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.items {HistoryItems}   the pre-fetched history
   * @param options.readGenerations {Function}   reads the account's user key
   *   generation kids, from {@link #userKeyGenerationsReader}
   * @returns {{ resolve: Function, dropped: Set<string> }}   `resolve` maps a
   *   kid to its public key-agreement key, or `null` for a kid this wallet
   *   did not admit, and records that kid in `dropped`
   */
  #admittedRecipientResolver({
    collectionId,
    items,
    readGenerations
  }: {
    collectionId: string
    items: HistoryItems
    readGenerations: () => Promise<Set<string>>
  }): {
    resolve: (kid: string) => Promise<RecipientPublicKey | null>
    dropped: Set<string>
  } {
    const owner = ownerRecipient({
      keyAgreementKey: this.#vaultKeys.keyAgreementKey
    })
    const admitted = StorageManager.#shareReaders({ collectionId, items })
    for (const { doc } of items.entries) {
      if (!doc.type?.includes('Login')) {
        continue
      }
      const zcaps = (doc.object as { zcaps?: unknown } | undefined)?.zcaps
      if (!Array.isArray(zcaps)) {
        continue
      }
      for (const entry of zcaps) {
        const zcap = ((entry ?? {}) as { zcap?: IZcap }).zcap
        if (
          !zcap?.invocationTarget ||
          this.#rotatableCollectionOf(zcap.invocationTarget) !== collectionId
        ) {
          continue
        }
        const controllers = Array.isArray(zcap.controller)
          ? zcap.controller
          : [zcap.controller]
        for (const controller of controllers) {
          const kid = controller && StorageManager.#granteeRosterKid(controller)
          if (kid) {
            admitted.add(kid)
          }
        }
      }
    }
    const dropped = new Set<string>()
    return {
      dropped,
      async resolve(kid) {
        if (kid === owner.id) {
          return owner
        }
        if (admitted.has(kid) || (await readGenerations()).has(kid)) {
          return await trustRosterDidKeys(kid)
        }
        dropped.add(kid)
        return null
      }
    }
  }

  /**
   * The collections each grantee's key still sits in the current key epoch
   * of, among the collections its grants target: the candidates and the
   * roster check the recipient revocations rotate on, run read-only. A grant
   * target counts when it names a collection of this Space that is not
   * protected, and that the Space's lean listing does not report public (a
   * public collection carries no key-epoch roster; a listing that cannot be
   * read filters nothing). Each distinct candidate's governed descriptor is read once,
   * in parallel, and shared across the grantees that target it. A read that
   * fails is logged and counted in the `failed` of every grantee targeting
   * it, since the caller cannot then tell whether that collection still
   * lists the grantee. Without a remote store nothing can be read, so each
   * grantee reports one failure. A grantee whose controller derives no
   * roster kid was never escrowed, and lists nowhere.
   *
   * @param options {object}
   * @param options.grantees {Array<{ controller: string; targets: string[] }>}
   *   each grantee did:key with its grants' invocation targets, expired
   *   grants included
   * @returns {Promise<Array<{ controller: string; collectionIds: string[];
   *   failed: number }>>}   one entry per grantee, in the order given
   */
  async granteeRosterCollections({
    grantees
  }: {
    grantees: Array<{ controller: string; targets: string[] }>
  }): Promise<
    Array<{ controller: string; collectionIds: string[]; failed: number }>
  > {
    if (!this.#remoteStore) {
      return grantees.map(({ controller }) => ({
        controller,
        collectionIds: [],
        failed: 1
      }))
    }
    const candidatesOf = grantees.map(({ controller, targets }) => {
      const candidates = new Set<string>()
      if (StorageManager.#granteeRosterKid(controller)) {
        for (const target of targets) {
          const collectionId = this.#rotatableCollectionOf(target)
          if (collectionId) {
            candidates.add(collectionId)
          }
        }
      }
      return candidates
    })
    // One read per distinct collection, whichever grantees target it.
    const distinct = new Set(candidatesOf.flatMap(set => [...set]))
    // A collection the lean listing reports public carries no key-epoch
    // roster, so it costs no governed-log read. The listing is one read for
    // every candidate; one that fails only loses the filter.
    if (distinct.size > 0) {
      try {
        for (const {
          id,
          isPublic
        } of await this.listCollectionPublicStates()) {
          if (isPublic) {
            distinct.delete(id)
            for (const candidates of candidatesOf) {
              candidates.delete(id)
            }
          }
        }
      } catch (err) {
        log.warn('Could not list the public collections among grant targets', {
          err
        })
      }
    }
    const descriptors = new Map<
      string,
      CollectionEncryption | undefined | Error
    >()
    await Promise.all(
      [...distinct].map(async collectionId => {
        try {
          descriptors.set(
            collectionId,
            await this.#readGovernedDescriptor({ collectionId })
          )
        } catch (err) {
          log.warn('Could not read a granted collection key epoch', {
            collectionId,
            err
          })
          descriptors.set(
            collectionId,
            err instanceof Error ? err : new Error(String(err))
          )
        }
      })
    )
    return grantees.map(({ controller }, index) => {
      const recipientId = StorageManager.#granteeRosterKid(controller)
      const collectionIds: string[] = []
      let failed = 0
      for (const collectionId of candidatesOf[index]) {
        const descriptor = descriptors.get(collectionId)
        if (descriptor instanceof Error) {
          failed += 1
        } else if (
          recipientId &&
          currentEpochRecipientKids({ descriptor }).includes(recipientId)
        ) {
          collectionIds.push(collectionId)
        }
      }
      return { controller, collectionIds, failed }
    })
  }

  /**
   * A grantee's own roster kid, derived the way provisioning derives it.
   * Undefined for a controller the derivation cannot handle. Such a
   * controller was never escrowed anywhere (resolution refuses it for a
   * provisioned collection), so there is nothing to rotate: an agent granted
   * only a public collection under a non-did:key controller is the case this
   * admits.
   *
   * @param controller {string}   the grantee DID
   * @returns {string | undefined}
   */
  static #granteeRosterKid(controller: string): string | undefined {
    try {
      return x25519RecipientFromDidKey({ did: controller }).id
    } catch {
      return undefined
    }
  }

  /**
   * The collection a grant's invocation target names when a revocation may
   * rotate it: a collection of this Space that is not protected. Undefined
   * for a protected collection, a target that names no collection of this
   * Space, or a session with no remote store.
   *
   * @param invocationTarget {string}
   * @returns {string | undefined}
   */
  #rotatableCollectionOf(invocationTarget: string): string | undefined {
    const remote = this.#remoteStore
    if (!remote) {
      return undefined
    }
    const collectionId = collectionIdFromTarget({
      invocationTarget,
      serverUrl: remote.storageServerUrl,
      spaceId: remote.spaceId
    })
    if (!collectionId || isProtectedCollection(collectionId)) {
      return undefined
    }
    return collectionId
  }

  /**
   * Whether a collection's current key epoch, read from its governed
   * descriptor, lists a recipient. A collection with no key epochs lists
   * none. A failed read throws.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.recipientId {string}   the recipient's key-agreement kid
   * @returns {Promise<boolean>}
   */
  async #currentEpochLists({
    collectionId,
    recipientId
  }: {
    collectionId: string
    recipientId: string
  }): Promise<boolean> {
    const descriptor = await this.#readGovernedDescriptor({ collectionId })
    return currentEpochRecipientKids({ descriptor }).includes(recipientId)
  }

  /**
   * The full delegated zcaps recorded for one grantee, scanned from the
   * `Login` history activities `matches` accepts: those whose recorded `zcap`
   * was delegated to `controller` and has not already expired by its own
   * `expires` (wallet-core's `delegationExpired`, beyond the revocation
   * clock-skew margin; an absent or unparseable
   * value is not expired). Deduplicated by capability id. A capability
   * delegated to another controller is another grantee's and is not counted
   * at all. `skipped` counts this grantee's entries that carry no revocable
   * capability: a legacy summary-only record, or an already-expired grant.
   * `unrevocable` counts the legacy summary-only records alone, the one kind
   * that may still be live: nothing can be POSTed for it, so it ends only at
   * its own expiry. A summary-only record names no controller, so it is
   * counted on a Login whose full capabilities name this controller, or name
   * none at all. `expired` carries the grants dropped for expiry alone:
   * nothing to revoke, but they still name the collections the grantee may
   * remain a key-epoch recipient of. The predicate is what tells the two
   * grantee kinds apart: an App Connect app (an origin plus an `appConnect`
   * member) and an agent (the interaction-URL origin marker and no
   * `appConnect`).
   *
   * @param options {object}
   * @param options.matches {Function}   the Login-object predicate
   * @param options.controller {string}   the grantee the grants were
   *   delegated to
   * @param options.items {HistoryItems}   the
   *   pre-fetched history, so this need not re-scan it
   * @returns {{ zcaps: IDelegatedZcap[]; skipped: number;
   *   unrevocable: number; expired: IDelegatedZcap[] }}
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
    items: HistoryItems
  }): {
    zcaps: IDelegatedZcap[]
    skipped: number
    unrevocable: number
    expired: IDelegatedZcap[]
  } {
    const zcaps: IDelegatedZcap[] = []
    const expired: IDelegatedZcap[] = []
    const seen = new Set<string>()
    const now = Date.now()
    let skipped = 0
    let unrevocable = 0
    for (const { doc } of items.entries) {
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
      let legacy = 0
      let namesController = false
      let namesOther = false
      for (const entry of object.zcaps) {
        const zcap = ((entry ?? {}) as { zcap?: IZcap }).zcap
        // A legacy summary-only entry has no revocable capability; expiry is
        // the backstop.
        if (!zcap || !('parentCapability' in zcap)) {
          legacy += 1
          continue
        }
        // Only revoke capabilities delegated to this grantee's key.
        const controllers = Array.isArray(zcap.controller)
          ? zcap.controller
          : [zcap.controller]
        if (!controllers.includes(controller)) {
          namesOther = true
          continue
        }
        namesController = true
        if (seen.has(zcap.id)) {
          continue
        }
        seen.add(zcap.id)
        // The one expiry reading every revocation path shares: the zcap's
        // own `expires`, and an absent or unparseable one is NOT expired.
        if (delegationExpired({ zcap, now })) {
          skipped += 1
          expired.push(zcap)
          continue
        }
        zcaps.push(zcap)
      }
      // A Login naming only other controllers is another grantee's.
      if (namesController || !namesOther) {
        skipped += legacy
        unrevocable += legacy
      }
    }
    return { zcaps, skipped, unrevocable, expired }
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
  async listHistoryItems(): Promise<HistoryItems> {
    // Same stale-descriptor refresh as `listCredentials`, once per session.
    return this.#readWithEpochRefresh({
      collectionId: 'wallet-activity',
      read: async () => {
        const { entries, unknownEpoch, unreadable } =
          await this.#store.listHistoryItems()
        return {
          value: { entries, unreadable },
          unknownEpoch: unknownEpoch > 0
        }
      }
    })
  }

  /**
   * Signs the pull axis of a share: a read-only (GET/HEAD) zcap on the
   * collection URL, delegated to the grantee. It is rooted at the Space root
   * capability, so targets outside the Space are unsatisfiable by
   * construction. In a transient session it chains under the generation
   * delegation the session's authority rides instead, with the expiry limited
   * to the delegation's own. Signing is local and inert, so a caller can
   * record the signed grant before `shareCollection` escrows the reader.
   *
   * @param options {object}
   * @param options.profile {ControllerProfile}   the session profile
   * @param options.collectionId {string}   the WAS collection id to share
   * @param options.controller {string}   the grantee's DID (the zcap controller)
   * @param [options.expires] {Date}   the zcap's expiry; defaults to the
   *   read-only grant TTL
   * @returns {Promise<IDelegatedZcap>}
   */
  async delegateShareGrant({
    profile,
    collectionId,
    controller,
    expires
  }: {
    profile: ControllerProfile
    collectionId: string
    controller: string
    expires?: Date
  }): Promise<IDelegatedZcap> {
    const remote = this.#requireRemote('Sharing a collection')
    const spaceRootCapability = rootCapabilityId(remote.spaceUrl)
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
    return (await profile.zcapClient.delegate({
      capability: profile.invocationCapability ?? spaceRootCapability,
      invocationTarget: collectionUrl,
      controller,
      allowedActions: ['GET', 'HEAD'],
      expires: expiresAt
    })) as unknown as IDelegatedZcap
  }

  /**
   * Shares one of the wallet's encrypted collections with another reader,
   * doing BOTH halves of a share as one procedure: the read axis (an epoch-key
   * recipient entry, so the reader can decrypt) and the pull axis (the
   * read-only Collection zcap `delegateShareGrant` signed, so the server
   * serves it ciphertext). Requires a passphrase session (the recipient
   * operations rewrite the Collection Description) with an unlocked vault and
   * a remote store.
   *
   * The zcap is checked before anything is written: it must name a
   * controller, target this collection's canonical URL, and allow only GET
   * and HEAD. A zcap that fails the check is refused with nothing escrowed.
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
   *   (vault KAK)
   * @param options.user {User}   recorded as the share activity's actor
   * @param options.collectionId {string}   the WAS collection id to share
   * @param options.recipient {RecipientPublicKey}   the grantee's public
   *   key-agreement key (its `id` is the recipient `kid`)
   * @param options.zcap {IDelegatedZcap}   the pull-axis capability
   *   `delegateShareGrant` signed for the grantee
   * @param [options.app] {{ name: string, origin: string }}   the connected app
   *   the share was granted to, when the grantee is one; recorded on the share
   *   activity so the settings panel can name it instead of showing a bare DID
   * @returns {Promise<{ descriptor: CollectionEncryption }>}   the new
   *   descriptor
   */
  async shareCollection({
    profile,
    user,
    collectionId,
    recipient,
    zcap,
    app
  }: {
    profile: ControllerProfile
    user: User
    collectionId: string
    recipient: RecipientPublicKey
    zcap: IDelegatedZcap
    app?: { name: string; origin: string }
  }): Promise<{ descriptor: CollectionEncryption }> {
    const remote = this.#requireRemote('Sharing a collection')
    const { keyAgreementKey, keyResolver } = profile
    if (!keyAgreementKey || !keyResolver) {
      throw new Error('Sharing a collection requires the vault key material.')
    }
    if (!profile.keyAgent) {
      throw new Error('Sharing a collection requires a passphrase session.')
    }
    const controller = zcap.controller
    // An absent `allowedAction` allows every action the parent does, so it
    // counts as empty here and is refused.
    const allowedActions = [zcap.allowedAction ?? []].flat()
    if (
      typeof controller !== 'string' ||
      zcap.invocationTarget !== remote.collectionTargetUrl(collectionId) ||
      allowedActions.length === 0 ||
      !allowedActions.every(action => action === 'GET' || action === 'HEAD')
    ) {
      throw new Error(
        'A share grant must be a read-only zcap on the shared collection.'
      )
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

    // Record the share -- the full delegated zcap document is the revocation
    // hook `unshareCollection` reads back.
    await this.#recordActivity(id =>
      buildHistoryCollectionShared({
        user,
        collectionId,
        recipientId: recipient.id,
        controller,
        zcap,
        expires: zcap.expires,
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
    return { descriptor }
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
   * from the `CollectionShare` history activities and revoked on the pull
   * axis under the recorded-grant policy ({@link #postRevocations}), the one
   * the app and agent revocations use; an empty set is acceptable (e.g. all
   * grants already expired) -- the rotation still happens. The rotated
   * descriptor is cached and swapped into the local ciphers as soon as the
   * rotation lands. A capability whose POST fails (a refusal the verified
   * document cannot explain included) throws that first failure verbatim,
   * `err.name` intact, once every POST settles, and no `CollectionUnshare` is
   * recorded. Otherwise a `CollectionUnshare` activity is recorded (no zcap).
   *
   * A torn unshare stays retryable. The rotation has already dropped the
   * reader from the current epoch, but {@link listCollectionShares} keeps
   * listing a reader whose recorded share grant is unexpired and has no
   * `CollectionUnshare` after it, so the panel still offers the removal. A
   * retry finds the reader already off the current epoch, so
   * `removeRecipient` appends no second epoch and runs the pull alone. A
   * grant the server has already revoked counts as revoked there. A refusal
   * the document cannot explain fails each retry until the grant expires.
   * From then on the pull skips it and the panel stops listing the reader,
   * since an expired grant is no authority left to revoke.
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
    this.#requireRemote('Unsharing a collection')
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
    const rotation = await this.#rotateOffRecipient({
      collectionId,
      recipientId,
      revoke,
      items,
      readSignerCheck: () => this.#readSignerCheck(),
      readGenerations: this.#userKeyGenerationsReader(),
      action: 'Unsharing a collection'
    })

    // The rotation is durable whatever the pull did, so the session adopts it
    // before the pull's outcome is weighed.
    await this.#adoptCollectionDescriptor({
      collectionId,
      descriptor: rotation.descriptor,
      vaultKeys: { keyAgreementKey, keyResolver }
    })
    if (rotation.failed.length > 0) {
      // As on the grant stage: the ids that did land, and why the rest were
      // skipped, are diagnosable here alone, since nothing is recorded.
      log.warn('Could not revoke every share grant; no unshare recorded', {
        collectionId,
        failed: rotation.failed.map(entry => entry.id),
        revokedIds: rotation.revokedIds,
        skipped: rotation.skipped
      })
      throw rotation.failed[0].err
    }

    await this.#recordActivity(id =>
      buildHistoryCollectionUnshared({ user, collectionId, recipientId, id })
    )
    return rotation.descriptor
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
   * @param options.items {HistoryItems}   the
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
    items: HistoryItems
  }): IDelegatedZcap[] {
    const zcaps: IDelegatedZcap[] = []
    for (const { doc } of items.entries) {
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
   * A reader the current epoch no longer lists is still listed while it
   * holds a live share grant: a `CollectionShare` whose recorded zcap has
   * not expired, with no `CollectionUnshare` recorded for the pair since.
   * That is the state an unshare leaves when its rotation landed and its
   * pull failed, and listing it is what lets the user retry the unshare.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param [options.items] {HistoryItems}   a
   *   pre-fetched history scan, when the caller already holds one (the
   *   settings panel lists every encrypted collection off one read)
   * @returns {Promise<Array<{ recipientId: string; controller?: string;
   *   expires?: string; appName?: string; appOrigin?: string }>>}
   */
  async listCollectionShares({
    collectionId,
    items
  }: {
    collectionId: string
    items?: HistoryItems
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
    const history = items ?? (await this.listHistoryItems())
    // The owner's own key-agreement key is recipient zero on every epoch; drop
    // it so the list is only the other readers. A reader a torn unshare
    // rotated off, whose grant is still live, joins them.
    const recipientIds = [
      ...new Set([
        ...currentEpochRecipientKids({
          descriptor,
          ownerKid: this.#vaultKeys.keyAgreementKey.id
        }),
        ...StorageManager.#shareReaders({
          collectionId,
          items: history,
          live: true
        })
      ])
    ]
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
    for (const { doc } of history.entries) {
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
   * The readers a recorded `CollectionShare` names for one collection, less
   * those a `CollectionUnshare` for the same pair supersedes: one recorded
   * at or after that share, or one whose stamp does not parse, which
   * supersedes every share of the pair. With `live`, only a share recording
   * a zcap that has not expired counts (wallet-core's `delegationExpired`,
   * the reading the revocation's own expiry skip uses). An unshare is
   * recorded only once its pull has succeeded, so a live reader has a grant
   * no unshare has confirmed revoked.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.items {HistoryItems}   the pre-fetched history
   * @param [options.live] {boolean}   count only unexpired share grants
   * @returns {Set<string>}   the readers' key-agreement kids
   */
  static #shareReaders({
    collectionId,
    items,
    live = false
  }: {
    collectionId: string
    items: HistoryItems
    live?: boolean
  }): Set<string> {
    // The latest unshare stamp per reader; NaN when a stamp does not parse.
    const unsharedAt = new Map<string, number>()
    for (const { doc } of items.entries) {
      if (!doc.type?.includes('CollectionUnshare')) {
        continue
      }
      const object = doc.object as
        { collectionId?: string; recipientId?: string } | undefined
      if (object?.collectionId !== collectionId || !object.recipientId) {
        continue
      }
      const stamp = Date.parse(doc.created ?? '')
      const previous = unsharedAt.get(object.recipientId)
      if (previous === undefined || Number.isNaN(stamp) || stamp > previous) {
        unsharedAt.set(object.recipientId, stamp)
      }
    }
    const now = Date.now()
    const readers = new Set<string>()
    for (const { doc } of items.entries) {
      if (!doc.type?.includes('CollectionShare')) {
        continue
      }
      const object = doc.object as
        | { collectionId?: string; recipientId?: string; zcap?: IZcap }
        | undefined
      if (object?.collectionId !== collectionId || !object.recipientId) {
        continue
      }
      if (
        live &&
        (!object.zcap || delegationExpired({ zcap: object.zcap, now }))
      ) {
        continue
      }
      const unshared = unsharedAt.get(object.recipientId)
      if (unshared !== undefined) {
        const shared = Date.parse(doc.created ?? '')
        if (Number.isNaN(unshared) || !(shared > unshared)) {
          continue
        }
      }
      readers.add(object.recipientId)
    }
    return readers
  }

  /**
   * Lists the stored contacts. Unknown-epoch Resources mean the contacts cipher
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
   * Rewrites a contact's Resource in place and appends its `update` revision.
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
   * snapshot (read before the Resource is removed).
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
   * payload that every replica's revisions refer to), not the resource id --
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

  /**
   * The content-migration import methods: one per migrated collection, each
   * taking an ARCHIVED Resource out of a backup bundle and writing it with no
   * side effects of its own -- no `created` activity, no `create` revision, and
   * no re-minted id, timestamp, or `writerId`. The interactive write methods
   * above keep their side effects unconditionally; nothing here is a flag on
   * them.
   *
   * Every one reports an {@link ImportOutcome} rather than throwing, so the
   * walk carries on past a Resource it could not write. The one exception is the
   * walk-stopping error (`WALK_STOPPING_ERROR_NAME`, was-client's 507), which
   * is a wall rather than a per-Resource failure and is rethrown so the walk
   * stops.
   *
   * The merge rule is "skip existing, by content identity", so a re-run of the
   * same bundle converges and a populated account keeps what it has. The
   * "already held" checks read the {@link HeldContent} snapshot the caller
   * took with {@link snapshotHeldContent}, and each accepted write adds its
   * Resource to that snapshot, so one run reads each collection once and a
   * Resource it wrote counts as held for the Resources behind it.
   *
   * @param options {object}
   * @param options.what {string}   what the failed write was, for the log line
   * @param options.write {function}   the write, reporting its own outcome
   * @returns {Promise<Outcome | 'failed'>}
   */
  async #importResource<Outcome extends string>({
    what,
    write
  }: {
    what: string
    write: () => Promise<Outcome>
  }): Promise<Outcome | 'failed'> {
    try {
      return await write()
    } catch (err) {
      if (errorNameOf(err) === WALK_STOPPING_ERROR_NAME) {
        // The Space is full: every Resource behind this one would fail the same
        // way, so the walk stops rather than wasting the rest of the bundle.
        throw err
      }
      log.warn(`Could not import an archived ${what}`, { err })
      return 'failed'
    }
  }

  /**
   * Reads what the account holds in the collections the import methods
   * write, once, as the snapshot they decide against. The three listings are
   * independent and run together. Each rides the same stale-descriptor
   * refresh the page reads do, so a Resource another client re-sealed under a
   * rotated key epoch is still seen as held rather than imported a second
   * time.
   *
   * Credentials need no entry: their dedupe is the shared write half's own
   * cid check.
   *
   * @returns {Promise<HeldContent>}
   */
  async snapshotHeldContent(): Promise<HeldContent> {
    const [heads, revisions, items] = await Promise.all([
      this.#readWithEpochRefresh({
        collectionId: 'contacts',
        read: async () => ({
          value: await this.#store.listContactHeads(),
          unknownEpoch: this.#store.unknownEpochContacts > 0
        })
      }),
      this.#readWithEpochRefresh({
        collectionId: 'contacts-history',
        read: async () => ({
          value: await this.#store.listAllContactRevisions(),
          unknownEpoch: this.#store.unknownEpochContactsHistory > 0
        })
      }),
      this.listHistoryItems()
    ])
    const contactHeads = new Map<string, ContactHeadPayload>()
    for (const { resourceId, head } of heads) {
      // Legacy heads written before the resource-id / contact-id split carry
      // no usable distinction; fall back to the resource id for those.
      contactHeads.set(head.contactId ?? resourceId, head)
    }

    const contactRevisions = new Map<string, Set<string>>()
    for (const revision of revisions) {
      let identities = contactRevisions.get(revision.contactId)
      if (!identities) {
        identities = new Set<string>()
        contactRevisions.set(revision.contactId, identities)
      }
      identities.add(contentCid(revision as unknown as Json))
    }

    const activities = new Map<string, WalletActivity>()
    for (const { id, doc } of items.entries) {
      activities.set(id, doc)
    }

    return { contactHeads, contactRevisions, activities }
  }

  /**
   * Imports one archived credential, deduped by its content cid. Records no
   * Create activity: the bundle's own `wallet-activity` Resources carry the old
   * wallet's history, and a burst of creations dated today would bury it.
   *
   * A credential presenting as an app key (the marker type) is reported
   * `skipped` without a write: app keys are wallet-minted and do not migrate in
   * this build, so the credential is screened and counted as not migrated
   * rather than counted as a write that failed.
   *
   * @param options {object}
   * @param options.credential {IVerifiableCredential}
   * @returns {Promise<ImportOutcome>}
   */
  async importCredential({
    credential
  }: {
    credential: IVerifiableCredential
  }): Promise<ImportOutcome> {
    return await this.#importResource({
      what: 'credential',
      write: async () => {
        if (presentsAsAppKey(credential)) {
          log.warn('Skipping an archived credential presenting as an app key')
          return 'skipped'
        }
        const { inserted } = await this.#storeCredential({ credential })
        return inserted ? 'accepted' : 'skipped'
      }
    })
  }

  /**
   * Imports one archived contact head verbatim, under the `contactId` the old
   * wallet minted -- the identity every migrated revision refers to -- with
   * its archived `updatedAt` and `writerId`. Records no `create` revision.
   *
   * A head carrying no `contactId` is `conflicting`: it could be deduped
   * against nothing, so every re-run would land another copy under a fresh
   * resource id, and reporting it as failed would invite a retry that can never
   * converge.
   *
   * Two checks run before the write. A held contact that is the un-customized
   * seed twin of the archived one (social-core's `isUnlinkedSeedTwin` over
   * this wallet's seed names) already stands for it, so the archived copy is
   * reported `seed-twin` and lands nowhere; a customized local seed contact is
   * not matched and the archived copy lands beside it. Then the id check: a
   * held contact under the same `contactId` is `skipped` when its payload's
   * content identity matches, and `conflicting` when it differs -- the held
   * contact is left untouched and nothing is written, so a doctored bundle
   * cannot overwrite a genuine contact by reusing its id.
   *
   * `seed-twin` is reported apart from `skipped` because the contact's
   * revisions ride on the difference: an already-held head stands for them,
   * while a seed twin's revisions carry the old account's identity in every
   * snapshot and must not land. The walk maps it down to the sink vocabulary
   * and owns the orphan rule for the revisions.
   *
   * @param options {object}
   * @param options.head {ContactHeadPayload}
   * @param options.held {HeldContent}   the run's snapshot, updated on accept
   * @returns {Promise<ImportOutcome | 'seed-twin'>}
   */
  async importContactHead({
    head,
    held
  }: {
    head: ContactHeadPayload
    held: HeldContent
  }): Promise<ImportOutcome | 'seed-twin'> {
    return await this.#importResource({
      what: 'contact',
      write: async (): Promise<ImportOutcome | 'seed-twin'> => {
        if (!head.contactId) {
          log.warn(
            'Refusing an archived contact head that carries no contactId'
          )
          return 'conflicting'
        }
        const heads = held.contactHeads
        // Only an archived head carrying a seed name can have a twin, so the
        // scan over the held heads runs for those alone.
        if (SEED_CONTACT_NAMES.includes(head.contact.displayName)) {
          for (const local of heads.values()) {
            if (
              isUnlinkedSeedTwin(
                local.contact,
                head.contact,
                SEED_CONTACT_NAMES
              )
            ) {
              return 'seed-twin'
            }
          }
        }
        // Compared through the read-side upgrade every listing passes a head
        // through, so a head this import itself wrote reads back as the same
        // identity and a re-run converges rather than reporting a conflict.
        const upgraded = upgradeContactHeadPayload(head)
        const stored = heads.get(head.contactId)
        if (stored) {
          const archived = contentCid(upgraded as unknown as Json)
          return archived === contentCid(stored as unknown as Json)
            ? 'skipped'
            : 'conflicting'
        }
        await this.#store.putContactHead({ head })
        heads.set(head.contactId, upgraded)
        return 'accepted'
      }
    })
  }

  /**
   * Imports one archived contact revision verbatim, keeping its archived
   * `timestamp` and `writerId`, appended to `contacts-history` under the
   * `contactId` it carries.
   *
   * A revision payload carries no id of its own, so its identity is the
   * content id of the payload, compared against the snapshot's identities for
   * that contact; a match is `skipped`. The snapshot's one decrypt pass is
   * what a stored, blinded index would replace (FW-545).
   *
   * Whether the revision's contact exists is deliberately not checked here.
   * The orphan rule belongs to the walk, which knows what the bundle carried
   * and what this run wrote; this method only refuses to crash without a
   * head.
   *
   * @param options {object}
   * @param options.revision {ContactRevisionPayload}
   * @param options.held {HeldContent}   the run's snapshot, updated on accept
   * @returns {Promise<ImportOutcome>}
   */
  async importContactRevision({
    revision,
    held
  }: {
    revision: ContactRevisionPayload
    held: HeldContent
  }): Promise<ImportOutcome> {
    return await this.#importResource({
      what: 'contact revision',
      write: async () => {
        let identities = held.contactRevisions.get(revision.contactId)
        if (!identities) {
          identities = new Set<string>()
          held.contactRevisions.set(revision.contactId, identities)
        }
        // Upgraded for the comparison, stored verbatim: the listings upgrade
        // every revision they read, so an identity built from the raw archived
        // payload would miss this import's own earlier write.
        const identity = contentCid(
          upgradeContactRevisionPayload(revision) as unknown as Json
        )
        if (identities.has(identity)) {
          return 'skipped'
        }
        await this.#store.addContactRevision({ revision })
        identities.add(identity)
        return 'accepted'
      }
    })
  }

  /**
   * Imports one archived activity verbatim, its own `id` included, deduped by
   * that id. A held activity under the same id whose body's content identity
   * differs is `conflicting`: the archived activity lands nowhere and the held
   * activity is untouched.
   *
   * An archived activity carrying no id of its own is `conflicting` too. It
   * cannot be deduped, so every re-run would add another copy; reporting it as
   * failed would invite a retry that can never converge.
   *
   * Which activities are worth migrating (only a credential's own, and the
   * drop rule for an archived `created` activity) is the walk's filter, not this
   * method's.
   *
   * @param options {object}
   * @param options.activity {WalletActivity}
   * @param options.held {HeldContent}   the run's snapshot, updated on accept
   * @returns {Promise<ImportOutcome>}
   */
  async importActivity({
    activity,
    held
  }: {
    activity: WalletActivity
    held: HeldContent
  }): Promise<ImportOutcome> {
    return await this.#importResource({
      what: 'activity',
      write: async () => {
        const id = activity.id
        if (!id) {
          log.warn('Refusing an archived activity that carries no id')
          return 'conflicting'
        }
        const stored = held.activities.get(id)
        if (!stored) {
          await this.#store.addHistoryItem({ resourceId: id, activity })
          held.activities.set(id, activity)
          return 'accepted'
        }
        return contentCid(stored as Json) === contentCid(activity as Json)
          ? 'skipped'
          : 'conflicting'
      }
    })
  }

  /**
   * Creates, or adopts, one app collection the content migration is about to
   * fill, in the account's own Space. App collections are remote-only on
   * every session kind, so this and the two methods after it talk to the
   * remote store directly.
   *
   * The standing collection is read first, and a collection the account
   * already holds is checked before anything is written (see
   * {@link #checkStandingAppCollection}). The check refuses a collection
   * whose shape differs from the archive's with an
   * {@link AppCollectionMismatchError}. Then the collection is ensured. The
   * ensure's own report of whether its guarded create made the collection
   * decides what this run may set up, not the earlier read. A create lost to
   * a rival reads the rival's collection back and checks it the same way.
   *
   * A standing collection keeps its own settings: its public read, its index
   * schema, and its attribution. One exception is this migration's own torn
   * create. A standing collection that holds no Resources and carries the
   * archived `generator` is finished as if this run had created it. An
   * archive with no `generator` never qualifies, since an unattributed
   * standing collection is one no grant this wallet resolved created, and
   * the run cannot tell it from its own.
   *
   * An encrypted collection is provisioned owner-only: a fresh governing log
   * whose first epoch wraps to the user key alone, with a new blinded-index
   * key. The first epoch is create-if-absent, so a standing roster is
   * adopted. On a collection this run creates or finishes, the archived
   * `indexSchema`, when given, is declared, unless the collection already
   * declares one. Last, the cipher the Resources are read and written through is
   * built from the descriptor and the collection's metadata as it now
   * stands, so every write carries the blinded index entries the
   * collection's schema asks for. A standing collection that predates the
   * blinded index carries no key to declare under; its Resources migrate without
   * index entries. The archived public read is ignored for an encrypted
   * collection.
   *
   * A plaintext collection is ensured private. When this run creates or
   * finishes it and the archive says public, the world-read grant is set
   * afterwards.
   *
   * `generator` is stamped on a create only.
   *
   * @param options {object}
   * @param options.collectionId {string}   the WAS collection id
   * @param options.encrypted {boolean}   whether the archived collection
   *   carried a governing collection log
   * @param [options.isPublic] {boolean}   whether the archived collection was
   *   world-readable; read for a plaintext collection only
   * @param [options.generator] {CollectionGenerator}   the archived app
   *   attribution
   * @param [options.indexSchema] {IndexSchema}   the archived blinded-index
   *   schema; an encrypted collection only
   * @returns {Promise<void>}
   */
  async ensureImportedAppCollection({
    collectionId,
    encrypted,
    isPublic,
    generator,
    indexSchema
  }: {
    collectionId: string
    encrypted: boolean
    isPublic?: boolean
    generator?: CollectionGenerator
    indexSchema?: IndexSchema
  }): Promise<void> {
    const remote = this.#requireRemote('Importing an app collection')
    this.#importCollections.delete(collectionId)
    this.#importCiphers.delete(collectionId)
    // An encrypted collection's public read is not the archive's to set.
    const archivedPublic = !encrypted && isPublic === true
    const check = async (standing: StandingAppCollection) =>
      await this.#checkStandingAppCollection({
        remote,
        collectionId,
        encrypted,
        isPublic: archivedPublic,
        generator,
        standing
      })
    const standing = await remote.collectionMetadata({ collectionId })
    let verdict = standing === undefined ? undefined : await check(standing)
    const { created } = encrypted
      ? await this.#ensureImportedGovernedCollection({
          remote,
          collectionId,
          generator
        })
      : await this.#ensureImportedPlaintextCollection({
          remote,
          collectionId,
          generator
        })
    if (!created && verdict === undefined) {
      // A rival created the collection between the read and the create.
      const rival = await remote.collectionMetadata({ collectionId })
      if (rival === undefined) {
        throw new Error(
          `The collection "${collectionId}" vanished while it was ensured.`
        )
      }
      verdict = await check(rival)
    }
    const finishes = created || verdict?.resumesOwnCreate === true

    if (!encrypted) {
      if (finishes && archivedPublic && verdict?.standsPublic !== true) {
        await remote.collectionHandle({ collectionId }).setPublic()
      }
      return
    }

    const descriptor = await this.#installFirstEpoch({ collectionId })
    const { keyAgreementKey, keyResolver } = this.#vaultKeys
    // A standing collection keeps its own schema: declaring the archived one
    // could add a `unique` constraint the collection's app never asked for.
    // A finished torn create declares it unless an earlier run already did.
    const declares =
      created ||
      (finishes &&
        (await remote.collectionMeta({ collectionId })) === undefined)
    const indexes = declares ? (indexSchema?.indexes ?? []) : []
    if (indexes.length > 0 && !descriptor.hmac) {
      log.warn(
        'The collection carries no blinded-index key, so its imported resources ' +
          'carry no index entries',
        { collectionId }
      )
    } else if (indexes.length > 0) {
      await remote.declareCollectionIndexes({
        collectionId,
        encryption: descriptor,
        keyAgreementKey,
        keyResolver,
        indexes: indexes.map(({ attribute, unique }) => ({
          attribute,
          ...(unique !== undefined && { unique })
        }))
      })
    }
    await this.#installImportCipher({ collectionId, descriptor })
    this.#importCollections.add(collectionId)
  }

  /**
   * The plaintext half of {@link ensureImportedAppCollection}'s ensure:
   * was-client's guarded create, always private. The world-read grant is the
   * caller's to set, and only on a collection this run made.
   *
   * @param options {object}
   * @param options.remote {WASRemoteStore}
   * @param options.collectionId {string}
   * @param [options.generator] {CollectionGenerator}
   * @returns {Promise<{ created: boolean }>}
   */
  async #ensureImportedPlaintextCollection({
    remote,
    collectionId,
    generator
  }: {
    remote: WASRemoteStore
    collectionId: string
    generator?: CollectionGenerator
  }): Promise<{ created: boolean }> {
    try {
      return await remote.ensureCollection({
        id: collectionId,
        isPublic: false,
        ...(generator !== undefined && { generator })
      })
    } catch (err) {
      // The ensure wraps its failure; a full Space must still reach the
      // walk under its own name, so the walk stops.
      const cause = (err as Error).cause
      if (errorNameOf(cause) === WALK_STOPPING_ERROR_NAME) {
        throw cause
      }
      throw err
    }
  }

  /**
   * The encrypted half of {@link ensureImportedAppCollection}'s ensure: the
   * bare guarded create of a log-governed collection. A rival that won the
   * create with a client-written `encryption` descriptor makes was-client
   * refuse with its `ValidationError`, which is reported as the mismatch it
   * is.
   *
   * @param options {object}
   * @param options.remote {WASRemoteStore}
   * @param options.collectionId {string}
   * @param [options.generator] {CollectionGenerator}
   * @returns {Promise<{ created: boolean }>}
   */
  async #ensureImportedGovernedCollection({
    remote,
    collectionId,
    generator
  }: {
    remote: WASRemoteStore
    collectionId: string
    generator?: CollectionGenerator
  }): Promise<{ created: boolean }> {
    try {
      return await remote.ensureGovernedCollection({
        id: collectionId,
        ...(generator !== undefined && { generator })
      })
    } catch (err) {
      if (errorNameOf(err) !== 'ValidationError') {
        throw err
      }
      const encryption = (await remote.collectionMetadata({ collectionId }))
        ?.encryption
      if (encryption !== undefined && !isGovernedDescriptor(encryption)) {
        throw new AppCollectionMismatchError({
          collectionId,
          message: clientWrittenDescriptorMessage(collectionId),
          cause: err
        })
      }
      throw err
    }
  }

  /**
   * Checks an app collection the account already holds against the
   * archived one, before anything is written. Nothing is written here.
   *
   * First it decides whether the collection is this migration's own torn
   * create. That holds when the collection has no Resources and its `generator`
   * equals the archived one. A missing archived `generator` never
   * qualifies.
   *
   * Then it refuses, with an {@link AppCollectionMismatchError}:
   *
   * - an archived plaintext collection over one that stands encrypted;
   * - any archive over a collection encrypted under a client-written
   *   descriptor, which no governing log can take over;
   * - an archived encrypted collection over a plaintext one that holds
   *   Resources;
   * - for a plaintext archive, a public read that differs from the
   *   archive's. A torn create that stands private under a public archive is
   *   let through, so the caller can grant the public read it missed;
   * - for a plaintext archive, an empty collection with no `encryption`
   *   member and no public read, unless it is a torn create. That is also
   *   the state an App Connect encrypted provision torn before its first
   *   epoch leaves, and a plaintext Resource landed there would keep the app's
   *   provision refused for good.
   *
   * An empty collection with no `encryption` member is let through for an
   * encrypted archive, which finishes such a provision.
   *
   * @param options {object}
   * @param options.remote {WASRemoteStore}
   * @param options.collectionId {string}
   * @param options.encrypted {boolean}   the archived kind
   * @param options.isPublic {boolean}   the archived public read; always
   *   `false` for an encrypted archive
   * @param [options.generator] {CollectionGenerator}   the archived
   *   attribution
   * @param options.standing {StandingAppCollection}   the standing
   *   collection's metadata
   * @returns {Promise<{ resumesOwnCreate: boolean; standsPublic: boolean }>}
   */
  async #checkStandingAppCollection({
    remote,
    collectionId,
    encrypted,
    isPublic,
    generator,
    standing
  }: {
    remote: WASRemoteStore
    collectionId: string
    encrypted: boolean
    isPublic: boolean
    generator?: CollectionGenerator
    standing: StandingAppCollection
  }): Promise<{ resumesOwnCreate: boolean; standsPublic: boolean }> {
    const refuse = (message: string): never => {
      throw new AppCollectionMismatchError({ collectionId, message })
    }
    const encryption = standing.encryption
    const standsEncrypted = encryption !== undefined
    if (standsEncrypted && !encrypted) {
      refuse(
        `The collection "${collectionId}" already stands encrypted, so an ` +
          'archived plaintext collection cannot be imported into it.'
      )
    }
    if (encryption !== undefined && !isGovernedDescriptor(encryption)) {
      refuse(clientWrittenDescriptorMessage(collectionId))
    }
    const handle = remote.collectionHandle({ collectionId })
    const sameGenerator =
      generator !== undefined &&
      standing.generator !== undefined &&
      contentCid(generator as unknown as Json) ===
        contentCid(standing.generator as unknown as Json)
    // Resources matter for the torn-create test, and for the kind checks on a
    // collection with no `encryption` member. The listing stops at the first
    // page holding a Resource.
    const holdsAnyResource = async (): Promise<boolean> => {
      for await (const page of handle.listPages()) {
        if (page.items.length > 0) {
          return true
        }
      }
      return false
    }
    const [holdsResources, standsPublic] = await Promise.all([
      sameGenerator || !standsEncrypted ? holdsAnyResource() : false,
      encrypted ? false : handle.isPublic()
    ])
    const resumesOwnCreate = sameGenerator && !holdsResources
    if (encrypted) {
      if (!standsEncrypted && holdsResources) {
        refuse(
          `The collection "${collectionId}" already holds unencrypted ` +
            'resources, so an archived encrypted collection cannot be ' +
            'imported into it.'
        )
      }
      return { resumesOwnCreate, standsPublic: false }
    }
    const missedGrant = resumesOwnCreate && isPublic && !standsPublic
    if (standsPublic !== isPublic && !missedGrant) {
      refuse(
        `The collection "${collectionId}" already stands ` +
          `${standsPublic ? 'public' : 'private'}, and the archived one is ` +
          `${isPublic ? 'public' : 'private'}. Its setting is left as it is.`
      )
    }
    if (!holdsResources && !standsPublic && !resumesOwnCreate) {
      refuse(
        `The collection "${collectionId}" stands empty with no encryption ` +
          'set up, which may be an encrypted collection not yet finished, ' +
          'so archived plaintext resources are not written into it.'
      )
    }
    return { resumesOwnCreate, standsPublic }
  }

  /**
   * Builds the cipher an encrypted app collection's imported Resources go
   * through, from its descriptor and its metadata as it now stands, so the
   * collection's index schema is installed on it. The cipher is recorded
   * beside the descriptor it was built from.
   *
   * @param options {object}
   * @param options.collectionId {string}
   * @param options.descriptor {CollectionEncryption}
   * @returns {Promise<{ cipher: EdvDocCipher; descriptor: CollectionEncryption }>}
   */
  async #installImportCipher({
    collectionId,
    descriptor
  }: {
    collectionId: string
    descriptor: CollectionEncryption
  }): Promise<{ cipher: EdvDocCipher; descriptor: CollectionEncryption }> {
    const { keyAgreementKey, keyResolver } = this.#vaultKeys
    // Read back rather than built from the archived schema: a standing
    // collection keeps its own declarations, and its Resources must carry them.
    const meta = await this.#requireRemote(
      'Importing an app collection'
    ).collectionMeta({ collectionId })
    const cipher = await createEdvDocCipher({
      keyAgreementKey,
      keyResolver,
      collectionId,
      encryption: descriptor,
      ...(meta !== undefined && { meta })
    })
    const entry = { cipher, descriptor }
    this.#importCiphers.set(collectionId, entry)
    return entry
  }

  /**
   * The cipher for an encrypted app collection
   * {@link ensureImportedAppCollection} ensured, with the descriptor it was
   * built from. After an unknown-epoch refresh dropped it, it is rebuilt
   * from the verified head of the collection's governing log. Refuses a
   * collection it has not ensured.
   *
   * @param collectionId {string}
   * @returns {Promise<{ cipher: EdvDocCipher; descriptor: CollectionEncryption }>}
   */
  async #importCipherFor(
    collectionId: string
  ): Promise<{ cipher: EdvDocCipher; descriptor: CollectionEncryption }> {
    if (!this.#importCollections.has(collectionId)) {
      throw new Error(
        `The app collection "${collectionId}" was not ensured before its resources.`
      )
    }
    const cached = this.#importCiphers.get(collectionId)
    if (cached) {
      return cached
    }
    const descriptor = await this.#readGovernedDescriptor({ collectionId })
    if (!descriptor) {
      throw new Error(
        `The app collection "${collectionId}" has no encryption descriptor.`
      )
    }
    return await this.#installImportCipher({ collectionId, descriptor })
  }

  /**
   * The cipher an imported Resource is sealed under, current as of this write.
   * The server takes a write's `Key-Epoch` as advisory, so a Resource sealed
   * under a superseded epoch would land. An epoch rotated mid-run, by a
   * revocation cascade in another tab say, must therefore be caught here.
   *
   * Each write reads the collection's served metadata, one small request,
   * and compares its current epoch with the one the cipher was built under.
   * Only when they differ is the governing log's verified head read, and
   * the cipher is rebuilt, schema included, when that head has moved. The
   * served member only triggers the check. The cipher is always built from
   * the verified head.
   *
   * @param collectionId {string}
   * @returns {Promise<{ cipher: EdvDocCipher; descriptor: CollectionEncryption }>}
   */
  async #importCipherForWrite(
    collectionId: string
  ): Promise<{ cipher: EdvDocCipher; descriptor: CollectionEncryption }> {
    const entry = await this.#importCipherFor(collectionId)
    const served = await this.#requireRemote(
      'Importing an app collection'
    ).collectionEncryption({ collectionId })
    if (served?.currentEpoch === entry.descriptor.currentEpoch) {
      return entry
    }
    const verified = await this.#readGovernedDescriptor({ collectionId })
    if (
      verified === undefined ||
      verified.currentEpoch === entry.descriptor.currentEpoch
    ) {
      return entry
    }
    log.info(
      'An app collection epoch moved mid-import; rebuilding its cipher',
      {
        collectionId,
        currentEpoch: verified.currentEpoch
      }
    )
    return await this.#installImportCipher({
      collectionId,
      descriptor: verified
    })
  }

  /**
   * Reads what the account holds in one app collection, once per run, as
   * the map {@link importAppCollectionResource} decides against: each held
   * Resource's identity (see {@link appResourceIdentity}) to its content cid.
   * A plaintext Resource's identity is its resource id. In an encrypted
   * collection, a JSON Resource is recorded under its payload's identity,
   * and a bytes Resource under its resource id with no cid. A bytes Resource
   * is recognized without reading its content, so a chunked one is never
   * reassembled here. A Resource sealed under an epoch the cipher does not
   * know drives the one unknown-epoch refresh, and the Resources are
   * decrypted again under the rebuilt cipher. One that still will not
   * decrypt is left out and logged. That includes a pending stub a killed
   * chunked write left.
   *
   * @param options {object}
   * @param options.collectionId {string}   an app collection this run ensured
   * @param options.encrypted {boolean}
   * @returns {Promise<HeldAppResources>}
   */
  async snapshotAppCollection({
    collectionId,
    encrypted
  }: {
    collectionId: string
    encrypted: boolean
  }): Promise<HeldAppResources> {
    const documents = await this.#requireRemote(
      'Importing an app collection'
    ).listCollectionDocuments({ collectionId })
    if (!encrypted) {
      const held: HeldAppResources = new Map()
      for (const { id, data } of documents) {
        held.set(id, contentCid(data))
      }
      return held
    }
    return await this.#readWithEpochRefresh({
      collectionId,
      read: async () => {
        // Fetched inside the read: a refresh drops the cipher.
        const { cipher } = await this.#importCipherFor(collectionId)
        const decrypted = await Promise.all(
          documents.map(async ({ id, data }) => ({
            id,
            ...(await decryptHeldAppResource({
              cipher,
              id,
              envelope: data,
              source: `app collection "${collectionId}"`
            }))
          }))
        )
        const held: HeldAppResources = new Map()
        for (const { id, value, bytes } of decrypted) {
          if (bytes) {
            held.set(appResourceIdentity({ resourceId: id }), null)
          } else if (value !== undefined) {
            const cid = contentCid(value)
            held.set(appResourceIdentity({ json: value, cid }), cid)
          }
        }
        return {
          value: held,
          unknownEpoch: decrypted.some(entry => entry.unknownEpoch)
        }
      }
    })
  }

  /**
   * Imports one archived app collection Resource, deduped by its identity
   * (see {@link snapshotAppCollection}). A held Resource under the same
   * identity is `skipped` when its content matches, and `conflicting` when it
   * differs: the archived Resource lands nowhere and the held one is
   * untouched.
   *
   * An encrypted JSON Resource is re-sealed through the collection's import
   * cipher and written under the fresh content-derived id the envelope
   * takes. An encrypted bytes Resource is sealed under its archived content
   * type and written at its archived resource id, create-if-absent, as a
   * chunked document when it is large. A taken id is read back and compared
   * by bytes, and a pending stub a killed chunked write left there is
   * removed and the Resource written again. A plaintext Resource keeps its
   * archived resource id and content type, written create-if-absent. A JSON
   * one another writer landed there since the snapshot is `conflicting`. A
   * non-JSON one is not in the snapshot, so an id already taken is read
   * back: the same bytes are `skipped`, and other bytes are `conflicting`.
   *
   * A migration runs one at a time (see `migrateContent`), since a second
   * run could remove a stub the first is still filling.
   *
   * @param options {object}
   * @param options.collectionId {string}   an app collection this run ensured
   * @param options.encrypted {boolean}
   * @param options.resourceId {string}   the Resource's archived resource id
   * @param options.contentType {string}   the archived content type
   * @param options.content {{ json: Json } | { bytes: Uint8Array }}   the
   *   decrypted payload or parsed JSON body, or a non-JSON body's raw bytes
   *   (for an encrypted collection, a payload that decrypted to a `Blob`)
   * @param options.held {HeldAppResources}   the collection's snapshot, updated on
   *   accept
   * @returns {Promise<ImportOutcome>}
   */
  async importAppCollectionResource({
    collectionId,
    encrypted,
    resourceId,
    contentType,
    content,
    held
  }: {
    collectionId: string
    encrypted: boolean
    resourceId: string
    contentType: string
    content: { json: Json } | { bytes: Uint8Array }
    held: HeldAppResources
  }): Promise<ImportOutcome> {
    return await this.#importResource({
      what: 'app collection resource',
      write: async (): Promise<ImportOutcome> => {
        const remote = this.#requireRemote('Importing an app collection')
        if ('bytes' in content && encrypted) {
          const { cipher, descriptor } =
            await this.#importCipherForWrite(collectionId)
          const { keyAgreementKey, keyResolver } = this.#vaultKeys
          const written = await remote.putEncryptedResourceBytes({
            collectionId,
            resourceId,
            bytes: content.bytes,
            contentType,
            encryption: descriptor,
            keyAgreementKey,
            keyResolver,
            isPendingStub: envelope =>
              cipher.isPendingStub({ id: resourceId, envelope })
          })
          if (written.created) {
            held.set(appResourceIdentity({ resourceId }), null)
            return 'accepted'
          }
          return written.held !== undefined &&
            equalBytes(written.held, content.bytes)
            ? 'skipped'
            : 'conflicting'
        }
        if ('bytes' in content) {
          if (held.has(resourceId)) {
            // A JSON Resource stands under the id this non-JSON Resource would
            // take.
            return 'conflicting'
          }
          const { created } = await remote.putPlaintextResource({
            collectionId,
            resourceId,
            data: content.bytes,
            contentType
          })
          if (created) {
            return 'accepted'
          }
          const stored = await remote.getResourceBytes({
            collectionId,
            resourceId
          })
          return stored !== undefined && equalBytes(stored, content.bytes)
            ? 'skipped'
            : 'conflicting'
        }

        const { json } = content
        const cid = contentCid(json)
        const identity = encrypted
          ? appResourceIdentity({ json, cid })
          : resourceId
        const stored = held.get(identity)
        if (stored !== undefined) {
          return stored === cid ? 'skipped' : 'conflicting'
        }
        if (encrypted) {
          const { cipher } = await this.#importCipherForWrite(collectionId)
          const { id, envelope, epoch } = await cipher.encrypt({ data: json })
          await remote.putCollectionResource({
            collectionId,
            resourceId: id,
            body: envelope,
            ...(epoch !== undefined && { epoch })
          })
        } else {
          const { created } = await remote.putPlaintextResource({
            collectionId,
            resourceId,
            data: json,
            contentType
          })
          if (!created) {
            return 'conflicting'
          }
        }
        held.set(identity, cid)
        return 'accepted'
      }
    })
  }

  /**
   * Writes one activity and then removes every OTHER Resource carrying the same
   * activity id -- the migration's import activity, the one activity written
   * this way.
   *
   * The order is load-bearing. `listHistoryItems` keeps the first Resource it
   * meets per activity id, and an envelope is nondeterministic, so a re-run's
   * fresh Resource would otherwise hide behind the first run's stale one
   * forever. Writing first leaves no window with no Resource at all, and a
   * kill between the two writes leaves two Resources that the next run's
   * delete step clears, so it converges either way.
   *
   * @param options {object}
   * @param options.activity {WalletActivity}   carries its own deterministic
   *   id, the one the replaced Resources share
   * @returns {Promise<void>}
   */
  async putHistoryItemReplacingOthers({
    activity
  }: {
    activity: WalletActivity
  }): Promise<void> {
    const id = activity.id
    if (!id) {
      throw new Error(
        'Cannot replace history resources for an activity that carries no id.'
      )
    }
    const resourceId = await this.#store.addHistoryItem({
      resourceId: id,
      activity
    })
    const resources = await this.#store.findHistoryItemsByInnerId({ id })
    for (const resource of resources) {
      if (resource.resourceId !== resourceId) {
        await this.#store.deleteHistoryItemByResourceId({
          resourceId: resource.resourceId
        })
      }
    }
  }

  /**
   * Removes every Resource carrying one activity id. An approval uses it to take
   * back the Login it persisted before provisioning, when the rest of the
   * approval fails before anything is delivered.
   *
   * @param options {object}
   * @param options.id {string}   the activity id to remove
   * @returns {Promise<void>}
   */
  async deleteHistoryActivity({ id }: { id: string }): Promise<void> {
    const resources = await this.#store.findHistoryItemsByInnerId({ id })
    for (const resource of resources) {
      await this.#store.deleteHistoryItemByResourceId({
        resourceId: resource.resourceId
      })
    }
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
