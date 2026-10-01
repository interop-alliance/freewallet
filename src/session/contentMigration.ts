/**
 * The content-migration ceremony: a backup bundle's content read back into
 * the account this session is logged into.
 *
 * `@interop/wallet-backup` owns the reading -- the bundle's outer tar, the
 * old secret's derivation, the archived user key roster, and the decrypt
 * walk -- and pushes one plaintext Resource at a time at the sink this module
 * builds over `StorageManager`'s four import methods. The walk issues no
 * request and the module holds no reference to the secret past the call: it
 * is handed to `migrateBundle`, which zeroes the derived material when it
 * ends, and nothing here stores or logs it.
 *
 * What the import methods do not carry, this module does, because it alone
 * knows what the run has already written: the orphan rule for a contact
 * revision whose head is nowhere, the activity filter (only a credential's
 * own activities migrate), and the drop rule for an archived `Create` the
 * account already records. The walk's report then becomes the one Import
 * activity the run writes, replacing any earlier run's Import activity for
 * the same bundle.
 *
 * Every session kind may run it, a guest included: every import method
 * routes to the session's own backend, so a transient session writes
 * remote-direct and a remembered one writes to the replica.
 *
 * App collections, the ones a connected app had the old account provision,
 * migrate too when the session can create them (remote storage and the
 * descriptor logs of a promoted account). Each is re-created owner-only
 * under its archived attribution, and its Resources are written remote-direct on
 * every session kind, since no replica holds an app collection. A guest or a
 * no-WAS session leaves them counted as not migrated.
 */
import { migrateBundle, MIGRATION_WALK_ORDER } from '@interop/wallet-backup'
import type {
  AppCollectionResource,
  ByteSource,
  MigrationReport,
  MigrationSecret,
  MigrationSink,
  SinkOutcome
} from '@interop/wallet-backup'
import { addHistoryContentImported } from '@interop/wallet-core/space'
import type { ImportCollectionOutcome } from '@interop/wallet-core/space'
import { errorNameOf } from '@interop/wallet-core/menders'
import { ceremonyEvents } from '@interop/wallet-core'
import type {
  CeremonyDetail,
  CeremonyEmitter,
  CeremonyOutcome
} from '@interop/wallet-core'
import type {
  ContactHeadPayload,
  ContactRevisionPayload
} from '@interop/social-core'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { credentialActivityInfo } from '@/lib/historyActivity'
import { quotaViewFromReport } from '@/lib/storageQuota'
import { createLogger } from '@/lib/log'
import { isRememberedSession } from '@/session/persistence'
import { awaitCollectionsInSync } from '@/stores/syncStatusStore'
import type { WalletActivity } from '@/stores/storageManager'
import type { Session } from '@/types/auth'
import type { HeldAppResources, HeldContent } from '@/types/migration'
import type { Json } from '@interop/was-sync'

const log = createLogger('fw:session:migration')

/**
 * Refuses a content migration started while another is still running in
 * this tab. Two runs over the same bundle could each find the other's
 * unfinished chunked write at an id both are importing, and remove it as a
 * torn write's stub while it is still being filled.
 */
export class ContentMigrationInProgressError extends Error {
  constructor() {
    super('A content migration is already running.')
    this.name = 'ContentMigrationInProgressError'
  }
}

// Whether a migration is running in this tab. The sink runs one at a time.
let migrationRunning = false

/**
 * The migration's stage ids for the ceremony event channel, in run order:
 * the waits and pre-checks before the walk, the walk itself, and the Import
 * activity write.
 */
export const CONTENT_MIGRATION_STAGES = [
  'preflight',
  'walk',
  'import-activity'
] as const

/**
 * One value of {@link CONTENT_MIGRATION_STAGES}.
 */
export type ContentMigrationStage = (typeof CONTENT_MIGRATION_STAGES)[number]

/**
 * The thrown errors a migration run classifies as `refused`: a run already
 * going in this tab, the walk's own refusals of the bundle and the secret,
 * and the user's cancel. Each leaves what landed safe for a re-run to build
 * on. Every other throw is `failed`, a `QuotaExceededError` from the Import
 * activity write included.
 */
const CONTENT_MIGRATION_REFUSALS: ReadonlyArray<string> = [
  'ContentMigrationInProgressError',
  'BundleInvalidError',
  'AccountSpaceArchiveMissingError',
  'BundleRecipientMissingError',
  'AbortError'
]

/**
 * The quota pre-check's finding: the bundle is bigger than the Space has
 * room for. Surfaced rather than thrown -- the user decides whether to run
 * the walk anyway, and the walk stops on its own if the server refuses.
 */
export interface ContentMigrationQuotaWarning {
  bundleBytes: number
  freeBytes: number
}

/**
 * One migration run's outcome: the package's report, plus what this module
 * added around it.
 */
export interface ContentMigrationResult {
  report: MigrationReport
  quotaWarning?: ContentMigrationQuotaWarning
  /**
   * False when a remembered session's replication had not settled before the
   * walk began, so the merge checks read a replica that may lag the remote.
   */
  replicaInSync: boolean
}

/**
 * The bundle's size in bytes when it is known without draining a stream.
 *
 * @param options {object}
 * @param options.bundle {ByteSource}
 * @param [options.bundleBytes] {number}   the size a caller already knows
 *   (a picked `File`'s), preferred over the source itself
 * @returns {number | undefined}
 */
function bundleSizeOf({
  bundle,
  bundleBytes
}: {
  bundle: ByteSource
  bundleBytes?: number
}): number | undefined {
  if (bundleBytes !== undefined) {
    return bundleBytes
  }
  return bundle instanceof Uint8Array ? bundle.byteLength : undefined
}

/**
 * Reads the Space's quota report and says whether the bundle would overrun
 * what is left. Absent quotas (no remote storage, an unreported limit, an
 * unreachable server) are not a refusal: the check is skipped and the walk
 * proceeds.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.bundleBytes] {number}
 * @returns {Promise<ContentMigrationQuotaWarning | undefined>}
 */
async function quotaWarningFor({
  session,
  bundleBytes
}: {
  session: Session
  bundleBytes?: number
}): Promise<ContentMigrationQuotaWarning | undefined> {
  if (bundleBytes === undefined || !session.storage.hasRemoteStorage) {
    return undefined
  }
  let freeBytes: number | undefined
  try {
    const report = await session.storage.getSpaceQuotas()
    freeBytes = report ? quotaViewFromReport(report)?.freeBytes : undefined
  } catch (err) {
    log.warn('Could not read the Space quotas before a content migration', {
      err
    })
    return undefined
  }
  if (freeBytes === undefined || bundleBytes <= freeBytes) {
    return undefined
  }
  return { bundleBytes, freeBytes }
}

/**
 * The DID the Import activity records as the account imported into: the
 * account's did:webvh once it has one, the pointer's DID before promotion,
 * and the session's own did:key on a guest or a no-WAS session.
 *
 * @param session {Session}
 * @returns {string}
 */
function targetDidOf(session: Session): string {
  return (
    session.profile.didWebvh?.did ??
    session.profile.accountPointer?.did ??
    session.user.id
  )
}

/**
 * The sink's app-collection member, over the session's app-collection import
 * methods. It holds what those methods cannot: whether each collection is
 * encrypted, and each collection's held-Resource snapshot, read at its first Resource
 * and kept current by the writes.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {NonNullable<MigrationSink['appCollections']>}
 */
function appCollectionsSink({
  session
}: {
  session: Session
}): NonNullable<MigrationSink['appCollections']> {
  const { storage } = session
  const encryptedById = new Map<string, boolean>()
  const snapshots = new Map<string, Promise<HeldAppResources>>()

  return {
    async ensureCollection({
      collectionId,
      encrypted,
      isPublic,
      generator,
      indexSchema
    }): Promise<void> {
      encryptedById.set(collectionId, encrypted)
      snapshots.delete(collectionId)
      await storage.ensureImportedAppCollection({
        collectionId,
        encrypted,
        ...(isPublic !== undefined && { isPublic }),
        ...(generator !== undefined && { generator }),
        ...(indexSchema !== undefined && { indexSchema })
      })
    },

    async importResource(handed: AppCollectionResource): Promise<SinkOutcome> {
      const { collectionId, resourceId, contentType } = handed
      const encrypted = encryptedById.get(collectionId) ?? true
      let snapshot = snapshots.get(collectionId)
      if (!snapshot) {
        snapshot = storage.snapshotAppCollection({ collectionId, encrypted })
        snapshots.set(collectionId, snapshot)
      }
      let held: HeldAppResources
      try {
        held = await snapshot
      } catch (err) {
        // Read again at the next Resource: one failed listing must not decide
        // every Resource behind it.
        snapshots.delete(collectionId)
        log.warn('Could not read an app collection before importing into it', {
          collectionId,
          err
        })
        return 'failed'
      }
      return await storage.importAppCollectionResource({
        collectionId,
        encrypted,
        resourceId,
        contentType,
        content:
          'bytes' in handed
            ? { bytes: handed.bytes }
            : { json: handed.json as Json },
        held
      })
    }
  }
}

/**
 * Builds the sink over the session's import methods, holding the per-run
 * state they cannot see: the held-content snapshot they all decide against
 * and keep current, what this run did with each archived contact head, and
 * which credentials the account already records a `Create` activity for.
 *
 * The snapshot is read at the first Resource that needs it, which the walk order
 * puts before any contact or activity write, so a re-run reads the same
 * `Create` set the first run did.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {MigrationSink}
 */
function migrationSink({ session }: { session: Session }): MigrationSink {
  const { storage } = session
  // What the import method answered for each archived contact head, as the
  // revisions that refer to it need to read it: `accepted` and `skipped` both
  // mean the head stands in the account under its archived `contactId`;
  // `seed-twin` means the account's own seeded contact stands for it and the
  // archived revisions, carrying the old account's identity, must not land;
  // `conflicting` means the id is held under different content; `failed`
  // means the write may be retried, and the revisions wait for that re-run.
  const headOutcomes = new Map<string, SinkOutcome | 'seed-twin'>()
  let snapshot: Promise<HeldContent> | undefined
  let heldCreatedCids: Set<string> | undefined

  /**
   * The run's held-content snapshot, read once.
   * @returns {Promise<HeldContent>}
   */
  function held(): Promise<HeldContent> {
    if (!snapshot) {
      snapshot = storage.snapshotHeldContent()
    }
    return snapshot
  }

  /**
   * The cids the account already records a credential `Create` activity for,
   * as the snapshot holds them: taken before this run writes any activity.
   * @returns {Promise<Set<string>>}
   */
  async function heldCreated(): Promise<Set<string>> {
    if (!heldCreatedCids) {
      heldCreatedCids = new Set<string>()
      for (const doc of (await held()).activities.values()) {
        const info = credentialActivityInfo(doc)
        if (info?.verb === 'created') {
          heldCreatedCids.add(info.cid)
        }
      }
    }
    return heldCreatedCids
  }

  return {
    ...(storage.canProvisionAppCollections && {
      appCollections: appCollectionsSink({ session })
    }),

    async importCredential({ json }): Promise<SinkOutcome> {
      return await storage.importCredential({
        credential: json as IVerifiableCredential
      })
    },

    async importContact({ json }): Promise<SinkOutcome> {
      const head = json as ContactHeadPayload
      const outcome = await storage.importContactHead({
        head,
        held: await held()
      })
      if (head.contactId) {
        headOutcomes.set(head.contactId, outcome)
      }
      // A seed twin is a skip to the walk: the account already stands for
      // the contact, and nothing was written.
      return outcome === 'seed-twin' ? 'skipped' : outcome
    },

    async importContactRevision({ json }): Promise<SinkOutcome> {
      const revision = json as ContactRevisionPayload
      const outcome = headOutcomes.get(revision.contactId)
      if (outcome === 'failed') {
        // The head may still land on a re-run, and its revisions land with it
        // then (nothing holds them yet). Reported skipped rather than failed,
        // so one head that would not write does not count its revisions
        // toward the walk's consecutive-failure stop and end the collection.
        return 'skipped'
      }
      if (outcome === 'conflicting' || outcome === 'seed-twin') {
        return 'skipped'
      }
      const content = await held()
      if (
        outcome === undefined &&
        !content.contactHeads.has(revision.contactId)
      ) {
        // An orphan: no head in the bundle and none in the account, so the
        // revision would be reachable through no contact at all.
        log.warn('Skipping an archived contact revision with no contact', {
          contactId: revision.contactId
        })
        return 'skipped'
      }
      return await storage.importContactRevision({ revision, held: content })
    },

    async importActivity({ json }): Promise<SinkOutcome> {
      const activity = json as WalletActivity
      const info = credentialActivityInfo(activity)
      if (!info) {
        // Everything else records an authority event on the old account --
        // a login, a grant, a revocation, a collection share -- whose subject
        // does not migrate.
        return 'skipped'
      }
      if (info.verb === 'created' && (await heldCreated()).has(info.cid)) {
        // The account already says when it got this credential; a second
        // creation at another date would read as two.
        return 'skipped'
      }
      return await storage.importActivity({ activity, held: await held() })
    }
  }
}

/**
 * The per-collection counts the Import activity carries: the three the
 * activity's shape names, plus the cause that ended a collection early.
 * `conflicting` and `unopenable` stay in the report the page renders.
 *
 * @param report {MigrationReport}
 * @returns {Record<string, ImportCollectionOutcome>}
 */
function importedCollections(
  report: MigrationReport
): Record<string, ImportCollectionOutcome> {
  const collections: Record<string, ImportCollectionOutcome> = {}
  for (const [collectionId, counts] of Object.entries(report.collections)) {
    collections[collectionId] = {
      accepted: counts.accepted,
      skipped: counts.skipped,
      failed: counts.failed,
      ...(counts.stoppedBy !== undefined && { stoppedBy: counts.stoppedBy })
    }
  }
  return collections
}

/**
 * Migrates a backup bundle's content into the session's account.
 *
 * The bundle and the secret travel straight into the walk. Nothing here
 * keeps either past the call: the secret is a parameter of this function and
 * of `migrateBundle` alone, and the walk zeroes what it derived from it when
 * it ends, whether it finished, was aborted, or threw.
 *
 * It refuses one thing of its own: a run started while another is still
 * running in this tab, with `ContentMigrationInProgressError`. A bundle that
 * cannot be opened, an archive with no account Space, and a secret that
 * opens nothing are the walk's refusals. All of them reach the caller as
 * thrown errors it maps through {@link contentMigrationErrorKey}. Past those,
 * every failure is a count in the returned report.
 *
 * Each call is one `content-migration` run on the ceremony event channel.
 * Its events carry counts and enums alone.
 *
 * @param options {object}
 * @param options.session {Session}   the account imported INTO
 * @param options.bundle {ByteSource}   the bundle tar's bytes, or a stream
 * @param options.secret {MigrationSecret}   the OLD account's passphrase,
 *   its recovery code, or the backup credential the bundle carries
 * @param [options.bundleBytes] {number}   the bundle's size, for the quota
 *   pre-check, when the caller knows it without draining a stream
 * @param [options.signal] {AbortSignal}   cancels between Resources; an aborted
 *   run writes no Import activity
 * @param [options.onProgress] {function}   called once per Resource with
 *   `{ collectionId, index, outcome }`
 * @returns {Promise<ContentMigrationResult>}
 */
export async function migrateContent({
  session,
  bundle,
  secret,
  bundleBytes,
  signal,
  onProgress
}: {
  session: Session
  bundle: ByteSource
  secret: MigrationSecret
  bundleBytes?: number
  signal?: AbortSignal
  onProgress?: (options: {
    collectionId: string
    index: number
    outcome: SinkOutcome | 'unopenable'
  }) => void
}): Promise<ContentMigrationResult> {
  const events = ceremonyEvents<ContentMigrationStage>({
    ceremony: 'content-migration',
    log,
    refusals: CONTENT_MIGRATION_REFUSALS
  })
  return await events.run(async () => {
    if (migrationRunning) {
      throw new ContentMigrationInProgressError()
    }
    migrationRunning = true
    try {
      return await runMigration({
        session,
        bundle,
        secret,
        bundleBytes,
        signal,
        onProgress,
        events
      })
    } finally {
      migrationRunning = false
    }
  }, migrationOutcomeEvent)
}

/**
 * The outcome event one returned migration maps to: `partial` when the walk
 * stopped early or left Resources unmigrated, `clean` otherwise. Detail is
 * totals across the collections: no collection name, bundle id, or other
 * bundle-supplied text.
 *
 * @param result {ContentMigrationResult}
 * @returns {{ outcome: CeremonyOutcome, detail: CeremonyDetail }}
 */
function migrationOutcomeEvent(result: ContentMigrationResult): {
  outcome: CeremonyOutcome
  detail: CeremonyDetail
} {
  const detail = migrationCounts(result.report)
  const stopped = result.report.stoppedAt !== undefined
  const unmigrated = detail.failed + detail.unopenable + detail.notMigrated
  return {
    outcome: stopped || unmigrated > 0 ? 'partial' : 'clean',
    detail: {
      ...detail,
      stopped,
      replicaInSync: result.replicaInSync,
      quotaWarning: result.quotaWarning !== undefined
    }
  }
}

/**
 * A walk report's totals across its collections, as event detail.
 *
 * @param report {MigrationReport}
 * @returns {object}   the totals, each a count
 */
function migrationCounts(report: MigrationReport): {
  collections: number
  accepted: number
  skipped: number
  conflicting: number
  failed: number
  unopenable: number
  notMigrated: number
} {
  const totals = {
    collections: 0,
    accepted: 0,
    skipped: 0,
    conflicting: 0,
    failed: 0,
    unopenable: 0,
    notMigrated: 0
  }
  for (const counts of Object.values(report.collections)) {
    totals.collections += 1
    totals.accepted += counts.accepted
    totals.skipped += counts.skipped
    totals.conflicting += counts.conflicting
    totals.failed += counts.failed
    totals.unopenable += counts.unopenable
  }
  for (const count of Object.values(report.notMigrated)) {
    totals.notMigrated += count
  }
  return totals
}

/**
 * The body of {@link migrateContent}, run once the single-run check has
 * passed.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.bundle {ByteSource}
 * @param options.secret {MigrationSecret}
 * @param [options.bundleBytes] {number}
 * @param [options.signal] {AbortSignal}
 * @param [options.onProgress] {function}
 * @returns {Promise<ContentMigrationResult>}
 */
async function runMigration({
  session,
  bundle,
  secret,
  bundleBytes,
  signal,
  onProgress,
  events
}: Parameters<typeof migrateContent>[0] & {
  events: CeremonyEmitter<ContentMigrationStage>
}): Promise<ContentMigrationResult> {
  // The login-time mender block can rotate the user key and rebuild every
  // cipher under a Resource in flight, so the walk waits it out. It never
  // rejects.
  await session.mends

  // The quota probe depends on neither the mender block nor replication, so
  // its round trip overlaps the sync wait below.
  const quotaProbe = quotaWarningFor({
    session,
    bundleBytes: bundleSizeOf({ bundle, bundleBytes })
  })

  let replicaInSync = true
  if (isRememberedSession(session)) {
    // Every merge check reads the session's own store, which on a remembered
    // session is the replica; deciding "the account already holds this"
    // against a replica that lags the remote would import a second copy.
    replicaInSync = await awaitCollectionsInSync({
      collectionIds: MIGRATION_WALK_ORDER.map(entry => entry.collectionId)
    })
    if (!replicaInSync) {
      log.warn(
        'Importing a bundle before replication settled: the merge checks ' +
          'read a replica that may lag the remote'
      )
    }
  }

  const quotaWarning = await quotaProbe
  if (quotaWarning) {
    log.warn('The bundle is larger than the Space has room for', {
      bundleBytes: quotaWarning.bundleBytes,
      freeBytes: quotaWarning.freeBytes
    })
  }
  events.stage('preflight', {
    replicaInSync,
    quotaWarning: quotaWarning !== undefined
  })

  const report = await migrateBundle({
    bundle,
    secret,
    sink: migrationSink({ session }),
    ...(signal !== undefined && { signal }),
    ...(onProgress !== undefined && { onProgress })
  })
  events.stage('walk', {
    ...migrationCounts(report),
    stopped: report.stoppedAt !== undefined
  })

  // The run record, written whenever the walk ended by its own rules (its
  // tail, a quota refusal, or a collection's consecutive-failure stop) and
  // never on an abort, which throws past this line. It replaces an earlier
  // run's Import activity for the same bundle rather than standing beside it.
  await session.storage.putHistoryItemReplacingOthers({
    activity: addHistoryContentImported({
      targetDid: targetDidOf(session),
      manifest: report.manifest,
      provenance: 'unverified',
      collections: importedCollections(report),
      ...(report.stoppedAt !== undefined && { stoppedAt: report.stoppedAt })
    })
  })
  events.stage('import-activity')

  return { report, quotaWarning, replicaInSync }
}

/**
 * Maps a migration failure to the i18n key its message lives under, in the
 * style of `src/session/loginErrorKey.ts`. The package's refusals are matched
 * by `err.name`: they are minted in another package, so `instanceof` would
 * silently miss a duplicated or linked copy.
 *
 * @param err {unknown}
 * @returns {string}   a `storage.migration.errors.*` key
 */
export function contentMigrationErrorKey(err: unknown): string {
  switch (errorNameOf(err)) {
    // The bundle is not a bundle: the outer tar will not read, its manifest
    // is unusable, or the archived user key roster is unreadable.
    case 'BundleInvalidError':
      return 'storage.migration.errors.bundleInvalid'
    // The bundle carries no account Space archive, which is where the user
    // key roster lives, so nothing in it can be opened.
    case 'AccountSpaceArchiveMissingError':
      return 'storage.migration.errors.accountArchiveMissing'
    // The secret opens nothing: the archived roster wraps no key to it. A
    // wrong passphrase or code, or a secret established after the export.
    case 'BundleRecipientMissingError':
      return 'storage.migration.errors.secretNotRecipient'
    // The user cancelled. The walk stops between Resources, so what landed stays.
    case 'AbortError':
      return 'storage.migration.errors.cancelled'
    // The Space is full. The walk itself stops on this and reports
    // `stoppedAt`; reaching here means the Import activity's own write was
    // refused.
    case 'QuotaExceededError':
      return 'storage.migration.errors.quotaExceeded'
    // Another run is still going in this tab.
    case 'ContentMigrationInProgressError':
      return 'storage.migration.errors.inProgress'
    default:
      log.error('Content migration failed', { err })
      return 'storage.migration.errors.failed'
  }
}
