/**
 * The backup-export ceremony: a backup credential established into the
 * account, then every Space the account names exported and packed into one
 * bundle file.
 *
 * `@interop/wallet-backup` owns the order -- the credential first, then the
 * Space listing, then one export per Space, then the packing -- and this
 * module owns every effect it reaches for. The credential is a standing
 * unlock credential (`backupCredential.ts`), established the way a passkey
 * registration is, from 32 random bytes the bundle packs, so the listing
 * that follows already names the credential's unlock Space and the bundle
 * carries the Space its secret opens. A restore is then the ordinary
 * transient login on that credential's record: nothing retired, no key
 * rotated. The secret is handed to the package and held nowhere else:
 * nothing here stores it, returns it, or logs it, and neither is the export
 * passphrase.
 *
 * The Spaces are the account Space, the client-annex Space, and one unlock
 * Space per entry of the unlock-methods registry (passphrase, passkey, every
 * recovery code, and every backup credential, the one just established
 * included). The client-annex Space is the one the account document's
 * `#DelegatedClients` pointer names, on both branches. Only a document
 * naming none skips that archive; a named Space this session cannot reach
 * refuses the run. Every export rides a freshly minted POST-only child of
 * the entry's management zcap: an enrolled session signs that child with the
 * stored zcap's own delegatee, and a ladder-anchored one with the acting
 * credential's ladder VM. The account and annex Spaces answer to the session
 * itself -- an enrolled session root-invokes both, and a ladder-anchored one
 * rides the generation delegation on the account Space and the record's
 * `delegatedClients` delegation on the annex.
 *
 * The capability pre-flight runs FIRST, before the credential is
 * established: a refusal there leaves no orphan "Backup <date>" row behind.
 * It covers all three capabilities the run needs -- the account Space's, the
 * annex Space's, and every registry entry's management zcap -- each checked
 * for `POST` locally, and one more condition: a session that cannot commit
 * the new credential's rung into the pointed annex generation (an enrolled
 * session holding no ladder seed) refuses here, since a bundle written
 * anyway would restore an account whose first login loses every grant. The
 * credential's own entry is minted with the full verb set, so it needs no
 * pre-check, and each export re-checks its own entry as it goes.
 *
 * The rule is fail-whole. A Space that cannot be exported -- an entry
 * recording no management zcap, one whose `allowedAction` carries no `POST`,
 * or a request the server refuses -- fails the whole export rather than
 * writing a bundle that reads as complete and is not. The same rule covers
 * the listing: a registry read back from the server that does not name the
 * credential just established, and a registry whose entries change while
 * the Spaces are being exported, both refuse rather than write a bundle
 * whose contents no single moment of the account ever had. It covers the
 * account archive too: its `did.jsonl` is read before the bundle is packed,
 * and an archive not carrying the log entry this visit pinned refuses. A
 * visit holding no pin for that log checks nothing and says so.
 *
 * The pivot is the credential's establishment, the ceremony's one durable
 * write. A run torn after it has COMPLETED leaves an ordinary labeled backup
 * credential, listed and removable under Settings > Backup credentials like
 * any other, so the mender is a re-run. A tear INSIDE it leaves the registry
 * entry its entry-first write recorded, whose Remove converges whatever the
 * establishment reached (`backupCredential.ts`).
 */
import { BUNDLE_ROLE, exportBundle } from '@interop/wallet-backup'
import type { ByteSource } from '@interop/wallet-backup'
import {
  collectBytes,
  parseArchivePath,
  parseResourceFileName,
  readSpaceArchive
} from '@interop/space-archive'
import type { IZcap } from '@interop/data-integrity-core'
import {
  clientAnnexRungAdmitted,
  delegatedClientsDelegationSpaceId
} from '@interop/wallet-core/clientAnnex'
import { errorNameOf } from '@interop/wallet-core/menders'
import { ceremonyEvents } from '@interop/wallet-core'
import type { CeremonyEmitter } from '@interop/wallet-core'
import { DID_LOG_RESOURCE, ID_COLLECTION } from '@interop/wallet-core/space'
import { accountLogPinId } from '@interop/wallet-core/webvh'
import { createLogger } from '@/lib/log'
import { causeChain } from '@/lib/storageErrors'
import {
  accountCeremonyContext,
  canRunUserKeyCeremonies,
  requireEnrolledCeremonyContext,
  type AccountCeremonyContext
} from '@/session/accountCeremonyContext'
import {
  BackupAnnexCommitError,
  establishBackupCredential
} from '@/session/backupCredential'
import { wasServiceDescription } from '@/lib/wasService'
import {
  pointedClientAnnexReach,
  standingClientAnnexReachOf,
  type ClientAnnexReach
} from '@/session/annexReach'
import {
  getUnlockMethods,
  unlockSpaceCapabilityRefusal,
  unlockSpaceVerbInvocation,
  type UnlockMethod,
  type UnlockMethodsRecord,
  type UnlockSpaceCapabilityRefusal
} from '@/session/unlockMethods'
import type { Session } from '@/types/auth'

const log = createLogger('fw:session:backup')

/**
 * The wallet named in every bundle's manifest, as the profile's `createdBy`
 * client: a name and the project's own URL, no version (the server's travels
 * in each per-Space archive, and a restore needs no wallet version).
 */
const BACKUP_CLIENT = {
  name: 'freewallet',
  url: 'https://github.com/interop-alliance/freewallet'
}

/**
 * A capability refusal: which unlock method it is about, carried on the
 * error so the dialog can name it and say what refreshes it. A passphrase
 * entry carries no label, so only its kind is reported. The two concrete
 * refusals below differ only in name.
 */
export class BackupCapabilityError extends Error {
  readonly entryType?: UnlockMethod['type']
  readonly entryLabel?: string

  constructor(
    message: string,
    entry: { entryType?: UnlockMethod['type']; entryLabel?: string } = {}
  ) {
    super(message)
    this.name = 'BackupCapabilityError'
    this.entryType = entry.entryType
    this.entryLabel = entry.entryLabel
  }
}

/**
 * Thrown when a registry entry records no management zcap at all, so nothing
 * can be minted to export its unlock Space.
 */
export class BackupCapabilityMissingError extends BackupCapabilityError {
  constructor(...args: ConstructorParameters<typeof BackupCapabilityError>) {
    super(...args)
    this.name = 'BackupCapabilityMissingError'
  }
}

/**
 * Thrown when a recorded management zcap cannot carry this export: it allows
 * no `POST`, it has expired, or it names a target or a delegatee this session
 * cannot act through.
 *
 * What refreshes such a zcap depends on the entry. A passphrase's and a
 * passkey's are re-minted by a login with that credential. A recovery code's
 * and a backup credential's have no refresh path from Settings -- only their
 * own unlock identity can re-delegate -- so the remedy there is to remove the
 * entry and export or issue again.
 */
export class BackupCapabilityUnsupportedError extends BackupCapabilityError {
  constructor(...args: ConstructorParameters<typeof BackupCapabilityError>) {
    super(...args)
    this.name = 'BackupCapabilityUnsupportedError'
  }
}

/**
 * The refusal one entry's pre-flight outcome maps to: a missing zcap is its
 * own refusal, and every other outcome is a zcap that cannot carry the
 * export.
 *
 * @param options {object}
 * @param options.entry {UnlockMethod}
 * @param options.refusal {UnlockSpaceCapabilityRefusal}
 * @returns {BackupCapabilityError}
 */
function backupCapabilityRefusal({
  entry,
  refusal
}: {
  entry: UnlockMethod
  refusal: UnlockSpaceCapabilityRefusal
}): BackupCapabilityError {
  const named = {
    entryType: entry.type,
    ...('label' in entry && entry.label ? { entryLabel: entry.label } : {})
  }
  if (refusal === 'no-capability') {
    return new BackupCapabilityMissingError(
      `The unlock method "${entry.type}" records no management capability, ` +
        'so its Space cannot be exported.',
      named
    )
  }
  return new BackupCapabilityUnsupportedError(
    `The unlock method "${entry.type}" cannot be exported (${refusal}).`,
    named
  )
}

/**
 * Thrown when the session has no remote account Space, so there is nothing
 * to export. A precondition refusal: it fires before anything is minted.
 */
export class BackupRemoteStorageMissingError extends Error {
  constructor() {
    super('A backup export needs a remote Space to export.')
    this.name = 'BackupRemoteStorageMissingError'
  }
}

/**
 * The export's stage ids for the ceremony event channel, in run order. The
 * last two fire as the caller reads the stream: once every Space's archive
 * is in hand, and once the registry settle check has passed.
 */
export const BACKUP_EXPORT_STAGES = [
  'preflight',
  'establish-credential',
  'list-spaces',
  'export-spaces',
  'settle'
] as const

/**
 * One value of {@link BACKUP_EXPORT_STAGES}.
 */
export type BackupExportStage = (typeof BACKUP_EXPORT_STAGES)[number]

/**
 * The pre-flight errors a run classifies as `refused` on the event channel.
 * Both capability refusals are named, since matching is by `err.name`. A
 * throw once the establishment has begun, or once the stream has started, is
 * `failed` whatever its name, except the user's cancel, which is `refused`.
 */
const BACKUP_EXPORT_REFUSALS: ReadonlyArray<string> = [
  'BackupCapabilityMissingError',
  'BackupCapabilityUnsupportedError',
  'BackupAnnexCommitError',
  'BackupRemoteStorageMissingError'
]

/**
 * Thrown when the registry read back after the establishment does not list
 * the credential the run just established. The bundle's whole claim is that
 * the file plus its packed secret restores the account, and a listing missing
 * that credential's unlock Space would not carry the Space the secret opens.
 */
export class BackupCredentialNotListedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BackupCredentialNotListedError'
  }
}

/**
 * Thrown when the unlock-methods registry names a different set of unlock
 * Spaces once the exports are done than it did when they were listed: a
 * credential was added or removed while the run was under way.
 */
export class BackupRegistryChangedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BackupRegistryChangedError'
  }
}

/**
 * Thrown when the account Space's archive does not carry the account log this
 * visit verified: its `did.jsonl` holds no entry with the pinned head's
 * `versionId`, or it carries no `did.jsonl` at all. The archive may legitimately
 * be AHEAD of the pin -- this run's own establishment appends an entry -- so
 * what is required is that the pinned entry is somewhere in the archived chain.
 * An archive that is not is a different log, and a bundle built on it would
 * restore an account this visit never saw.
 */
export class BackupContinuityError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BackupContinuityError'
  }
}

/**
 * Thrown when one Space's export request itself failed. The package wraps it
 * again with the Space it happened on, so both survive in the cause chain.
 */
export class BackupSpaceExportError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'BackupSpaceExportError'
  }
}

/**
 * What the ceremony reports as it runs: the stage, and for an export the
 * Space's place in the listing so a dialog can say "Space 2 of 5".
 */
export interface BackupExportProgress {
  stage: 'establishing-credential' | 'exporting-space' | 'packing'
  index?: number
  total?: number
}

/**
 * Whether this session can produce a backup. It establishes a standing
 * credential, so it needs an account-ceremony context and the user key, and
 * it exports Spaces, so it needs a remote backend: a guest and a no-WAS
 * deployment are offered no backup.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {boolean}
 */
export function canExportBackup({ session }: { session: Session }): boolean {
  return (
    canRunUserKeyCeremonies({ session }) && session.storage.hasRemoteStorage
  )
}

/**
 * Whether a capability carries a verb. A capability with no `allowedAction`,
 * or an empty one, delegates every action; the same reading
 * `unlockSpaceCapabilityRefusal` makes of a stored management zcap.
 *
 * @param options {object}
 * @param [options.capability] {IZcap}
 * @param options.verb {string}
 * @returns {boolean}
 */
function zcapAllowsVerb({
  capability,
  verb
}: {
  capability?: IZcap
  verb: string
}): boolean {
  const allowed = (capability as { allowedAction?: unknown } | undefined)
    ?.allowedAction
  if (allowed === undefined) {
    return true
  }
  const actions = Array.isArray(allowed) ? allowed : [allowed]
  return actions.length === 0 || actions.includes(verb)
}

/**
 * The client-annex generation this run exports and commits into, resolved
 * from the account document on both branches: the `#DelegatedClients` pointer
 * names the live generation, and its Space is the only annex Space this
 * account has. `undefined` means the document names none, which is an
 * ordinary state and skips the archive and the commit.
 *
 * The record's `delegatedClients` delegation is this session's REACH into that
 * Space on the ladder branch, not its name: a session holding none, or holding
 * one that targets some other Space, cannot export the annex the document
 * names, and refuses rather than writing a bundle that reads as complete. An
 * enrolled session root-invokes, so the pointer alone settles it. The reach
 * handed back reads the generation's log the way this session may: the
 * standing client under the sibling delegation on the ladder branch, the root
 * key on the enrolled one.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}
 * @returns {Promise<ClientAnnexReach | undefined>}
 */
async function pointedAnnexFor({
  session,
  context
}: {
  session: Session
  context: AccountCeremonyContext
}): Promise<ClientAnnexReach | undefined> {
  const reach = await pointedClientAnnexReach({
    session,
    pointer: context.pointer
  })
  if (!reach) {
    log.debug('The account names no client-annex Space; none is exported')
    return undefined
  }
  if (context.kind === 'enrolled') {
    return reach
  }
  const sibling = context.sibling
  const standingClient = session.profile.standingUnlock?.standingClient
  if (!sibling || !standingClient) {
    throw new BackupCapabilityMissingError(
      'This session holds no delegation into the client-annex Space, so ' +
        'its archive cannot be exported.'
    )
  }
  if (
    delegatedClientsDelegationSpaceId({ delegation: sibling }) !== reach.spaceId
  ) {
    throw new BackupCapabilityUnsupportedError(
      "This session's delegation names a different client-annex Space than " +
        'the account document points at, so that Space cannot be exported.'
    )
  }
  if (!zcapAllowsVerb({ capability: sibling, verb: 'POST' })) {
    throw new BackupCapabilityUnsupportedError(
      "This session's delegation into the client-annex Space carries no " +
        'POST, so that Space cannot be exported.'
    )
  }
  return standingClientAnnexReachOf({
    pointer: context.pointer,
    clientAnnexDid: reach.clientAnnexDid,
    standing: { standingClient, delegatedClients: sibling },
    pinStore: session.persistence.logPins,
    serviceDescription: await wasServiceDescription()
  })
}

/**
 * Exports the client-annex Space: a root invocation on an enrolled session,
 * and on a ladder-anchored one the record's `delegatedClients` delegation,
 * sent by the credential's own standing client (the annex Space answers to
 * the account did:webvh, which a per-visit key is not). The pre-flight has
 * already settled that the delegation stands and reaches the Space the
 * account document points at, so the refusal below covers the standing client
 * alone.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}
 * @param options.spaceId {string}
 * @param [options.signal] {AbortSignal}
 * @returns {Promise<ReadableStream<Uint8Array>>}
 */
async function exportAnnexSpace({
  session,
  context,
  spaceId,
  signal
}: {
  session: Session
  context: AccountCeremonyContext
  spaceId: string
  signal?: AbortSignal
}): Promise<ReadableStream<Uint8Array>> {
  const { remoteStore } = context
  if (context.kind === 'enrolled') {
    return await remoteStore.exportSpace({
      spaceId,
      zcapClient: session.profile.zcapClient,
      ...(signal ? { signal } : {})
    })
  }
  const sibling = context.sibling
  const standingClient = session.profile.standingUnlock?.standingClient
  if (!sibling || !standingClient) {
    throw new BackupCapabilityMissingError(
      'This session holds no delegation into the client-annex Space, so ' +
        'its archive cannot be exported.'
    )
  }
  return await remoteStore.exportSpace({
    spaceId,
    zcapClient: standingClient.agents.zcapClient,
    capability: sibling,
    ...(signal ? { signal } : {})
  })
}

/**
 * The read-only pre-flight of one entry's export: refuses when the entry
 * records no management zcap or when the recorded one cannot carry a `POST`.
 * It mints nothing and sends nothing, so a refusal is this ceremony's own
 * rather than a server 404 the ceremony reads as a Space failure.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}
 * @param options.entry {UnlockMethod}
 * @returns {void}
 */
function refuseUnexportableEntry({
  session,
  context,
  entry
}: {
  session: Session
  context: AccountCeremonyContext
  entry: UnlockMethod
}): void {
  const refusal = unlockSpaceCapabilityRefusal({
    session,
    entry,
    ...(context.kind === 'ladder' ? { signer: context.ladderDeleter } : {}),
    verb: 'POST'
  })
  if (refusal) {
    throw backupCapabilityRefusal({ entry, refusal })
  }
}

/**
 * Runs the capability pre-flight over every Space this run will export,
 * BEFORE the backup credential is established. A refusal here therefore
 * leaves nothing behind: no credential, no entry, no Space. The credential
 * this run is about to establish is minted with the full verb set, so it is
 * not among the entries checked here.
 *
 * Three capabilities carry the run. The account Space answers to the
 * generation delegation on the ladder branch and to a root invocation on the
 * enrolled one; the client-annex Space answers to the record's
 * `delegatedClients` delegation and to a root invocation; each unlock Space
 * answers to a child of its entry's management zcap. All three are checked
 * for `POST` here, since a record sealed before the delegated-clients action
 * set carried `POST` passes every other check and is refused only by the
 * server, past the pivot, leaving one orphan "Backup <date>" row per retry.
 *
 * One more condition rides the annex: the establishment must commit the new
 * credential's rung into the pointed generation, signed by this session's
 * own ladder rung. Two sessions cannot: an enrolled one whose record sealed
 * no ladder seed (the commit's honest skip), and one whose rung the pointed
 * generation neither reveals nor commits (the mid-generation lockout). Both
 * are read-only questions, so both are refused here rather than after the
 * roster wrap and the record are written and the cleanup has to retire them.
 *
 * The pointed generation and the registry are handed back -- the
 * generation's Space id for the listing and its DID for the establishment,
 * the registry as the establishment's base -- so neither is read a second
 * time: the generation the establishment commits into is the one this
 * pre-flight checked the session's rung against. The annex questions and
 * the registry read are independent, so they go out together.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}
 * @returns {Promise<{ annex?: ClientAnnexReach, registry: UnlockMethodsRecord | null }>}
 */
async function preflightBackupCapabilities({
  session,
  context
}: {
  session: Session
  context: AccountCeremonyContext
}): Promise<{
  annex?: ClientAnnexReach
  registry: UnlockMethodsRecord | null
}> {
  if (context.kind === 'ladder') {
    const generation = session.profile.invocationCapability
    if (!generation) {
      throw new BackupCapabilityMissingError(
        'This session holds no delegation on the account Space, so it ' +
          'cannot be exported.'
      )
    }
    if (!zcapAllowsVerb({ capability: generation, verb: 'POST' })) {
      throw new BackupCapabilityUnsupportedError(
        "This session's delegation on the account Space carries no POST, " +
          'so it cannot be exported.'
      )
    }
  }
  const [annex, registry] = await Promise.all([
    committableAnnexFor({ session, context }),
    getUnlockMethods({ session })
  ])
  for (const entry of registry?.methods ?? []) {
    refuseUnexportableEntry({ session, context, entry })
  }
  return { ...(annex ? { annex } : {}), registry }
}

/**
 * The pointed client-annex generation, refused unless this session can
 * commit the new credential's rung into it: the pre-flight's annex half.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}
 * @returns {Promise<ClientAnnexReach | undefined>}   `undefined` when the
 *   document names no generation
 * @throws {BackupAnnexCommitError}   this session cannot commit into it
 */
async function committableAnnexFor({
  session,
  context
}: {
  session: Session
  context: AccountCeremonyContext
}): Promise<ClientAnnexReach | undefined> {
  const annex = await pointedAnnexFor({ session, context })
  if (!annex) {
    return undefined
  }
  const ladderSeed = session.profile.ladderSeed
  if (!ladderSeed) {
    throw new BackupAnnexCommitError({ reason: 'no-ladder-seed' })
  }
  if (
    !(await clientAnnexRungAdmitted({
      store: annex.logStore(),
      ladderSeed,
      generationId: annex.generationId,
      expectedDid: annex.clientAnnexDid
    }))
  ) {
    throw new BackupAnnexCommitError({ reason: 'rung-uncommitted' })
  }
  return annex
}

/**
 * The `versionId`s of every entry in the account archive's `did.jsonl`, in
 * archive order, or `undefined` when the archive carries none. The walk stops
 * at the log entry, so the rest of the archive stays unread.
 *
 * @param options {object}
 * @param options.archive {Uint8Array}   the account Space's archive bytes
 * @returns {Promise<string[] | undefined>}
 */
async function archivedAccountLogVersions({
  archive
}: {
  archive: Uint8Array
}): Promise<string[] | undefined> {
  const opened = await readSpaceArchive(archive)
  try {
    for await (const entry of opened.entries) {
      const path = parseArchivePath(entry.name)
      if (
        path.area !== 'collection' ||
        path.collectionId !== ID_COLLECTION.id
      ) {
        continue
      }
      const { resourceId } = parseResourceFileName(path.fileName)
      if (resourceId !== DID_LOG_RESOURCE) {
        continue
      }
      const text = new TextDecoder().decode(await entry.bytes())
      return text
        .split('\n')
        .filter(line => line.trim() !== '')
        .map(line => {
          const parsed = JSON.parse(line) as { versionId?: unknown }
          return typeof parsed.versionId === 'string' ? parsed.versionId : ''
        })
    }
  } finally {
    await opened.close()
  }
  return undefined
}

/**
 * Checks the account Space's archive against this visit's chain-head pin for
 * the account log. Every other archive is accepted as whatever bytes the host
 * returns; this one is the account's identity, so it is read back before it is
 * packed.
 *
 * The archive may legitimately be ahead of the pin, by the entries this run
 * itself wrote (the establishment appends one), so what is required is that
 * the pinned entry appears in the archived chain rather than that it is the
 * tail. A visit holding no pin for this log checks nothing: nothing was read
 * under a pin this visit, so there is no continuity to compare against.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.spaceId {string}   the account Space
 * @param options.archive {Uint8Array}
 * @returns {Promise<void>}
 */
async function refuseForkedAccountArchive({
  session,
  spaceId,
  archive
}: {
  session: Session
  spaceId: string
  archive: Uint8Array
}): Promise<void> {
  const pin = await session.persistence.logPins.read({
    logId: accountLogPinId({ spaceId })
  })
  if (!pin) {
    log.warn(
      'No chain-head pin is held for the account log this visit, so the ' +
        'exported archive is not checked against one'
    )
    return
  }
  const versions = await archivedAccountLogVersions({ archive })
  if (!versions) {
    throw new BackupContinuityError(
      'The exported account archive carries no account log, so the bundle ' +
        'would not restore this account.'
    )
  }
  if (!versions.includes(pin.head)) {
    throw new BackupContinuityError(
      'The exported account archive does not carry the account log this ' +
        'session verified, so the bundle would restore a different account ' +
        'history.'
    )
  }
}

/**
 * Exports one sibling unlock Space through a freshly minted POST-only child
 * of the entry's management zcap, the same mint the deletion walk's DELETE
 * rides (`unlockSpaceVerbInvocation`): an enrolled session signs that child
 * with the stored zcap's own delegatee and sends it as that delegatee, and a
 * ladder-anchored one signs with the acting credential's ladder VM and sends
 * it as that VM's own bare did:key. The mint re-runs the pre-flight over the
 * stored zcap, which the run as a whole already ran before it minted
 * anything.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}
 * @param options.entry {UnlockMethod}
 * @param [options.signal] {AbortSignal}
 * @returns {Promise<ReadableStream<Uint8Array>>}
 */
async function exportUnlockSpace({
  session,
  context,
  entry,
  signal
}: {
  session: Session
  context: AccountCeremonyContext
  entry: UnlockMethod
  signal?: AbortSignal
}): Promise<ReadableStream<Uint8Array>> {
  const invocation = await unlockSpaceVerbInvocation({
    session,
    entry,
    ...(context.kind === 'ladder' ? { signer: context.ladderDeleter } : {}),
    verb: 'POST'
  })
  if (typeof invocation === 'string') {
    throw backupCapabilityRefusal({ entry, refusal: invocation })
  }
  return await context.remoteStore.exportSpace({
    spaceId: entry.unlockSpaceId,
    ...invocation,
    ...(signal ? { signal } : {})
  })
}

/**
 * Runs the export ceremony and hands back the bundle as a stream.
 *
 * The capability pre-flight runs before anything is minted, so a refusal
 * leaves no orphan credential behind. The backup credential is established
 * next, so the bundle is self-sufficient: the file plus its packed secret
 * carries everything a restore login on the credential's record needs.
 * Every Space the account names then
 * follows, in the order the bundle lists them -- the account Space, the
 * client-annex Space, then one per unlock-methods registry entry -- and any
 * one of them failing fails the whole run.
 *
 * The stream is handed back once the Spaces are listed. The Space exports run
 * as the caller reads it, so a failure from then on (a refused export, the
 * registry settle check, a cancel) errors the stream rather than rejecting
 * this call.
 *
 * Each call is one `backup-export` run on the ceremony event channel. Its
 * outcome fires where the run ends: at a rejection of this call, or when
 * the returned stream closes, errors, or is cancelled. Detail is counts and
 * booleans alone.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.credentialLabel {string}   the label the backup credential
 *   is listed under in Settings
 * @param [options.exportPassphrase] {string}   seals the packed secret;
 *   without it the secret travels in the clear and the file is a bearer
 *   credential
 * @param [options.signal] {AbortSignal}
 * @param [options.onProgress] {Function}
 * @returns {Promise<ReadableStream<Uint8Array>>}
 */
export async function exportBackup({
  session,
  credentialLabel,
  exportPassphrase,
  signal,
  onProgress
}: {
  session: Session
  credentialLabel: string
  exportPassphrase?: string
  signal?: AbortSignal
  onProgress?: (progress: BackupExportProgress) => void
}): Promise<ReadableStream<Uint8Array>> {
  const events = ceremonyEvents<BackupExportStage>({
    ceremony: 'backup-export',
    log
  })
  // `committing` is set once the establishment begins: from there on nothing
  // is a pre-flight refusal, whatever its name. `spaceOrder` is the listed
  // Space ids in pack order.
  const progress = { committing: false, spaceOrder: [] as string[] }
  let stream: ReadableStream<Uint8Array>
  try {
    stream = await runBackupExport({
      session,
      credentialLabel,
      exportPassphrase,
      signal,
      onProgress,
      events,
      progress
    })
  } catch (err) {
    failOutcome({ events, err, preflight: !progress.committing })
    throw err
  }
  return observedExportStream({
    stream,
    events,
    detail: () => ({
      spaces: progress.spaceOrder.length,
      sealed: exportPassphrase !== undefined
    })
  })
}

/**
 * Emits a run's outcome for a throw, a stream error, or a stream cancel:
 * `refused` for the user's cancel (an `AbortError` anywhere in the cause
 * chain) and for a pre-flight refusal, `failed` for anything else.
 *
 * @param options {object}
 * @param options.events {CeremonyEmitter}
 * @param options.err {unknown}   the thrown value or the cancel reason
 * @param [options.preflight] {boolean}   true while the run is still before
 *   the establishment, so a named pre-flight refusal classifies as `refused`
 */
function failOutcome({
  events,
  err,
  preflight = false
}: {
  events: CeremonyEmitter<BackupExportStage>
  err: unknown
  preflight?: boolean
}): void {
  const refused =
    backupExportCancelled(err) ||
    (preflight && BACKUP_EXPORT_REFUSALS.includes(errorNameOf(err)))
  events.outcome(refused ? 'refused' : 'failed', undefined, err)
}

/**
 * Passes the bundle stream through unchanged and emits the run's outcome
 * where the run ends: `clean` when the stream closes, `refused` when the
 * user cancelled (an `AbortError` anywhere in the cause chain), and `failed`
 * for any other error or cancel, since by then the stream has started.
 *
 * @param options {object}
 * @param options.stream {ReadableStream<Uint8Array>}
 * @param options.events {CeremonyEmitter}
 * @param options.detail {Function}   the clean outcome's counts, read at the
 *   close
 * @returns {ReadableStream<Uint8Array>}
 */
function observedExportStream({
  stream,
  events,
  detail
}: {
  stream: ReadableStream<Uint8Array>
  events: CeremonyEmitter<BackupExportStage>
  detail: () => { spaces: number; sealed: boolean }
}): ReadableStream<Uint8Array> {
  const reader = stream.getReader()
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      let chunk: ReadableStreamReadResult<Uint8Array>
      try {
        chunk = await reader.read()
      } catch (err) {
        failOutcome({ events, err })
        controller.error(err)
        return
      }
      if (chunk.done) {
        events.outcome('clean', detail())
        controller.close()
        return
      }
      controller.enqueue(chunk.value)
    },
    async cancel(reason) {
      failOutcome({ events, err: reason })
      await reader.cancel(reason)
    }
  })
}

/**
 * The body of {@link exportBackup}, with the run's emitter and the progress
 * the outcome reads.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.credentialLabel {string}
 * @param [options.exportPassphrase] {string}
 * @param [options.signal] {AbortSignal}
 * @param [options.onProgress] {Function}
 * @param options.events {CeremonyEmitter}
 * @param options.progress {object}   `committing` once the establishment
 *   begins, and the listed Space ids in pack order
 * @returns {Promise<ReadableStream<Uint8Array>>}
 */
async function runBackupExport({
  session,
  credentialLabel,
  exportPassphrase,
  signal,
  onProgress,
  events,
  progress
}: {
  session: Session
  credentialLabel: string
  exportPassphrase?: string
  signal?: AbortSignal
  onProgress?: (progress: BackupExportProgress) => void
  events: CeremonyEmitter<BackupExportStage>
  progress: { committing: boolean; spaceOrder: string[] }
}): Promise<ReadableStream<Uint8Array>> {
  // The registry passes and the mender block both rewrite what this run
  // reads (the unlock-methods registry, the roster, the annex pointer), so
  // the ceremony waits them out rather than racing them. Neither rejects.
  await session.registryReady
  await session.mends

  const context =
    (await accountCeremonyContext({ session })) ??
    requireEnrolledCeremonyContext({ session, action: 'Exporting a backup' })

  const accountSpaceId = session.storage.spaceId
  if (!accountSpaceId) {
    throw new BackupRemoteStorageMissingError()
  }

  // Before the pivot: a capability this run cannot export under refuses here,
  // where nothing has been minted yet, rather than after the establishment
  // has left a "Backup <date>" credential nothing wrote a bundle for.
  const { annex, registry } = await preflightBackupCapabilities({
    session,
    context
  })
  const annexSpaceId = annex?.spaceId
  events.stage('preflight', {
    annex: annexSpaceId !== undefined,
    unlockMethods: registry?.methods.length ?? 0
  })

  /**
   * The registry entries this run exports, by Space id, filled in by the
   * listing below so each export knows which entry it is exporting.
   */
  const unlockEntries = new Map<string, UnlockMethod>()
  /**
   * The unlock Space id of the credential the establishment recorded, which
   * the listing checks the registry for.
   */
  let establishedSpaceId: string | undefined

  return await exportBundle({
    meta: {
      created: new Date().toISOString(),
      createdBy: { controller: context.pointer.did, client: BACKUP_CLIENT }
    },
    establishBackupCredential: async () => {
      progress.committing = true
      const established = await establishBackupCredential({
        session,
        context,
        label: credentialLabel,
        clientAnnexDid: annex?.clientAnnexDid ?? null,
        registry
      })
      establishedSpaceId = established.unlockSpaceId
      events.stage('establish-credential')
      return established.secret
    },
    listSpaces: async () => {
      // The listing is read back from the server rather than taken from the
      // record the establishment's own writes handed back, so the check that
      // follows is about what the account now holds, and the settle read at
      // the end is about the set still being that one once the archives are
      // in hand.
      const registry = await getUnlockMethods({ session })
      if (
        !registry ||
        !registry.methods.some(
          entry => entry.unlockSpaceId === establishedSpaceId
        )
      ) {
        throw new BackupCredentialNotListedError(
          'The unlock-methods registry does not list the backup credential ' +
            'this backup just established, so the bundle would not carry ' +
            'the Space its secret opens.'
        )
      }
      const spaces: Array<{ spaceId: string; role: string }> = [
        { spaceId: accountSpaceId, role: BUNDLE_ROLE.accountSpaceArchive }
      ]
      if (annexSpaceId) {
        spaces.push({
          spaceId: annexSpaceId,
          role: BUNDLE_ROLE.clientAnnexSpaceArchive
        })
      }
      for (const entry of registry.methods) {
        unlockEntries.set(entry.unlockSpaceId, entry)
        spaces.push({
          spaceId: entry.unlockSpaceId,
          role: BUNDLE_ROLE.unlockSpaceArchive
        })
      }
      // The Space ids in pack order, so a progress report can say which of
      // how many is being exported.
      progress.spaceOrder = spaces.map(space => space.spaceId)
      events.stage('list-spaces', { spaces: spaces.length })
      return spaces
    },
    exportSpace: async ({ spaceId, role }): Promise<ByteSource> => {
      try {
        if (role === BUNDLE_ROLE.accountSpaceArchive) {
          // Buffered whole so the log inside it can be read before it is
          // packed. The package collects each archive whole before writing
          // its entry anyway, so this holds no more in memory than it does.
          const archive = await collectBytes(
            await context.remoteStore.exportSpace({
              ...(signal ? { signal } : {})
            })
          )
          await refuseForkedAccountArchive({
            session,
            spaceId: accountSpaceId,
            archive
          })
          return archive
        }
        if (role === BUNDLE_ROLE.clientAnnexSpaceArchive) {
          return await exportAnnexSpace({
            session,
            context,
            spaceId,
            ...(signal ? { signal } : {})
          })
        }
        const entry = unlockEntries.get(spaceId)
        if (!entry) {
          throw new BackupCapabilityMissingError(
            `No unlock method names the Space "${spaceId}".`
          )
        }
        return await exportUnlockSpace({
          session,
          context,
          entry,
          ...(signal ? { signal } : {})
        })
      } catch (err) {
        if (
          err instanceof BackupCapabilityError ||
          err instanceof BackupContinuityError ||
          backupExportCancelled(err)
        ) {
          throw err
        }
        throw new BackupSpaceExportError(
          `The storage server refused to export the Space "${spaceId}".`,
          { cause: err }
        )
      }
    },
    ...(exportPassphrase ? { exportPassphrase } : {}),
    ...(signal ? { signal } : {}),
    onProgress: ({ stage, spaceId }) => {
      const { spaceOrder } = progress
      const position = spaceId ? spaceOrder.indexOf(spaceId) : -1
      onProgress?.({
        stage,
        ...(position >= 0 ? { index: position + 1 } : {}),
        ...(spaceOrder.length ? { total: spaceOrder.length } : {})
      })
    },
    // The export is a walk, not a snapshot: each Space is read at its own
    // moment, and nothing on the server holds the set still. So the registry
    // is read once more when every archive is in hand, and a set of unlock
    // Spaces that differs from the listed one fails the run under the same
    // fail-whole rule -- a credential added mid-run would be missing from the
    // bundle, and one removed would be in it after its Space was gone. The
    // package runs this before the bundle's last entry is written, so a
    // refusal errors the stream rather than ending a saved file as complete.
    settle: async () => {
      events.stage('export-spaces', { spaces: progress.spaceOrder.length })
      await settledRegistry({ session, listed: unlockEntries })
      events.stage('settle')
    }
  })
}

/**
 * Re-reads the unlock-methods registry once the exports are done and refuses
 * when its set of unlock Spaces differs from the one this run listed.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.listed {Map<string, UnlockMethod>}   the entries the listing
 *   exported, keyed by unlock Space id
 * @returns {Promise<void>}
 */
async function settledRegistry({
  session,
  listed
}: {
  session: Session
  listed: Map<string, UnlockMethod>
}): Promise<void> {
  const registry = await getUnlockMethods({ session })
  const current = new Set(
    (registry?.methods ?? []).map(entry => entry.unlockSpaceId)
  )
  const added = [...current].filter(spaceId => !listed.has(spaceId))
  const removed = [...listed.keys()].filter(spaceId => !current.has(spaceId))
  if (added.length === 0 && removed.length === 0) {
    return
  }
  log.warn("The account's unlock methods changed during the export", {
    added: added.length,
    removed: removed.length
  })
  throw new BackupRegistryChangedError(
    "This account's unlock methods changed while the backup was being " +
      'written, so the bundle would not match any one state of the account.'
  )
}

/**
 * The i18n key one failure renders as. The package wraps a Space export
 * failure with the Space it happened on, so the chain is walked rather than
 * just the outermost error, and the first match in this order wins.
 *
 * The two capability refusals resolve to a key per unlock-method kind, since
 * what refreshes the zcap differs: a passphrase's and a passkey's are
 * re-minted by a login with that credential, while a recovery code's and a
 * backup credential's have no refresh path from Settings and the remedy is
 * to remove the entry and issue or export again.
 * {@link backupExportErrorLabel} carries the entry's own label for those
 * keys.
 *
 * @param err {unknown}
 * @returns {string}
 */
export function backupExportErrorKey(err: unknown): string {
  const names = errorNameChain(err)
  // The user cancelled. The credential, if it was already established,
  // stands.
  if (backupExportCancelled(err)) {
    return 'storage.backup.errors.cancelled'
  }
  // This session cannot commit the credential's rung into the annex: its
  // record sealed no ladder seed, or the generation does not admit its rung.
  // The remedy differs, so the copy is keyed on the refusal's reason.
  const annexRefusal = [...causeChain(err)].find(
    current => errorNameOf(current) === 'BackupAnnexCommitError'
  ) as { reason?: string } | undefined
  if (annexRefusal) {
    return annexRefusal.reason === 'no-ladder-seed'
      ? 'storage.backup.errors.annexCommit.noLadderSeed'
      : 'storage.backup.errors.annexCommit.rungUncommitted'
  }
  // The establishment failed, after its cleanup.
  if (names.includes('BackupCredentialNotEstablishedError')) {
    return 'storage.backup.errors.notEstablished'
  }
  // An unlock method records no management zcap at all.
  if (names.includes('BackupCapabilityMissingError')) {
    return `storage.backup.errors.missingCapability.${refusedVariant(err)}`
  }
  // A management zcap that carries no `POST`, has expired, or names a
  // delegatee this session cannot act through.
  if (names.includes('BackupCapabilityUnsupportedError')) {
    return `storage.backup.errors.unsupportedCapability.${refusedVariant(err)}`
  }
  // The registry does not name the credential this run just established.
  if (names.includes('BackupCredentialNotListedError')) {
    return 'storage.backup.errors.credentialNotListed'
  }
  // The exported account archive is not the log this visit verified.
  if (names.includes('BackupContinuityError')) {
    return 'storage.backup.errors.continuity'
  }
  // A credential was added or removed while the export ran.
  if (names.includes('BackupRegistryChangedError')) {
    return 'storage.backup.errors.registryChanged'
  }
  // One Space's export request failed, which fails the whole bundle.
  if (names.includes('BackupSpaceExportError')) {
    return 'storage.backup.errors.spaceExportFailed'
  }
  // The listing named no account Space, so there would be nothing to read
  // the bundle back with.
  if (names.includes('AccountSpaceArchiveMissingError')) {
    return 'storage.backup.errors.accountSpaceMissing'
  }
  log.error('The backup export failed', { err })
  return 'storage.backup.errors.failed'
}

/**
 * The label of the unlock method a capability refusal is about, for the
 * message that names it. Absent for a passphrase, which carries none, and for
 * a refusal about no entry at all.
 *
 * @param err {unknown}
 * @returns {string | undefined}
 */
export function backupExportErrorLabel(err: unknown): string | undefined {
  return capabilityRefusalIn(err)?.entryLabel
}

/**
 * Which message a capability refusal renders: one per unlock-method kind,
 * plus `generic` for a refusal that names no entry (the client-annex
 * delegation, or a listed Space no entry claims).
 *
 * @param err {unknown}
 * @returns {string}
 */
function refusedVariant(err: unknown): string {
  switch (capabilityRefusalIn(err)?.entryType) {
    case 'recovery-code':
      return 'recoveryCode'
    case 'passkey':
      return 'passkey'
    case 'passphrase':
      return 'passphrase'
    case 'backup-credential':
      return 'backupCredential'
    default:
      return 'generic'
  }
}

/**
 * The first capability refusal in a cause chain, which is where the entry's
 * kind and label are carried.
 *
 * @param err {unknown}
 * @returns {BackupCapabilityError | undefined}
 */
function capabilityRefusalIn(err: unknown): BackupCapabilityError | undefined {
  for (const current of causeChain(err)) {
    if (current instanceof BackupCapabilityError) {
      return current
    }
  }
  return undefined
}

/**
 * Whether a failure is the user's own cancel. The cancel is re-wrapped on its
 * way out -- by this module's Space-export wrap, and by the package's own --
 * so the whole cause chain is read rather than the outermost error alone. A
 * cancelled run is not logged as an error anywhere.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function backupExportCancelled(err: unknown): boolean {
  return errorNameChain(err).includes('AbortError')
}

/**
 * Every error name in a cause chain, outermost first. Bounded, so a cyclic
 * `cause` cannot spin.
 *
 * @param err {unknown}
 * @returns {string[]}
 */
function errorNameChain(err: unknown): string[] {
  return [...causeChain(err)].map(errorNameOf)
}
