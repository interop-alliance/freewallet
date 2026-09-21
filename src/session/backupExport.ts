/**
 * The backup-export ceremony: a recovery code minted into the account, then
 * every Space the account names exported and packed into one bundle file.
 *
 * `@interop/wallet-backup` owns the order -- the code first, then the Space
 * listing, then one export per Space, then the packing -- and this module
 * owns every effect it reaches for. The code is minted through the wallet's
 * own issuance ceremony, so the listing that follows already names the
 * code's unlock Space and the bundle carries the Space the packed code
 * opens. The code string is handed to the package and held nowhere else:
 * nothing here stores it, returns it, or logs it, and neither is the export
 * passphrase.
 *
 * The Spaces are the account Space, the client-annex Space, and one unlock
 * Space per entry of the unlock-methods registry (passphrase, passkey, and
 * every recovery code, the one just issued included). The client-annex Space
 * is the one the account document's `#DelegatedClients` pointer names, on
 * both branches. Only a document naming none skips that archive; a named
 * Space this session cannot reach refuses the run. Every export rides a
 * freshly minted POST-only child of the entry's management zcap: an enrolled
 * session signs that child with the stored zcap's own delegatee, and a
 * ladder-anchored one with the acting credential's ladder VM. The account and
 * annex Spaces answer to the session itself -- an enrolled session
 * root-invokes both, and a ladder-anchored one rides the generation
 * delegation on the account Space and the record's `delegatedClients`
 * delegation on the annex.
 *
 * The capability pre-flight runs FIRST, before the recovery code is minted: a
 * refusal there leaves no orphan "Backup <date>" code behind. It covers all
 * three capabilities the run needs -- the account Space's, the annex Space's,
 * and every registry entry's management zcap -- each checked for `POST`
 * locally. The code's own entry is minted with the full verb set, so it needs
 * no pre-check, and each export re-checks its own entry as it goes.
 *
 * The rule is fail-whole. A Space that cannot be exported -- an entry
 * recording no management zcap, one whose `allowedAction` carries no `POST`,
 * or a request the server refuses -- fails the whole export rather than
 * writing a bundle that reads as complete and is not. The same rule covers
 * the listing: a registry read back from the server that does not name the
 * code just issued, and a registry whose entries change while the Spaces are
 * being exported, both refuse rather than write a bundle whose contents no
 * single moment of the account ever had. It covers the account archive too:
 * its `did.jsonl` is read before the bundle is packed, and an archive not
 * carrying the log entry this visit pinned refuses. A visit holding no pin
 * for that log checks nothing and says so.
 *
 * The pivot is the code issuance, which is the ceremony's one durable write.
 * A run torn after that issuance has COMPLETED leaves an ordinary labeled
 * recovery code, listed and removable in Settings like any other, so the
 * mender is a re-run. A tear INSIDE the issuance is the issuance ceremony's
 * own torn state, not this one's: it is the open gap
 * `every-document-key-agreement-entry-has-a-locatable-credential`, where a
 * document `keyAgreement` entry and a roster wrap stand for a code nothing
 * can locate.
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
import { delegatedClientsDelegationSpaceId } from '@interop/wallet-core/clientAnnex'
import { errorNameOf } from '@interop/wallet-core/menders'
import { DID_LOG_RESOURCE, ID_COLLECTION } from '@interop/wallet-core/space'
import { accountLogPinId } from '@interop/wallet-core/webvh'
import { createLogger } from '@/lib/log'
import { causeChain } from '@/lib/storageErrors'
import {
  accountCeremonyContext,
  requireEnrolledCeremonyContext,
  type AccountCeremonyContext
} from '@/session/accountCeremonyContext'
import {
  canIssueRecoveryCode,
  generateRecoveryCode,
  issueRecoveryCode
} from '@/session/recovery'
import { pointedClientAnnexReach } from '@/session/annexReach'
import {
  getUnlockMethods,
  unlockSpaceCapabilityRefusal,
  unlockSpaceVerbInvocation,
  type UnlockMethod,
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
 * has no refresh path at all -- only the code's own unlock identity can
 * re-delegate it -- so the remedy there is to remove the code and issue a new
 * one.
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
 * Thrown when the registry the issuance wrote does not list the code the run
 * just issued (or the issuance recorded no registry at all). The bundle's
 * whole claim is that the file plus the packed code restores the account, and
 * a listing missing that code's unlock Space would not carry the Space the
 * code opens.
 */
export class BackupCodeNotListedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BackupCodeNotListedError'
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
 * be AHEAD of the pin -- this run's own code issuance appends an entry -- so
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
  stage: 'issuing-code' | 'exporting-space' | 'packing'
  index?: number
  total?: number
}

/**
 * Whether this session can produce a backup. It mints a recovery code, so it
 * needs everything the issuance needs, and it exports Spaces, so it needs a
 * remote backend: a guest and a no-WAS deployment are offered no backup.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {boolean}
 */
export function canExportBackup({ session }: { session: Session }): boolean {
  return canIssueRecoveryCode({ session }) && session.storage.hasRemoteStorage
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
 * The client-annex Space this run exports, resolved from the account document
 * on both branches: the `#DelegatedClients` pointer names the live generation,
 * and its Space is the only annex Space this account has. `undefined` means
 * the document names none, which is an ordinary state and skips the archive.
 *
 * The record's `delegatedClients` delegation is this session's REACH into that
 * Space on the ladder branch, not its name: a session holding none, or holding
 * one that targets some other Space, cannot export the annex the document
 * names, and refuses rather than writing a bundle that reads as complete. An
 * enrolled session root-invokes, so the pointer alone settles it.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}
 * @returns {Promise<string | undefined>}
 */
async function annexSpaceIdFor({
  session,
  context
}: {
  session: Session
  context: AccountCeremonyContext
}): Promise<string | undefined> {
  const reach = await pointedClientAnnexReach({
    session,
    pointer: context.pointer
  })
  if (!reach) {
    log.debug('The account names no client-annex Space; none is exported')
    return undefined
  }
  if (context.kind === 'enrolled') {
    return reach.spaceId
  }
  const sibling = context.sibling
  if (!sibling) {
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
  return reach.spaceId
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
 * BEFORE the recovery code is minted. A refusal here therefore leaves nothing
 * behind: no code, no entry, no Space. The code this run is about to issue is
 * minted with the full verb set, so it is not among the entries checked here.
 *
 * Three capabilities carry the run. The account Space answers to the
 * generation delegation on the ladder branch and to a root invocation on the
 * enrolled one; the client-annex Space answers to the record's
 * `delegatedClients` delegation and to a root invocation; each unlock Space
 * answers to a child of its entry's management zcap. All three are checked
 * for `POST` here, since a record sealed before the delegated-clients action
 * set carried `POST` passes every other check and is refused only by the
 * server, past the pivot, leaving one orphan "Backup <date>" code per retry.
 *
 * The annex Space id the pointer resolves to is handed back, so the listing
 * does not resolve it a second time.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}
 * @returns {Promise<{ annexSpaceId?: string }>}
 */
async function preflightBackupCapabilities({
  session,
  context
}: {
  session: Session
  context: AccountCeremonyContext
}): Promise<{ annexSpaceId?: string }> {
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
  const annexSpaceId = await annexSpaceIdFor({ session, context })
  const registry = await getUnlockMethods({ session })
  for (const entry of registry?.methods ?? []) {
    refuseUnexportableEntry({ session, context, entry })
  }
  return annexSpaceId ? { annexSpaceId } : {}
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
 * itself wrote (the code issuance appends one), so what is required is that
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
 * The tar pack the package hands back, as a web stream the save path can
 * pipe. The pack is an async iterable of chunks, pulled one at a time -- but
 * the bundle is already written and finalized by the time it arrives, with no
 * consumer attached while it was packed, so the whole thing is sitting in the
 * pack's queue and this stream drains it rather than producing it. Making the
 * writer stream is wallet-backup's WBU-5.
 *
 * @param options {object}
 * @param options.pack {AsyncIterable<Uint8Array>}
 * @returns {ReadableStream<Uint8Array>}
 */
function streamFromPack({
  pack
}: {
  pack: AsyncIterable<Uint8Array>
}): ReadableStream<Uint8Array> {
  const chunks = pack[Symbol.asyncIterator]()
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      const { done, value } = await chunks.next()
      if (done) {
        controller.close()
        return
      }
      controller.enqueue(value)
    },
    async cancel(reason) {
      await chunks.return?.(reason)
    }
  })
}

/**
 * Runs the export ceremony and hands back the bundle as a stream.
 *
 * The capability pre-flight runs before anything is minted, so a refusal
 * leaves no orphan code behind. The recovery code is minted next, so the
 * bundle is self-sufficient: the
 * file plus that code opens the account with nothing else. Every Space the
 * account names then follows, in the order the bundle lists them -- the
 * account Space, the client-annex Space, then one per unlock-methods
 * registry entry -- and any one of them failing fails the whole run.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.codeLabel {string}   the label the minted recovery code is
 *   listed under in Settings
 * @param [options.exportPassphrase] {string}   seals the packed code; without
 *   it the code travels in the clear and the file is a bearer credential
 * @param [options.signal] {AbortSignal}
 * @param [options.onProgress] {Function}
 * @returns {Promise<ReadableStream<Uint8Array>>}
 */
export async function exportBackup({
  session,
  codeLabel,
  exportPassphrase,
  signal,
  onProgress
}: {
  session: Session
  codeLabel: string
  exportPassphrase?: string
  signal?: AbortSignal
  onProgress?: (progress: BackupExportProgress) => void
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
    throw new Error('A backup export needs a remote Space to export.')
  }

  // Before the pivot: a capability this run cannot export under refuses here,
  // where nothing has been minted yet, rather than after the issuance has
  // left a "Backup <date>" code nothing wrote a bundle for.
  const { annexSpaceId } = await preflightBackupCapabilities({
    session,
    context
  })

  /**
   * The registry entries this run exports, by Space id, filled in by the
   * listing below so each export knows which entry it is exporting.
   */
  const unlockEntries = new Map<string, UnlockMethod>()
  /**
   * The Space ids in pack order, so a progress report can say which of how
   * many is being exported.
   */
  let spaceOrder: string[] = []
  /**
   * What the issuance recorded: the code's entry, and the registry as the
   * write that recorded it left it, which is what the listing reads.
   */
  let issued: Awaited<ReturnType<typeof issueRecoveryCode>> | undefined

  const pack = await exportBundle({
    meta: {
      created: new Date().toISOString(),
      createdBy: { controller: context.pointer.did, client: BACKUP_CLIENT }
    },
    issueRecoveryCode: async () => {
      const code = generateRecoveryCode()
      issued = await issueRecoveryCode({ session, code, label: codeLabel })
      return code
    },
    listSpaces: async () => {
      // The listing is read back from the server rather than taken from the
      // record the issuance's own write handed back: that record has the
      // entry appended to it in memory, so it names the code whatever the
      // server stored. The check that follows is therefore about what the
      // account now holds, and the settle read at the end is about the set
      // still being that one once the archives are in hand.
      const registry = await getUnlockMethods({ session })
      if (
        !registry ||
        !registry.methods.some(
          entry => entry.unlockSpaceId === issued?.entry.unlockSpaceId
        )
      ) {
        throw new BackupCodeNotListedError(
          'The unlock-methods registry does not list the recovery code this ' +
            'backup just issued, so the bundle would not carry the Space ' +
            'that code opens.'
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
      spaceOrder = spaces.map(space => space.spaceId)
      return spaces
    },
    exportSpace: async ({ spaceId, role }): Promise<ByteSource> => {
      try {
        if (role === BUNDLE_ROLE.accountSpaceArchive) {
          // Buffered whole so the log inside it can be read before it is
          // packed. The package buffers the pack anyway, so this holds no
          // more in memory than the run already did.
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
      const position = spaceId ? spaceOrder.indexOf(spaceId) : -1
      onProgress?.({
        stage,
        ...(position >= 0 ? { index: position + 1 } : {}),
        ...(spaceOrder.length ? { total: spaceOrder.length } : {})
      })
    }
  })

  // The export is a walk, not a snapshot: each Space is read at its own
  // moment, and nothing on the server holds the set still. So the registry is
  // read once more now that every archive is in hand, and a set of unlock
  // Spaces that differs from the listed one fails the run under the same
  // fail-whole rule -- a credential added mid-run would be missing from the
  // bundle, and one removed would be in it after its Space was gone. The
  // check sits here rather than inside the last export because the pack is
  // buffered whole: nothing has been handed to the caller yet.
  await settledRegistry({ session, listed: unlockEntries })

  // tar-stream's `Pack` is a stream of chunks typed `unknown`; every one is
  // a `Uint8Array`, which the pack's own writers guarantee.
  return streamFromPack({ pack: pack as AsyncIterable<Uint8Array> })
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
 * re-minted by a login with that credential, while a recovery code's has no
 * refresh path and the remedy is to remove the code and issue another.
 * {@link backupExportErrorLabel} carries the entry's own label for those
 * keys.
 *
 * @param err {unknown}
 * @returns {string}
 */
export function backupExportErrorKey(err: unknown): string {
  const names = errorNameChain(err)
  // The user cancelled. The code, if it was already minted, stands.
  if (backupExportCancelled(err)) {
    return 'storage.backup.errors.cancelled'
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
  // The registry does not name the code this run just issued.
  if (names.includes('BackupCodeNotListedError')) {
    return 'storage.backup.errors.codeNotListed'
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
