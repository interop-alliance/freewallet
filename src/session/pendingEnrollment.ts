/**
 * The pending-enrollment resume: what a durable login does with a
 * PENDING-shape client-key record (`userKey` absent) -- one a
 * self-enrollment's persist-before-publish hook wrote and a tab death left
 * uncompleted. The record is the resume's only key set, so the
 * forgotten-browser detector deliberately spares it (freewallet
 * `decisions/0007`); this module decides, from the VERIFIED account-log
 * HISTORY, which of four outcomes the record gets:
 *
 * - **complete** (the VM stands in the current document): finish the
 *   enrollment -- the core's resume mode completes the roster escrow through
 *   the credential's standing wrap, the record gains its user key and drops
 *   `pending`, and the login proceeds enrolled.
 * - **seeded re-run** (the VM was never published): re-run the enrollment
 *   with the recorded key set, so the resumed run publishes the same client
 *   the torn run was publishing -- never a second mint.
 * - **wipe** (the VM was published at an earlier version and since removed):
 *   this client was deliberately disconnected; the detector's wipe and
 *   `BrowserForgottenError` apply exactly as for an enrolled record, and a
 *   revoked client is never re-published or re-escrowed.
 * - **discard** (a seeded re-run is impossible: the credential carries no
 *   standing authority, or the record's `pointerDid` no longer matches the
 *   MAC-authenticated pointer): the record is deleted -- the one lifecycle
 *   flow beyond the unlock-method ceremonies allowed to delete a client-key
 *   record, bounded to verified inputs and decided last, after the complete,
 *   wipe, and seeded re-run branches are ruled out -- and the next login
 *   routes as a record-less browser (the transient default, with
 *   `rememberBrowser: false` no longer refusing).
 *
 * Everything else is FAIL-CLOSED: a resume that cannot run, or that throws
 * outside the named refusal classes, surfaces the typed
 * `PendingEnrollmentError` rather than falling through to ordinary session
 * construction, which would run a userKey-less record on seed-derived vault
 * keys with every encrypted collection failing closed and no error. A
 * transport failure or a continuity refusal at any branch rethrows unchanged
 * (record kept, retried later) -- never a discard, never a wipe.
 */
import { agentsFromSeed } from '@interop/wallet-core/identity'
import {
  clientSigningKeyMultibase,
  isWebvhDid,
  verifyAccountLog
} from '@interop/wallet-core/webvh'
import type { ClientKeyRecord } from '@interop/wallet-core/keys'
import { deleteClientKeyRecord, sessionLogPinStore } from '@/lib/sessionKey'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { finishForgottenBrowserWipe } from '@/session/forget'
import { selfEnrollStandingClient } from '@/session/standingUnlock'
import type {
  KeyringFetchResult,
  PersistableClientKeys
} from '@/session/keyring'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:resume')

/**
 * Why a pending record's login was refused rather than resumed. `popup` is
 * the remote-direct (CHAPI popup) guard -- a popup never resumes;
 * `recovery-spend` is a spend-written record whose seeded re-run belongs to
 * `/recover` with the same code; `unresumable` is a record missing what the
 * completion needs while its client stands published (discarding it would
 * strand a phantom); `resume-failed` wraps any unclassified throw out of the
 * resume itself.
 */
export type PendingEnrollmentRefusalReason =
  'popup' | 'recovery-spend' | 'unresumable' | 'resume-failed'

/**
 * The fail-closed refusal of a pending-record login: the resume could not
 * run, or could not finish, and a pending record must never reach ordinary
 * session construction. The record is kept; a later login retries.
 */
export class PendingEnrollmentError extends Error {
  reason: PendingEnrollmentRefusalReason

  constructor({
    reason,
    message,
    cause
  }: {
    reason: PendingEnrollmentRefusalReason
    message?: string
    cause?: unknown
  }) {
    super(
      message ??
        `This browser's pending wallet connection could not be resumed (${reason}).`,
      { cause }
    )
    this.name = 'PendingEnrollmentError'
    this.reason = reason
  }
}

/**
 * The discard outcome: the pending record was deleted (a provably worthless
 * pre-pivot key set -- it grants nothing) and this browser routes as
 * record-less from the next login attempt on, restoring the transient
 * default and un-wedging `rememberBrowser: false`.
 */
export class PendingEnrollmentDiscardedError extends Error {
  constructor({ cause }: { cause?: unknown } = {}) {
    super(
      "This browser's pending wallet connection was dropped; the next login " +
        'proceeds as a new browser.',
      { cause }
    )
    this.name = 'PendingEnrollmentDiscardedError'
  }
}

/**
 * The transport state of the resume's account-log read: the fetch failed or
 * the served response was unusable for reasons short of a refusal (wallet-
 * core's `verifyAccountLog` throws a plain `TypeError` on a network failure
 * and a plain `Error` on a server fault, which `isStorageUnreachable` does
 * not recognize). No branch is decidable, so nothing is decided, deleted, or
 * wiped: the record is kept and a later login retries. Surfaces as the
 * existing storage-unreachable login state.
 */
export class PendingResumeLogUnavailableError extends Error {
  constructor({ cause }: { cause?: unknown } = {}) {
    super(
      'The account log could not be fetched to decide the pending-record ' +
        'resume; the record is kept and a later login retries.',
      { cause }
    )
    this.name = 'PendingResumeLogUnavailableError'
  }
}

/**
 * The refusal classes the fail-closed wrapper passes through unchanged: each
 * already has its own login surface (`loginErrorKey`), and re-wrapping one
 * would relabel a meaningful state as a generic resume failure.
 */
const PASSTHROUGH_ERROR_NAMES = new Set([
  'ResourceLogContinuityError',
  'ResourceLogIntegrityError',
  'UserKeyRosterContinuityError',
  'UserKeyRosterIntegrityError',
  'UserKeyRosterUnwrapError',
  'LadderAttributionError',
  'BrowserForgottenError',
  'BuiltOnHeadNotReachedError',
  'SelfEnrollmentSkewError',
  'PendingEnrollmentError',
  'PendingEnrollmentDiscardedError',
  'PendingResumeLogUnavailableError'
])

/**
 * Whether a keyring hit routes to the pending-enrollment resume: this client
 * holds a record under the credential, the account is promoted (only the
 * verified log can decide the resume's branch), and the record has no
 * `userKey` -- the pending discriminator (design question 2 as amended
 * 2026-08-24: a record WITH a user key routes enrolled whatever its other
 * members, so `pointerDid` is the resume's cross-check, not a routing
 * member, and a record predating it never loses the offline start).
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}
 * @returns {boolean}
 */
export function isPendingKeyringHit({
  found
}: {
  found: KeyringFetchResult
}): boolean {
  return !!(
    found.clientKeys &&
    !found.clientKeys.userKey &&
    found.pointer &&
    isWebvhDid(found.pointer.did)
  )
}

/**
 * Resumes (or otherwise disposes of) a pending-shape client-key record at
 * login, per the module doc's four outcomes. Throws for every non-completing
 * outcome; the completing ones return the enrolled key set and its persist
 * closure, exactly as `selfEnrollStandingClient` does, so the login proceeds
 * as an ordinary enrolled login (sweeps included) and the ladder-rung
 * refresh fires as it does after a fresh enrollment.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   a hit `isPendingKeyringHit`
 *   accepted
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<object>}   the completed key set and its persist closure
 */
export async function resumePendingEnrollment({
  found,
  idb
}: {
  found: KeyringFetchResult
  idb?: IDBFactory
}): Promise<{
  clientKeys: ClientKeyRecord
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
}> {
  try {
    return await decidePendingResume({ found, idb })
  } catch (err) {
    if (
      isStorageUnreachable(err) ||
      PASSTHROUGH_ERROR_NAMES.has((err as { name?: string } | null)?.name ?? '')
    ) {
      throw err
    }
    throw new PendingEnrollmentError({ reason: 'resume-failed', cause: err })
  }
}

/**
 * The branch decision itself, over the verified log history. Split out so the
 * fail-closed wrapper above stays one try/catch.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<object>}
 */
async function decidePendingResume({
  found,
  idb
}: {
  found: KeyringFetchResult
  idb?: IDBFactory
}): Promise<{
  clientKeys: ClientKeyRecord
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
}> {
  const clientKeys = found.clientKeys!
  const pointer = found.pointer!
  const pointerDid = pointer.did
  if (!pointerDid) {
    // The routing gate requires a promoted pointer; a hit without one can
    // only reach here through a caller bug, and is refused fail-closed.
    throw new PendingEnrollmentError({ reason: 'unresumable' })
  }
  // A spend-written record is /recover's to finish with the same code, on
  // EVERY branch: freewallet has no spend completion machinery until FW-317
  // lands, and completing it here would clear the pending members (the
  // unwrap-key carrier, the replacement-code bytes) whose whole purpose is
  // post-pivot re-derivability.
  if (clientKeys.pending?.ceremony === 'recovery-spend') {
    throw new PendingEnrollmentError({ reason: 'recovery-spend' })
  }
  // Every branch below is decided from THIS verified read: a continuity or
  // integrity refusal rethrows unchanged (through the wrapper's
  // passthrough), a transport failure surfaces as the storage-unreachable
  // state, and in both cases nothing is decided, deleted, or wiped.
  let verified: Awaited<ReturnType<typeof verifyAccountLog>>
  try {
    verified = await verifyAccountLog({
      did: pointerDid,
      spaceId: pointer.spaceId,
      host: pointer.host,
      pinStore: sessionLogPinStore({ idb })
    })
  } catch (err) {
    if (
      isStorageUnreachable(err) ||
      PASSTHROUGH_ERROR_NAMES.has((err as { name?: string } | null)?.name ?? '')
    ) {
      throw err
    }
    throw new PendingResumeLogUnavailableError({ cause: err })
  }
  const { keyAgent } = await agentsFromSeed({ seed: clientKeys.clientSeed })
  const clientDid = keyAgent.id
  const vmId = `${pointerDid}#${clientSigningKeyMultibase({ keyAgent })}`

  if (docListsVm({ doc: verified.doc, vmId })) {
    // The add entry landed; only the completion is missing.
    log.info('Pending-record resume: completing through the ceremony', {
      branch: 'complete',
      clientDid
    })
    return await resumeThroughCeremony({ found, idb })
  }

  if (logEverListedVm({ log: verified.log, vmId })) {
    // Published at an earlier version and since removed: this client was
    // deliberately disconnected (the unlabeled row's Disconnect, or a forget
    // from another client). The detector's wipe applies -- re-running the
    // enrollment here would silently reverse a revocation.
    log.info('Pending-record resume: client was removed; finishing the wipe', {
      branch: 'wipe',
      clientDid
    })
    return await finishForgottenBrowserWipe({ found, clientDid, idb })
  }

  // Never published. The two discard signals are decided here, LAST, after
  // the complete and wipe branches are ruled out (`decisions/0007`). A
  // record bound for another account than the one the (MAC-authenticated)
  // pointer now names cannot enter the pointed account, and a seeded re-run
  // with it would publish a foreign key set there.
  if (clientKeys.pointerDid && clientKeys.pointerDid !== pointerDid) {
    return await discardPendingRecord({
      found,
      idb,
      why: 'the recorded account pointer DID no longer matches the credential'
    })
  }
  const resumable = !!(
    found.standing?.ladderSeed &&
    found.standingClient &&
    found.persistClientKeys &&
    clientKeys.pending?.builtOnHead &&
    clientKeys.webvhUpdateKeys
  )
  if (!resumable) {
    return await discardPendingRecord({
      found,
      idb,
      why: 'the credential carries no standing authority to re-run with'
    })
  }
  log.info('Pending-record resume: seeded re-run of the enrollment', {
    branch: 'seeded-rerun',
    clientDid
  })
  return await resumeThroughCeremony({ found, idb })
}

/**
 * Runs the ceremony's resume mode over the record's replayed members. A
 * record missing any of them while its client stands published is refused
 * fail-closed (kept, never discarded: deleting it would strand a phantom the
 * document lists).
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<object>}
 */
async function resumeThroughCeremony({
  found,
  idb
}: {
  found: KeyringFetchResult
  idb?: IDBFactory
}): Promise<{
  clientKeys: ClientKeyRecord
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
}> {
  const clientKeys = found.clientKeys!
  const pending = clientKeys.pending
  if (
    !pending ||
    pending.ceremony !== 'self-enrollment' ||
    !clientKeys.webvhUpdateKeys
  ) {
    throw new PendingEnrollmentError({ reason: 'unresumable' })
  }
  return await selfEnrollStandingClient({
    found,
    idb,
    resume: {
      clientSeed: clientKeys.clientSeed,
      webvhUpdateKeys: clientKeys.webvhUpdateKeys,
      builtOnHead: pending.builtOnHead
    }
  })
}

/**
 * The discard outcome: deletes the pending record and throws the typed
 * discard error. Reached only on verified inputs and only in the
 * never-published branch, after the complete and wipe branches are ruled
 * out (`decisions/0007`'s discard-last ordering) -- a pre-pivot
 * pending key set grants nothing, and keeping it would wedge the browser
 * (durable refused, transient unreachable, the `rememberBrowser: false`
 * refusal answering with the wrong copy).
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}
 * @param [options.idb] {IDBFactory}
 * @param options.why {string}   the log-facing reason
 * @returns {Promise<never>}
 */
async function discardPendingRecord({
  found,
  idb,
  why
}: {
  found: KeyringFetchResult
  idb?: IDBFactory
  why: string
}): Promise<never> {
  log.warn('Discarding the pending client-key record', {
    branch: 'discard',
    why,
    unlockSpaceId: found.unlockSpaceId
  })
  await deleteClientKeyRecord({ spaceId: found.unlockSpaceId, idb })
  throw new PendingEnrollmentDiscardedError()
}

/**
 * Whether the current document lists the verification method.
 *
 * @param options {object}
 * @param options.doc {unknown}
 * @param options.vmId {string}
 * @returns {boolean}
 */
function docListsVm({ doc, vmId }: { doc: unknown; vmId: string }): boolean {
  const methods = (doc as { verificationMethod?: unknown } | null)
    ?.verificationMethod
  return (
    Array.isArray(methods) &&
    methods.some(method => (method as { id?: string })?.id === vmId)
  )
}

/**
 * Whether ANY version of the log ever listed the verification method -- the
 * published-then-removed test the document head alone cannot answer.
 *
 * @param options {object}
 * @param options.log {Array<{ state?: unknown }>}
 * @param options.vmId {string}
 * @returns {boolean}
 */
function logEverListedVm({
  log: entries,
  vmId
}: {
  log: Array<{ state?: unknown }>
  vmId: string
}): boolean {
  return entries.some(entry => docListsVm({ doc: entry.state, vmId }))
}
