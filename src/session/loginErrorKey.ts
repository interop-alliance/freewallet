/**
 * The login failure to i18n key mapping shared by every passphrase or
 * passkey login surface: the login page's two handlers, and the request
 * page's in-page login (`src/pages/external/ExternalRequestPage.tsx`). Each
 * arm logs what warrants it and returns the `auth.errors.*` key the surface
 * renders.
 */
import {
  KeyringRecordForgedError,
  KeyringRecordRolledBackError,
  KeyringRecordUnusableError
} from '@/session/keyring'
import { TransientLoginUnavailableError } from '@/session/transientLogin'
import type { TransientLoginUnavailableReason } from '@/session/transientLogin'
import {
  PendingEnrollmentDiscardedError,
  PendingEnrollmentError,
  PendingResumeLogUnavailableError
} from '@/session/pendingEnrollment'
import { SelfEnrollmentSkewError } from '@/session/standingUnlock'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:login')

/**
 * The `name` of a thrown value, if it carries one.
 *
 * The wallet-core refusals below are matched on `err.name` rather than
 * `instanceof`: they are raised inside app-injected seams, and the copy of
 * `@interop/wallet-core` that raised them can differ from the copy this file
 * imports (a linked checkout, or a duplicate through the dependency tree), so
 * an `instanceof` check would silently miss the refusal and fall through to
 * the generic setup-failed arm. Errors defined in this app keep `instanceof`.
 *
 * @param err {unknown}
 * @returns {unknown}
 */
function errorName(err: unknown): unknown {
  return (err as { name?: unknown } | null)?.name
}

/**
 * Maps a login failure to the i18n key its message lives under, logging the
 * arms that warrant it. Shared by the passphrase and the passkey handler,
 * which differ only in their log label and in the side effects they add on
 * top of the returned key.
 *
 * @param options {object}
 * @param options.err {unknown}   the caught failure
 * @param options.label {string}   the log prefix ("Login", "Passkey login")
 * @returns {object} the `auth.errors.*` key, plus the transient-login
 *   refusal's typed reason when that is what failed, so a caller can gate
 *   affordances on the reason rather than on string equality against a key.
 */
export function loginErrorKey({
  err,
  label
}: {
  err: unknown
  label: string
}): { key: string; transientReason?: TransientLoginUnavailableReason } {
  // The WAS storage server is unreachable -- offer a guest-mode fallback.
  if (isStorageUnreachable(err)) {
    return { key: 'auth.errors.storageUnreachable' }
  }
  // A resumed self-enrollment was served an account log that has not reached
  // the head its pending record was built on -- possibly nothing worse than
  // replication lag, so it surfaces as the transport state: the record is
  // kept and a later retry resumes.
  if (errorName(err) === 'BuiltOnHeadNotReachedError') {
    log.warn('Login deferred: the served log lags the recorded head', {
      label,
      err
    })
    return { key: 'auth.errors.storageUnreachable' }
  }
  // The resume's account-log read failed short of a refusal (a network
  // failure or server fault the fetch surfaced as a plain error): no branch
  // was decidable, the record is kept, and a later retry resumes -- the
  // transport state, not the pending refusal.
  if (err instanceof PendingResumeLogUnavailableError) {
    log.warn('Login deferred: the account log could not be fetched', {
      label,
      err
    })
    return { key: 'auth.errors.storageUnreachable' }
  }
  // The build-skew refusal: the self-enrollment core could not state that
  // its persist hook fired (a stale wallet-core build under new app code).
  // The key set was persisted before the refusal, so the browser IS
  // connected; the login is refused rather than trusted.
  if (err instanceof SelfEnrollmentSkewError) {
    log.error('Login refused: self-enrollment build skew', { label, err })
    return { key: 'auth.errors.selfEnrollmentSkew' }
  }
  // The authenticity refusal: the record's proof was not made by the key the
  // typed secret derives, so the storage host forged or tampered with it.
  if (err instanceof KeyringRecordForgedError) {
    log.error('Login refused: keyring record forged', { label, err })
    return { key: 'auth.errors.keyringForged' }
  }
  // The replay refusal: a validly signed record, but older than the newest
  // this browser has accepted for the secret.
  if (err instanceof KeyringRecordRolledBackError) {
    log.error('Login refused: keyring record rolled back', { label, err })
    return { key: 'auth.errors.keyringRolledBack' }
  }
  // The account-log continuity refusal: the served did:webvh log is a
  // rollback, a fork, or an identity switch against the chain head this
  // browser has pinned.
  if (errorName(err) === 'ResourceLogContinuityError') {
    log.error('Login refused: account log continuity violation', {
      label,
      err
    })
    return { key: 'auth.errors.accountLogContinuity' }
  }
  // The rollback refusal: the served key roster sits behind the epoch this
  // browser has already seen.
  if (errorName(err) === 'UserKeyRosterContinuityError') {
    log.error('Login refused: user key roster continuity violation', {
      label,
      err
    })
    return { key: 'auth.errors.userKeyRosterContinuity' }
  }
  // The served key roster failed authentication -- a fabricated or tampered
  // epoch configuration.
  if (errorName(err) === 'UserKeyRosterIntegrityError') {
    log.error('Login refused: user key roster integrity violation', {
      label,
      err
    })
    return { key: 'auth.errors.userKeyRosterIntegrity' }
  }
  // A torn enrollment: this browser's key is published for the account, but
  // the key roster holds no wrap for it, so the session cannot recover the
  // account key.
  if (errorName(err) === 'UserKeyRosterUnwrapError') {
    log.error('Login failed: user key roster unwrap error', { label, err })
    return { key: 'auth.errors.userKeyRosterUnwrap' }
  }
  // The self-enrolling login's fail-closed attribution refusal: the
  // published log commits no rung of this credential's update-key ladder (a
  // revoked or retired credential), or more than one (an ambiguous state
  // self-enrollment must not guess through).
  if (errorName(err) === 'LadderAttributionError') {
    log.error('Login refused: ladder attribution error', { label, err })
    return { key: 'auth.errors.ladderAttribution' }
  }
  // The finish-the-wipe detector's outcome: this browser's client entry was
  // removed from the account (a forget torn before its wipe, or a disconnect
  // from another client) and the local residue has just been cleared.
  if (errorName(err) === 'BrowserForgottenError') {
    // Both wipe reports ride the error: what failed, and what was deleted
    // without confirmation on a browser that cannot enumerate its
    // databases. The user-facing copy is the same either way (the account
    // is gone from here); the distinction is for the log.
    log.warn('Login: this browser was forgotten', { label, err })
    return { key: 'auth.errors.browserForgotten' }
  }
  // The pending-record discard: a provably worthless pre-pivot key set was
  // dropped, and the next login proceeds as a new browser (the transient
  // default; `rememberBrowser: false` no longer refuses).
  if (err instanceof PendingEnrollmentDiscardedError) {
    log.warn('Login: pending wallet connection discarded', { label, err })
    return { key: 'auth.errors.pendingEnrollmentDiscarded' }
  }
  // The pending-record fail-closed refusal: a resume that could not run (or
  // threw) keeps the record and refuses the login rather than constructing a
  // fail-open session over a userKey-less record. A spend-written record's
  // seeded re-run gets its own copy, directing back to /recover.
  if (err instanceof PendingEnrollmentError) {
    log.error('Login refused: pending enrollment could not be resumed', {
      label,
      reason: err.reason,
      err
    })
    return {
      key:
        err.reason === 'recovery-spend'
          ? 'auth.errors.pendingRecoveryResume'
          : 'auth.errors.pendingEnrollment'
    }
  }
  // A keyring record was found but is corrupt -- not a server outage and not
  // a wrong passphrase; surface it with recovery guidance.
  if (err instanceof KeyringRecordUnusableError) {
    log.error('Login failed: keyring record unusable', { label, err })
    return { key: 'auth.errors.keyringUnusable' }
  }
  // The transient login refused before any ceremony byte was written. Each
  // reason gets its own copy (the class sort in
  // `_spec/transient-refusal-considerations.md`); none offers connecting
  // this browser from a second client as the way out.
  if (err instanceof TransientLoginUnavailableError) {
    log.error('Login unavailable transiently', { label, err })
    return {
      key: transientRefusalKey(err.reason),
      transientReason: err.reason
    }
  }
  log.error('Login failed', { label, err })
  return { key: 'auth.errors.setupFailed' }
}

/**
 * The i18n key for one transient-login refusal reason. Exported for the CHAPI
 * popup's own error mapping (`mapPopupLoginError`), which reaches the same
 * refusals now that a record-less popup routes transient: the reason-to-copy
 * decision stays in one place rather than being restated per surface. The
 * copy is affordance-free by construction (no reason opens the
 * connect-this-browser card), so it reads correctly in a popup that has no
 * such card to offer.
 *
 * @param reason {TransientLoginUnavailableReason}
 * @returns {string}
 */
export function transientRefusalKey(
  reason: TransientLoginUnavailableReason
): string {
  switch (reason) {
    // A failed heal: both states are tears the transient composition mends
    // in place (re-running the credential-anchored establishment, minting
    // the missing epoch[0]), so the refusal only stands when the heal
    // itself failed and a retry re-runs it.
    case 'unpromoted-account':
    case 'no-user-key-roster':
      return 'auth.errors.transientSetupIncomplete'
    // The roster exists but its current epoch carries no wrap for this
    // credential (an adopted roster, or a rotation that dropped it). A
    // retry cannot help; another client or a rotation must re-escrow the
    // credential, so the copy is its own.
    case 'no-user-key-wrap':
      return 'auth.errors.transientNoUserKeyWrap'
    // The roster reads as absent but the mend's mint preconditions refused
    // to create one (a held roster-epoch pin, or key-agreement entries this
    // credential does not own). A retry re-runs the same refused
    // preconditions, so the copy points at a connected wallet instead.
    case 'roster-mint-refused':
      return 'auth.errors.transientRosterMintRefused'
    // The annex-generation family: no live generation the credential's
    // sibling delegation can reach. No remedy exists that a credential-only
    // visit can run until the ladder-signed generation mint lands, so the
    // copy is the honest refusal and offers none.
    case 'no-delegated-clients':
    case 'no-clientAnnex-generation':
    case 'no-generation-delegation':
      return 'auth.errors.transientUnavailable'
    // The configuration refusal (a `rememberBrowser: false` caller on a
    // no-WAS deployment). The login form never produces it; the
    // developer-facing string is the error's own message, carried in the log
    // above.
    case 'no-was-server':
      return 'auth.errors.setupFailed'
  }
}
