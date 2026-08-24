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
 * The i18n key for one transient-login refusal reason.
 *
 * @param reason {TransientLoginUnavailableReason}
 * @returns {string}
 */
function transientRefusalKey(reason: TransientLoginUnavailableReason): string {
  switch (reason) {
    // A failed heal: both states are tears the transient composition mends
    // in place (re-running the credential-anchored establishment, minting
    // the missing epoch[0]), so the refusal only stands when the heal
    // itself failed and a retry re-runs it.
    case 'unpromoted-account':
    case 'no-user-key-roster':
      return 'auth.errors.transientSetupIncomplete'
    // The annex-generation family: no live generation the credential's
    // sibling delegation can reach. No remedy exists that a credential-only
    // visit can run until the ladder-signed generation mint lands, so the
    // copy is the honest refusal and offers none.
    case 'no-delegated-clients':
    case 'no-clientAnnex-generation':
    case 'no-generation-delegation':
      return 'auth.errors.transientUnavailable'
    // A plain pointer record with no local key set: bricked, and the fix is
    // upstream (making the state unreachable), so it gets no copy of its
    // own and shares the honest refusal.
    case 'no-standing':
      return 'auth.errors.transientUnavailable'
    // The two configuration refusals (a `rememberBrowser: false` caller on
    // a no-WAS deployment or in the partitioned CHAPI popup). The login
    // form never produces them; the developer-facing string is the error's
    // own message, carried in the log above.
    case 'no-was-server':
    case 'remote-direct':
      return 'auth.errors.setupFailed'
  }
}
