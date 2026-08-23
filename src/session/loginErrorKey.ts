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
import { isStorageUnreachable } from '@/lib/storageErrors'

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
 * @returns {string}
 */
export function loginErrorKey({
  err,
  label
}: {
  err: unknown
  label: string
}): string {
  // The WAS storage server is unreachable -- offer a guest-mode fallback.
  if (isStorageUnreachable(err)) {
    return 'auth.errors.storageUnreachable'
  }
  // The authenticity refusal: the record's proof was not made by the key the
  // typed secret derives, so the storage host forged or tampered with it.
  if (err instanceof KeyringRecordForgedError) {
    console.error(`${label} refused:`, err)
    return 'auth.errors.keyringForged'
  }
  // The replay refusal: a validly signed record, but older than the newest
  // this browser has accepted for the secret.
  if (err instanceof KeyringRecordRolledBackError) {
    console.error(`${label} refused:`, err)
    return 'auth.errors.keyringRolledBack'
  }
  // The account-log continuity refusal: the served did:webvh log is a
  // rollback, a fork, or an identity switch against the chain head this
  // browser has pinned.
  if (errorName(err) === 'ResourceLogContinuityError') {
    console.error(`${label} refused:`, err)
    return 'auth.errors.accountLogContinuity'
  }
  // The rollback refusal: the served key roster sits behind the epoch this
  // browser has already seen.
  if (errorName(err) === 'UserKeyRosterContinuityError') {
    console.error(`${label} refused:`, err)
    return 'auth.errors.userKeyRosterContinuity'
  }
  // The served key roster failed authentication -- a fabricated or tampered
  // epoch configuration.
  if (errorName(err) === 'UserKeyRosterIntegrityError') {
    console.error(`${label} refused:`, err)
    return 'auth.errors.userKeyRosterIntegrity'
  }
  // A torn enrollment: this browser's key is published for the account, but
  // the key roster holds no wrap for it, so the session cannot recover the
  // account key.
  if (errorName(err) === 'UserKeyRosterUnwrapError') {
    console.error(`${label} failed:`, err)
    return 'auth.errors.userKeyRosterUnwrap'
  }
  // The self-enrolling login's fail-closed attribution refusal: the
  // published log commits no rung of this credential's update-key ladder (a
  // revoked or retired credential), or more than one (an ambiguous state
  // self-enrollment must not guess through).
  if (errorName(err) === 'LadderAttributionError') {
    console.error(`${label} refused:`, err)
    return 'auth.errors.ladderAttribution'
  }
  // The finish-the-wipe detector's outcome: this browser's client entry was
  // removed from the account (a forget torn before its wipe, or a disconnect
  // from another client) and the local residue has just been cleared.
  if (errorName(err) === 'BrowserForgottenError') {
    // Both wipe reports ride the error: what failed, and what was deleted
    // without confirmation on a browser that cannot enumerate its
    // databases. The user-facing copy is the same either way (the account
    // is gone from here); the distinction is for the log.
    console.warn(`${label}: this browser was forgotten:`, err)
    return 'auth.errors.browserForgotten'
  }
  // A keyring record was found but is corrupt -- not a server outage and not
  // a wrong passphrase; surface it with recovery guidance.
  if (err instanceof KeyringRecordUnusableError) {
    console.error(`${label} failed:`, err)
    return 'auth.errors.keyringUnusable'
  }
  // The transient login could not proceed here (a record without standing
  // authority or an annex sibling, no live generation, an unpromoted
  // account). Interim mapping onto the existing not-enrolled guidance --
  // connecting this browser durably is the one remedy every reason shares;
  // honest per-reason copy is a follow-up concern.
  if (err instanceof TransientLoginUnavailableError) {
    console.error(`${label} unavailable transiently:`, err)
    return 'auth.errors.clientNotEnrolled'
  }
  console.error(`${label} failed:`, err)
  return 'auth.errors.setupFailed'
}
