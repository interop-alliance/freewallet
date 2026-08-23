import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import { FiKey } from 'react-icons/fi'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Trans, useTranslation } from 'react-i18next'
import { Link as RouterLink, useLocation, useNavigate } from 'react-router'
import { AuthPageHeader } from '@/components/AuthPageHeader'
import { Toast } from '@/components/Toast'
import { authStyles } from '@/styles/appStyles'
import { useAuthStore } from '@/stores/authStore'
import type { SubmitEvent } from 'react'
import { useEffect, useState } from 'react'
import { loginWithPassphrase, loginWithPasskey } from '@/session/initSession'
import {
  KeyringRecordForgedError,
  KeyringRecordRolledBackError,
  KeyringRecordUnusableError
} from '@/session/keyring'
import { TransientLoginUnavailableError } from '@/session/transientLogin'
import { backfillPassphraseUnlockMethod } from '@/session/unlockMethods'
import { checkRecoveryHealth } from '@/session/recovery'
import { recordWalletLogin } from '@/session/walletLoginActivity'
import { showToast } from '@/stores/toastStore'
import type { ClientWebvhUpdateKeys } from '@interop/wallet-core/webvh'
import {
  EnrollmentPendingError,
  mintEnrollmentRequest
} from '@interop/wallet-core/enrollment'
import { completeEnrollment } from '@/lib/enrollment'
import { isStorageUnreachable } from '@/lib/storageErrors'
import {
  forgetBrowserWalletData,
  hasForgettableBrowserData
} from '@/session/forget'
import {
  PasskeyCancelledError,
  PasskeyPrfUnsupportedError,
  passkeySupported
} from '@/lib/passkey'
import { registerWallet } from '@/lib/registerWallet'
import { forcedRememberBrowser } from '@/lib/e2eSeams'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import type { AuthLocationState } from '@/types/auth'

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
function loginErrorKey({
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

/**
 * The refusal states that offer the forget affordance: the keyring
 * authenticity and replay refusals and the two continuity refusals -- the
 * states where a stale local prior (or a genuinely hostile host) wedges the
 * login with no in-app remedy. The affordance is the no-unlock-material
 * grade: a whole-database, browser-scoped wipe, never a ceremony -- nothing
 * derived from the typed secret is trusted in these states, so nothing is
 * signed, and each account's standing document client remains (stated in the
 * dialog copy).
 */
const FORGETTABLE_ERROR_KEYS = new Set([
  'auth.errors.keyringForged',
  'auth.errors.keyringRolledBack',
  'auth.errors.accountLogContinuity',
  'auth.errors.userKeyRosterContinuity'
])

export function LoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const login = useAuthStore(state => state.login)
  const location = useLocation()
  const state = location.state as AuthLocationState | null | undefined
  const bannerText = state?.authMessageKey
    ? t(state.authMessageKey)
    : state?.userMessage
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isPasskeySubmitting, setIsPasskeySubmitting] = useState(false)
  const [errorKey, setErrorKey] = useState<string | null>(null)
  // The enrollment (connect-this-browser) flow off the not-enrolled state:
  // the passphrase that located the account, then the locally minted key set
  // and its connect code. In-memory only -- nothing is durable until
  // `completeEnrollment` succeeds.
  const [notEnrolledPassphrase, setNotEnrolledPassphrase] = useState<
    string | null
  >(null)
  const [enrollment, setEnrollment] = useState<{
    passphrase: string
    clientSeed: Uint8Array
    webvhUpdateKeys: ClientWebvhUpdateKeys
    code: string
    clientDid: string
  } | null>(null)
  const [enrollBusy, setEnrollBusy] = useState(false)
  const [enrollErrorKey, setEnrollErrorKey] = useState<string | null>(null)
  // The forget-this-browser dialog off a forgettable refusal: `null` closed,
  // otherwise whether the browser holds anything to delete. Reset by every
  // fresh login attempt, so the dialog can never sit beside an error it did
  // not belong to (the FW-175 stale-state rule; the wipe itself is
  // browser-scoped, so there is no per-account binding to get wrong).
  const [forgetState, setForgetState] = useState<boolean | null>(null)
  const [forgetBusy, setForgetBusy] = useState(false)
  const { copied: codeCopied, copy: copyCode } = useCopyToClipboard({
    onError: (err: unknown) => {
      console.error('Could not copy the connect code:', err)
    }
  })

  useEffect(() => {
    void registerWallet()
  }, [])

  /**
   * Handles form submit event
   */
  const handleLogin = async (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (isSubmitting) {
      return
    }
    setIsSubmitting(true)
    setErrorKey(null)
    setForgetState(null)
    // Hoisted out of the try: the torn-enrollment catch arm below offers the
    // connect-this-browser flow, which needs the passphrase that located the
    // account.
    let passphrase = ''
    try {
      const data = new FormData(event.currentTarget)
      passphrase = data.get('login-passphrase') as string
      if (!passphrase) {
        return
      }
      const { session, userExists } = await loginWithPassphrase({
        passphrase,
        ...(forcedRememberBrowser() ? { rememberBrowser: true } : {})
      })
      if (!session && userExists) {
        // The passphrase located the account, but this browser holds no
        // client key set for it and the durable route had nothing to
        // self-enroll with (a no-WAS plain pointer record; with a WAS server
        // the non-remembered default is the transient route, whose refusals
        // arrive as `TransientLoginUnavailableError` in the catch below).
        // Offer the connect-this-browser flow.
        setErrorKey('auth.errors.clientNotEnrolled')
        setNotEnrolledPassphrase(passphrase)
        setEnrollment(null)
        setEnrollErrorKey(null)
        return
      }
      if (!session || !userExists) {
        return navigate('/signup', {
          state: { authMessageKey: 'auth.errors.profileNotFound' }
        })
      }
      // Session creation fired `ensureUserCollections` as `session.storageReady`;
      // wait for the collections to be provisioned/opened before proceeding.
      await session.storageReady
      login(session)
      recordWalletLogin({ session })
      // The roster read adopted a rotated user key but could not write this
      // browser's durable copy (client-key record or epoch pin): the session
      // is fine, so warn rather than fail the login.
      if (session.userKeyPersistFailed) {
        showToast({
          message: t('auth.login.rememberBrowserWarning'),
          severity: 'warning'
        })
      }
      // Backfill the passphrase entry in the unlock-methods registry (its
      // unlock Space + management zcap) from this full session, without a
      // second passphrase prompt. Fire-and-forget: it never blocks login, and
      // an existing registry not yet materialized stays that way (no
      // `createIfMissing`).
      void backfillPassphraseUnlockMethod({ session }).catch(err =>
        console.warn('Could not backfill the unlock-methods registry:', err)
      )
      // The login-time recovery health check: a recovery delegation signed by
      // a since-removed client rots silently and would brick recovery exactly
      // when it is needed, so nudge now rather than then.
      void checkRecoveryHealth({ session })
        .then(flags => {
          if (flags.length > 0) {
            showToast({
              message: t('auth.login.recoveryHealthWarning'),
              severity: 'warning'
            })
          }
        })
        .catch(err => console.warn('Recovery health check failed:', err))
      navigate('/dashboard', { replace: true })
    } catch (err) {
      const key = loginErrorKey({ err, label: 'Login' })
      setErrorKey(key)
      // A torn enrollment, or a transient login the account's state cannot
      // serve: connecting this browser mints a fresh key set and redoes the
      // wrap, so offer that flow.
      if (
        (key === 'auth.errors.userKeyRosterUnwrap' ||
          key === 'auth.errors.clientNotEnrolled') &&
        passphrase
      ) {
        setNotEnrolledPassphrase(passphrase)
        setEnrollment(null)
        setEnrollErrorKey(null)
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  /**
   * Starts the connect-this-browser flow off the not-enrolled state: mints
   * this browser's key set locally and shows the connect code to carry to an
   * already-connected browser. Only public halves leave this page.
   */
  const handleStartEnrollment = async () => {
    if (!notEnrolledPassphrase || enrollBusy) {
      return
    }
    setEnrollBusy(true)
    setEnrollErrorKey(null)
    try {
      const minted = await mintEnrollmentRequest()
      setEnrollment({ passphrase: notEnrolledPassphrase, ...minted })
    } catch (err) {
      console.error('Could not start connecting this browser:', err)
      setEnrollErrorKey('auth.enroll.failed')
    } finally {
      setEnrollBusy(false)
    }
  }

  /**
   * Finishes the connect-this-browser flow once the other browser approved
   * the code: verifies the enrollment from the published log, performs the
   * first roster read, persists the key set under the passphrase, and logs
   * in. While the approval has not landed yet, surfaces the pending state and
   * stays (retried by pressing the button again).
   */
  const handleCompleteEnrollment = async () => {
    if (!enrollment || enrollBusy) {
      return
    }
    setEnrollBusy(true)
    setEnrollErrorKey(null)
    try {
      // One ceremony call: it derives the unlock identity once and hands
      // back the logged-in session of the newly enrolled client.
      const session = await completeEnrollment({
        clientSeed: enrollment.clientSeed,
        webvhUpdateKeys: enrollment.webvhUpdateKeys,
        passphrase: enrollment.passphrase
      })
      await session.storageReady
      login(session)
      recordWalletLogin({ session })
      void backfillPassphraseUnlockMethod({ session }).catch(err =>
        console.warn('Could not backfill the unlock-methods registry:', err)
      )
      navigate('/dashboard', { replace: true })
    } catch (err) {
      if (err instanceof EnrollmentPendingError) {
        setEnrollErrorKey('auth.enroll.pending')
      } else {
        console.error('Connecting this browser failed:', err)
        setEnrollErrorKey('auth.enroll.failed')
      }
    } finally {
      setEnrollBusy(false)
    }
  }

  /**
   * Opens the forget-this-browser dialog off a forgettable refusal, probing
   * first whether this browser holds any wallet data at all (a
   * never-remembered browser gets the nothing-to-delete copy instead of a
   * destructive confirm).
   */
  const handleOpenForget = async () => {
    setForgetState(await hasForgettableBrowserData())
  }

  /**
   * Runs the no-unlock-material forget grade: the whole-database,
   * browser-scoped wipe. No ceremony and no signing -- the copy in the
   * dialog has already stated the standing-document-client residue.
   */
  const handleConfirmForget = async () => {
    if (forgetBusy) {
      return
    }
    setForgetBusy(true)
    try {
      const { failed, unverified } = await forgetBrowserWalletData()
      setForgetState(null)
      setErrorKey(null)
      // Three outcomes, in decreasing order of certainty about what is
      // gone: something could not be deleted, something was deleted but
      // could not be confirmed (this browser cannot enumerate its
      // databases), or a clean wipe.
      const messageKey =
        failed.length > 0
          ? 'auth.forget.incomplete'
          : unverified.length > 0
            ? 'auth.forget.unverified'
            : 'auth.forget.done'
      showToast({
        message: t(messageKey),
        severity: messageKey === 'auth.forget.done' ? 'success' : 'warning'
      })
    } catch (err) {
      console.error('Forgetting the wallet data on this browser failed:', err)
      showToast({ message: t('auth.forget.failed'), severity: 'error' })
    } finally {
      setForgetBusy(false)
    }
  }

  /**
   * Handles the "Log in with a Passkey" button. Runs the WebAuthn PRF
   * assertion via `loginWithPasskey`, then upgrades to a full session on a hit.
   */
  const handlePasskeyLogin = async () => {
    if (isSubmitting || isPasskeySubmitting) {
      return
    }
    setIsPasskeySubmitting(true)
    setErrorKey(null)
    setForgetState(null)
    try {
      const { session, userExists } = await loginWithPasskey(
        forcedRememberBrowser() ? { rememberBrowser: true } : {}
      )
      if (!session && userExists) {
        // The passkey located the account, but this browser holds no client
        // key set for it and its record carries no standing authority (a
        // pre-FW-154 bind). A standing passkey self-enrolls inside the login
        // call -- a platform-synced passkey on a fresh machine logs straight
        // in -- so this fallback only fires for a plain pointer record.
        setErrorKey('auth.errors.clientNotEnrolled')
        return
      }
      if (!session || !userExists) {
        // A fresh passkey cannot create an account -- stay on the page and ask
        // the user to log in with their passphrase first.
        setErrorKey('auth.errors.passkeyNoAccount')
        return
      }
      // Session creation fired `ensureUserCollections` as `session.storageReady`;
      // wait for the collections to be provisioned/opened before proceeding.
      await session.storageReady
      login(session)
      recordWalletLogin({ session })
      navigate('/dashboard', { replace: true })
    } catch (err) {
      if (err instanceof PasskeyCancelledError) {
        // The user dismissed or aborted the ceremony -- nothing to report.
      } else if (err instanceof PasskeyPrfUnsupportedError) {
        // This passkey or browser cannot evaluate the PRF extension.
        setErrorKey('auth.errors.passkeyPrfUnsupported')
      } else {
        // The connect-this-browser flow starts from a passphrase, so a torn
        // enrollment only surfaces its message here; the passphrase handler
        // offers the flow itself.
        setErrorKey(loginErrorKey({ err, label: 'Passkey login' }))
      }
    } finally {
      setIsPasskeySubmitting(false)
    }
  }

  return (
    <Box component="main" className="fw-page" sx={authStyles.page}>
      <AuthPageHeader />
      <Box sx={authStyles.pageContent}>
        <Typography variant="h4" component="h1" sx={authStyles.title}>
          {t('auth.login.heading')}
        </Typography>

        <Box sx={authStyles.cardsRow}>
          {/* Log in card */}
          <Card sx={authStyles.authCard} variant="outlined">
            <CardContent sx={authStyles.authCardContent}>
              <Box
                component="form"
                onSubmit={handleLogin}
                sx={authStyles.authCardForm}
              >
                {errorKey === 'auth.errors.storageUnreachable' ? (
                  <Alert severity="error" sx={authStyles.userMessage}>
                    <Trans
                      i18nKey="auth.errors.storageUnreachable"
                      components={{
                        guest: (
                          <Link
                            component={RouterLink}
                            to="/guest-login"
                            underline="always"
                          />
                        )
                      }}
                    />
                  </Alert>
                ) : errorKey === 'auth.errors.browserForgotten' ? (
                  <Alert severity="info" sx={authStyles.userMessage}>
                    {t(errorKey)}
                  </Alert>
                ) : errorKey ? (
                  <Alert severity="error" sx={authStyles.userMessage}>
                    {t(errorKey)}{' '}
                    <Link
                      component={RouterLink}
                      to="/recover"
                      underline="always"
                    >
                      {t('auth.login.recoverLink')}
                    </Link>
                  </Alert>
                ) : (
                  bannerText && (
                    <Alert severity="error" sx={authStyles.userMessage}>
                      {bannerText}
                    </Alert>
                  )
                )}

                {errorKey && FORGETTABLE_ERROR_KEYS.has(errorKey) && (
                  <Button
                    variant="outlined"
                    color="error"
                    onClick={handleOpenForget}
                    sx={authStyles.actionButton}
                    data-testid="forget-browser-button"
                  >
                    {t('auth.forget.button')}
                  </Button>
                )}

                {(errorKey === 'auth.errors.clientNotEnrolled' ||
                  errorKey === 'auth.errors.userKeyRosterUnwrap') &&
                  notEnrolledPassphrase &&
                  !enrollment && (
                    <Button
                      variant="outlined"
                      onClick={handleStartEnrollment}
                      loading={enrollBusy}
                      sx={authStyles.actionButton}
                    >
                      {t('auth.enroll.connectButton')}
                    </Button>
                  )}

                <Typography
                  variant="h5"
                  component="label"
                  htmlFor="login-passphrase"
                >
                  {t('auth.login.passphraseLabel')}
                </Typography>
                <TextField
                  id="login-passphrase"
                  name="login-passphrase"
                  type="password"
                  autoComplete="current-password"
                  sx={authStyles.input}
                />

                <Button
                  variant="contained"
                  type="submit"
                  loading={isSubmitting}
                  disabled={isPasskeySubmitting}
                  sx={authStyles.actionButton}
                >
                  {t('auth.login.submit')}
                </Button>

                <Typography
                  variant="h6"
                  component="p"
                  sx={authStyles.authFooterText}
                >
                  {t('auth.login.noWallet')}{' '}
                  <Box component="span" sx={{ whiteSpace: 'nowrap' }}>
                    <Link
                      component={RouterLink}
                      to="/signup"
                      underline="always"
                    >
                      {t('auth.login.signUpLink')}
                    </Link>
                    .
                  </Box>
                </Typography>
                <Typography
                  variant="body2"
                  component="p"
                  sx={authStyles.authFooterText}
                >
                  <Link component={RouterLink} to="/recover" underline="always">
                    {t('auth.login.forgotPassphrase')}
                  </Link>
                </Typography>
              </Box>
            </CardContent>
          </Card>

          {/* Connect-this-browser (enrollment) card */}
          {enrollment && (
            <Card sx={authStyles.authCard} variant="outlined">
              <CardContent sx={authStyles.authCardContent}>
                <Stack sx={{ gap: 2 }}>
                  <Typography variant="h5" component="h2">
                    {t('auth.enroll.heading')}
                  </Typography>
                  <Typography variant="body2">
                    {t('auth.enroll.explain')}
                  </Typography>
                  <TextField
                    label={t('auth.enroll.codeLabel')}
                    value={enrollment.code}
                    multiline
                    minRows={3}
                    slotProps={{
                      input: { readOnly: true },
                      htmlInput: { 'data-testid': 'enroll-connect-code' }
                    }}
                  />
                  <Button
                    variant="outlined"
                    onClick={() => void copyCode(enrollment.code)}
                  >
                    {codeCopied
                      ? t('common.copied')
                      : t('auth.enroll.copyCode')}
                  </Button>
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ wordBreak: 'break-all' }}
                  >
                    {t('auth.enroll.fingerprint', {
                      did: enrollment.clientDid
                    })}
                  </Typography>
                  {enrollErrorKey && (
                    <Alert
                      severity={
                        enrollErrorKey === 'auth.enroll.pending'
                          ? 'info'
                          : 'error'
                      }
                    >
                      {t(enrollErrorKey)}
                    </Alert>
                  )}
                  <Button
                    variant="contained"
                    onClick={handleCompleteEnrollment}
                    loading={enrollBusy}
                    sx={authStyles.actionButton}
                  >
                    {t('auth.enroll.completeButton')}
                  </Button>
                </Stack>
              </CardContent>
            </Card>
          )}

          {/* Passkey card */}
          {passkeySupported() && (
            <Card sx={authStyles.passkeyCard} variant="outlined">
              <CardContent sx={authStyles.passkeyCardContent}>
                <Button
                  variant="contained"
                  onClick={handlePasskeyLogin}
                  loading={isPasskeySubmitting}
                  loadingPosition="start"
                  disabled={isSubmitting}
                  startIcon={<FiKey />}
                  sx={authStyles.passkeyButton}
                >
                  {t('auth.login.passkey')}
                </Button>
              </CardContent>
            </Card>
          )}
        </Box>
      </Box>

      {/* The forget-this-browser confirm (the no-unlock-material grade). */}
      <Dialog
        open={forgetState !== null}
        onClose={() => setForgetState(null)}
        aria-labelledby="forget-browser-title"
      >
        <DialogTitle id="forget-browser-title">
          {t('auth.forget.title')}
        </DialogTitle>
        <DialogContent>
          {forgetState ? (
            <Stack sx={{ gap: 1.5 }}>
              <DialogContentText>{t('auth.forget.body')}</DialogContentText>
              <DialogContentText>
                {t('auth.forget.blastRadius')}
              </DialogContentText>
              <DialogContentText>{t('auth.forget.residue')}</DialogContentText>
            </Stack>
          ) : (
            <DialogContentText>{t('auth.forget.nothing')}</DialogContentText>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setForgetState(null)}>
            {t('common.cancel')}
          </Button>
          {forgetState && (
            <Button
              color="error"
              variant="contained"
              loading={forgetBusy}
              onClick={handleConfirmForget}
              data-testid="forget-browser-confirm"
            >
              {t('auth.forget.confirm')}
            </Button>
          )}
        </DialogActions>
      </Dialog>

      {/* This page is outside the dashboard layout that renders the shared
          snackbar, and the forget affordance reports its outcome here rather
          than on a page it navigates to. */}
      <Toast />
    </Box>
  )
}
