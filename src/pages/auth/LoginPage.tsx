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
import { loginErrorKey } from '@/session/loginErrorKey'
import { checkRecoveryHealth } from '@/session/recovery'
import { recordWalletLogin } from '@/session/walletLoginActivity'
import { showToast } from '@/stores/toastStore'
import type { ClientWebvhUpdateKeys } from '@interop/wallet-core/webvh'
import {
  EnrollmentPendingError,
  mintEnrollmentRequest
} from '@interop/wallet-core/enrollment'
import { completeEnrollment } from '@/lib/enrollment'
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
import { RecoveryCodeDisplay } from '@/components/RecoveryCodeDisplay'
import { forcedConnectOffer, forcedRememberBrowser } from '@/lib/e2eSeams'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import type { AuthLocationState, Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:login')

/**
 * The refusal states that offer the forget affordance: the keyring
 * authenticity refusal and the two continuity refusals -- the states where a
 * hostile host wedges the login with no in-app remedy. The affordance is the no-unlock-material
 * grade: a whole-database, browser-scoped wipe, never a ceremony -- nothing
 * derived from the typed secret is trusted in these states, so nothing is
 * signed, and each account's standing document client remains (stated in the
 * dialog copy).
 */
const FORGETTABLE_ERROR_KEYS = new Set([
  'auth.errors.keyringForged',
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
  // A resumed recovery spend's show-once obligation: the replacement code to
  // display and the confirm-gated completion to run before navigating on.
  // Set by a login that resumed a torn spend; `null` otherwise.
  const [spendPrompt, setSpendPrompt] = useState<NonNullable<
    Session['recoverySpendPrompt']
  > | null>(null)
  const [spendBusy, setSpendBusy] = useState(false)
  // The forget-this-browser dialog off a forgettable refusal: `null` closed,
  // otherwise whether the browser holds anything to delete. Reset by every
  // fresh login attempt, so the dialog can never sit beside an error it did
  // not belong to (the FW-175 stale-state rule; the wipe itself is
  // browser-scoped, so there is no per-account binding to get wrong).
  const [forgetState, setForgetState] = useState<boolean | null>(null)
  const [forgetBusy, setForgetBusy] = useState(false)
  const { copied: codeCopied, copy: copyCode } = useCopyToClipboard({
    onError: (err: unknown) => {
      log.error('Could not copy the connect code', { err })
    }
  })

  // Handler registration runs on mount, before the durability decision, so a
  // transient visit registers too: an unregistered handler never appears in
  // the mediator's chooser, and a public-terminal session that cannot answer
  // a CHAPI request is the same as no wallet at all. It writes nothing to
  // this origin (the registration bit lives on the mediator's), so it leaves
  // a transient visit residue-free here; the mediator-origin bit is the
  // stated limit no top-level wipe reaches.
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
    setNotEnrolledPassphrase(null)
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
      if (forcedConnectOffer()) {
        // The connect-this-browser e2e seam: the two-party enrollment specs
        // need the enrollee card from a cold browser, but a healthy WAS
        // account's default login now simply succeeds (every signup leaves
        // standing transient entry), so the seam stands in for the login
        // form's own connect entry until that ships -- the submit opens the
        // card with the typed passphrase instead of logging in. Always
        // false in production builds.
        setNotEnrolledPassphrase(passphrase)
        setEnrollment(null)
        setEnrollErrorKey(null)
        return
      }
      const { session, userExists } = await loginWithPassphrase({
        passphrase,
        ...(forcedRememberBrowser() ? { rememberBrowser: true } : {})
      })
      if (!session && userExists) {
        // The passphrase located the account, but this browser holds no
        // client key set for it and the durable route had nothing to
        // self-enroll with. Only a no-WAS deployment produces this state:
        // its bind is the plain pointer record, while every WAS signup
        // writes the standing layout, and on a WAS server the non-remembered
        // default is the transient route, whose refusals arrive as
        // `TransientLoginUnavailableError` in the catch below. Offer the
        // connect-this-browser flow.
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
      // The login-time registry passes run AFTER navigation, serialized on
      // `session.registryReady` -- navigation deliberately does not wait on
      // them (FW-300).
      await session.storageReady
      login(session)
      recordWalletLogin({ session })
      // The roster read adopted a rotated user key but could not write this
      // browser's copy of it (the client-key record): the session is fine,
      // so warn rather than fail the login.
      if (session.userKeyPersistFailed) {
        showToast({
          message: t('auth.login.rememberBrowserWarning'),
          severity: 'warning'
        })
      }
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
        .catch(err => log.warn('Recovery health check failed', { err }))
      if (session.recoverySpendPrompt) {
        // The login resumed a torn recovery spend that still owes the
        // show-once replacement-code display: render it here and gate the
        // record completion (and navigation) on the save confirm, exactly
        // as the /recover page does.
        setSpendPrompt(session.recoverySpendPrompt)
        return
      }
      navigate('/dashboard', { replace: true })
    } catch (err) {
      const { key } = loginErrorKey({ err, label: 'Login' })
      setErrorKey(key)
      // A torn enrollment (the durable path's own two-client state):
      // connecting this browser mints a fresh key set and redoes the wrap,
      // so offer that flow. A transient-login refusal never opens the card
      // (a remedy that presupposes a second client is no remedy there).
      if (key === 'auth.errors.userKeyRosterUnwrap' && passphrase) {
        setNotEnrolledPassphrase(passphrase)
        setEnrollment(null)
        setEnrollErrorKey(null)
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  /**
   * The resumed spend's "I saved this code" confirm: runs the confirm-gated
   * record completion (which clears the persisted replacement-code carrier)
   * and then navigates on. A failed completion is logged and the login
   * proceeds: the pending record stays, and the next login re-displays the
   * code and completes.
   */
  const handleSpendPromptSaved = async () => {
    if (!spendPrompt || spendBusy) {
      return
    }
    setSpendBusy(true)
    try {
      // The live session's CURRENT vault user key rides into the
      // completion: a login-sweep rotation while the code was on display
      // must not be written over by the resume's captured key.
      const currentUserKey = useAuthStore.getState().session?.profile.userKey
      await spendPrompt.complete(
        currentUserKey ? { currentUserKey } : undefined
      )
    } catch (err) {
      log.warn('Could not complete the resumed recovery spend on confirm', {
        err
      })
    } finally {
      setSpendBusy(false)
    }
    setSpendPrompt(null)
    navigate('/dashboard', { replace: true })
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
      log.error('Could not start connecting this browser', { err })
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
      navigate('/dashboard', { replace: true })
    } catch (err) {
      if (err instanceof EnrollmentPendingError) {
        setEnrollErrorKey('auth.enroll.pending')
      } else {
        log.error('Connecting this browser failed', { err })
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
      log.error('Forgetting the wallet data on this browser failed', { err })
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
    setNotEnrolledPassphrase(null)
    try {
      const { session, userExists } = await loginWithPasskey(
        forcedRememberBrowser() ? { rememberBrowser: true } : {}
      )
      if (!session && userExists) {
        // The passkey located the account, but this browser holds no client
        // key set for it and its record carries no standing authority (a
        // plain pointer record). A standing passkey self-enrolls inside the login
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
      // The login-time registry passes run AFTER navigation, serialized on
      // `session.registryReady` -- navigation deliberately does not wait on
      // them (FW-300).
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
        setErrorKey(loginErrorKey({ err, label: 'Passkey login' }).key)
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

        {/* A resumed recovery spend's show-once replacement code: rendered
            full-width above the login cards, with the confirm-gated
            completion behind the save button (the /recover page's own
            save-this-code sequence). */}
        {spendPrompt && (
          <Card sx={authStyles.enrollCard} variant="outlined">
            <CardContent sx={authStyles.authCardContent}>
              <Stack sx={{ gap: 2 }}>
                <Alert severity="warning">
                  {t('auth.recover.replacementExplain')}
                </Alert>
                {/* Non-blocking: the resume could not finish the new
                    passphrase's standing setup; a later login or resume
                    completes it. */}
                {spendPrompt.standing === 'pending' && (
                  <Alert severity="info">
                    {t('auth.recover.standingPending')}
                  </Alert>
                )}
                <RecoveryCodeDisplay
                  code={spendPrompt.replacementCode}
                  copyLabel={t('auth.recover.copyCode')}
                  testId="resume-replacement-recovery-code"
                />
                <Button
                  variant="contained"
                  onClick={() => void handleSpendPromptSaved()}
                  loading={spendBusy}
                >
                  {t('auth.recover.replacementSavedButton')}
                </Button>
              </Stack>
            </CardContent>
          </Card>
        )}

        {/* Connect-this-browser (enrollment) card: full-width above the
            login and passkey cards. */}
        {enrollment && (
          <Card sx={authStyles.enrollCard} variant="outlined">
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
                  {codeCopied ? t('common.copied') : t('auth.enroll.copyCode')}
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
                  sx={authStyles.enrollCompleteButton}
                >
                  {t('auth.enroll.completeButton')}
                </Button>
              </Stack>
            </CardContent>
          </Card>
        )}

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

                {notEnrolledPassphrase && !enrollment && (
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
