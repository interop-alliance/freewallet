import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import { FiKey } from 'react-icons/fi'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Trans, useTranslation } from 'react-i18next'
import { Link as RouterLink, useLocation, useNavigate } from 'react-router'
import { AuthPageHeader } from '@/components/AuthPageHeader'
import { authStyles } from '@/styles/appStyles'
import { useAuthStore } from '@/stores/authStore'
import type { SubmitEvent } from 'react'
import { useEffect, useState } from 'react'
import { loginWithPassphrase, loginWithPasskey } from '@/session/initSession'
import {
  AccountPointerChangedError,
  KeyringRecordUnusableError
} from '@/session/keyring'
import {
  PukRosterContinuityError,
  PukRosterIntegrityError,
  PukRosterUnwrapError
} from '@interop/wallet-core/keys'
import { backfillPassphraseUnlockMethod } from '@/session/unlockMethods'
import { checkRecoveryHealth } from '@/session/recovery'
import { showToast } from '@/stores/toastStore'
import type { ClientWebvhUpdateKeys } from '@interop/wallet-core/webvh'
import {
  EnrollmentPendingError,
  mintEnrollmentRequest
} from '@interop/wallet-core/enrollment'
import { completeEnrollment } from '@/lib/enrollment'
import { isStorageUnreachable } from '@/lib/storageErrors'
import {
  PasskeyCancelledError,
  PasskeyPrfUnsupportedError,
  passkeySupported
} from '@/lib/passkey'
import { registerWallet } from '@/lib/registerWallet'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import type { AuthLocationState } from '@/types/auth'

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
        passphrase
      })
      if (!session && userExists) {
        // The passphrase located the account, but this browser holds no
        // client key set for it -- unlocking is no longer sufficient to BE
        // the account. Offer the connect-this-browser (enrollment) flow.
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
      // The WAS storage server is unreachable -- offer a guest-mode fallback.
      if (isStorageUnreachable(err)) {
        setErrorKey('auth.errors.storageUnreachable')
      } else if (err instanceof AccountPointerChangedError) {
        // The continuity refusal: the server returned an account pointer that
        // conflicts with the one this browser has pinned.
        console.error('Login refused:', err)
        setErrorKey('auth.errors.accountPointerChanged')
      } else if (err instanceof PukRosterContinuityError) {
        // The rollback refusal: the served key roster sits behind the epoch
        // this browser has already seen.
        console.error('Login refused:', err)
        setErrorKey('auth.errors.pukRosterContinuity')
      } else if (err instanceof PukRosterIntegrityError) {
        // The served key roster failed authentication -- a fabricated or
        // tampered epoch configuration.
        console.error('Login refused:', err)
        setErrorKey('auth.errors.pukRosterIntegrity')
      } else if (err instanceof PukRosterUnwrapError) {
        // A torn enrollment: this browser's key is published for the account,
        // but the key roster holds no wrap for it, so the session cannot
        // recover the account key. Connecting this browser again mints a
        // fresh key set and redoes the wrap, so offer that flow.
        console.error('Login failed:', err)
        setErrorKey('auth.errors.pukRosterUnwrap')
        if (passphrase) {
          setNotEnrolledPassphrase(passphrase)
          setEnrollment(null)
          setEnrollErrorKey(null)
        }
      } else if (err instanceof KeyringRecordUnusableError) {
        // A keyring record was found but is corrupt -- not a server outage
        // and not a wrong passphrase; surface it with recovery guidance.
        console.error('Login failed:', err)
        setErrorKey('auth.errors.keyringUnusable')
      } else {
        console.error('Login failed:', err)
        setErrorKey('auth.errors.setupFailed')
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
      await completeEnrollment({
        clientSeed: enrollment.clientSeed,
        webvhUpdateKeys: enrollment.webvhUpdateKeys,
        passphrase: enrollment.passphrase
      })
      const { session } = await loginWithPassphrase({
        passphrase: enrollment.passphrase
      })
      if (!session) {
        setEnrollErrorKey('auth.enroll.failed')
        return
      }
      await session.storageReady
      login(session)
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
   * Handles the "Log in with a Passkey" button. Runs the WebAuthn PRF
   * assertion via `loginWithPasskey`, then upgrades to a full session on a hit.
   */
  const handlePasskeyLogin = async () => {
    if (isSubmitting || isPasskeySubmitting) {
      return
    }
    setIsPasskeySubmitting(true)
    setErrorKey(null)
    try {
      const { session, userExists } = await loginWithPasskey()
      if (!session && userExists) {
        // The passkey located the account, but this browser holds no client
        // key set for it (e.g. a platform-synced passkey on a fresh machine).
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
      navigate('/dashboard', { replace: true })
    } catch (err) {
      if (err instanceof PasskeyCancelledError) {
        // The user dismissed or aborted the ceremony -- nothing to report.
      } else if (err instanceof PasskeyPrfUnsupportedError) {
        // This passkey or browser cannot evaluate the PRF extension.
        setErrorKey('auth.errors.passkeyPrfUnsupported')
      } else if (isStorageUnreachable(err)) {
        // The WAS storage server is unreachable -- offer a guest-mode fallback.
        setErrorKey('auth.errors.storageUnreachable')
      } else if (err instanceof AccountPointerChangedError) {
        // The continuity refusal: the server returned an account pointer that
        // conflicts with the one this browser has pinned.
        console.error('Passkey login refused:', err)
        setErrorKey('auth.errors.accountPointerChanged')
      } else if (err instanceof PukRosterContinuityError) {
        // The rollback refusal: the served key roster sits behind the epoch
        // this browser has already seen.
        console.error('Passkey login refused:', err)
        setErrorKey('auth.errors.pukRosterContinuity')
      } else if (err instanceof PukRosterIntegrityError) {
        // The served key roster failed authentication -- a fabricated or
        // tampered epoch configuration.
        console.error('Passkey login refused:', err)
        setErrorKey('auth.errors.pukRosterIntegrity')
      } else if (err instanceof PukRosterUnwrapError) {
        // A torn enrollment: this browser's key is published for the account,
        // but the key roster holds no wrap for it. The connect-this-browser
        // flow starts from a passphrase, so the copy asks for one here.
        console.error('Passkey login failed:', err)
        setErrorKey('auth.errors.pukRosterUnwrap')
      } else if (err instanceof KeyringRecordUnusableError) {
        // A keyring record was found but is corrupt -- not a server outage;
        // surface it with recovery guidance.
        console.error('Passkey login failed:', err)
        setErrorKey('auth.errors.keyringUnusable')
      } else {
        console.error('Passkey login failed:', err)
        setErrorKey('auth.errors.setupFailed')
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

                {(errorKey === 'auth.errors.clientNotEnrolled' ||
                  errorKey === 'auth.errors.pukRosterUnwrap') &&
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
    </Box>
  )
}
