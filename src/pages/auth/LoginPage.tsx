import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Link from '@mui/material/Link'
import { FiKey } from 'react-icons/fi'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Trans, useTranslation } from 'react-i18next'
import { Link as RouterLink, useLocation, useNavigate } from 'react-router'
import { LanguageSelector } from '@/components/LanguageSelector'
import { ThemePicker } from '@/components/ThemePicker'
import { authStyles } from '@/styles/appStyles'
import { useAuthStore } from '@/stores/authStore'
import type { SubmitEvent } from 'react'
import { useEffect, useState } from 'react'
import { loginWithPassphrase, loginWithPasskey } from '@/session/initSession'
import { KeyringRecordUnusableError } from '@/session/keyring'
import { backfillPassphraseUnlockMethod } from '@/session/unlockMethods'
import { isStorageUnreachable } from '@/lib/storageErrors'
import {
  PasskeyCancelledError,
  PasskeyPrfUnsupportedError,
  passkeySupported
} from '@/lib/passkey'
import { registerWallet } from '@/lib/registerWallet'
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
    try {
      const data = new FormData(event.currentTarget)
      const passphrase = data.get('login-passphrase') as string
      if (!passphrase) {
        return
      }
      const { session, userExists } = await loginWithPassphrase({
        passphrase
      })
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
      navigate('/dashboard', { replace: true })
    } catch (err) {
      // The WAS storage server is unreachable -- offer a guest-mode fallback.
      if (isStorageUnreachable(err)) {
        setErrorKey('auth.errors.storageUnreachable')
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
      <Box sx={authStyles.pageColumn}>
        <Box sx={authStyles.languageBar}>
          <LanguageSelector />
          <ThemePicker />
        </Box>
        <Typography variant="h2" component="h1" sx={authStyles.title}>
          {t('landing.title')}
        </Typography>

        <Typography variant="h4" component="h2" sx={authStyles.title}>
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
                    {t(errorKey)}
                  </Alert>
                ) : (
                  bannerText && (
                    <Alert severity="error" sx={authStyles.userMessage}>
                      {bannerText}
                    </Alert>
                  )
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
                  <Link component={RouterLink} to="/signup" underline="always">
                    {t('auth.login.signUpLink')}
                  </Link>
                  .
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
    </Box>
  )
}
