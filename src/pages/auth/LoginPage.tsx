import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import CircularProgress from '@mui/material/CircularProgress'
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
import { initSessionFromSecret } from '@/session/initSession'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { registerWallet } from '@/lib/registerWallet'

type AuthLocationState = { authMessageKey?: string; userMessage?: string }

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
        console.log('No passphrase entered.')
        return
      }
      const { session, userExists } = await initSessionFromSecret({
        secret: passphrase
      })
      if (!userExists) {
        console.log('User does not exist, redirecting to signup page.')
        return navigate('/signup', {
          state: { authMessageKey: 'auth.errors.profileNotFound' }
        })
      }
      await session.storage.ensureUserCollections({
        user: session.user,
        profile: session.profile
      })
      login(session)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      // The WAS storage server is unreachable -- offer a guest-mode fallback.
      if (isStorageUnreachable(err)) {
        setErrorKey('auth.errors.storageUnreachable')
      } else {
        console.error('Login failed:', err)
        setErrorKey('auth.errors.setupFailed')
      }
    } finally {
      setIsSubmitting(false)
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
                  <Typography
                    variant="body1"
                    color="error"
                    sx={authStyles.userMessage}
                  >
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
                  </Typography>
                ) : errorKey ? (
                  <Typography
                    variant="body1"
                    color="error"
                    sx={authStyles.userMessage}
                  >
                    {t(errorKey)}
                  </Typography>
                ) : (
                  bannerText && (
                    <Typography
                      variant="body1"
                      color="error"
                      sx={authStyles.userMessage}
                    >
                      {bannerText}
                    </Typography>
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
                  name="login-passphrase"
                  type="password"
                  autoComplete="current-password"
                  sx={authStyles.input}
                />

                <Button
                  variant="contained"
                  type="submit"
                  disabled={isSubmitting}
                  startIcon={
                    isSubmitting ? (
                      <CircularProgress size={18} color="inherit" />
                    ) : undefined
                  }
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
          <Card sx={authStyles.passkeyCard} variant="outlined">
            <CardContent sx={authStyles.passkeyCardContent}>
              <Button
                variant="contained"
                disabled
                startIcon={<FiKey />}
                sx={authStyles.passkeyButton}
              >
                {t('auth.login.passkey')}
              </Button>
              <Typography variant="body2" color="text.secondary">
                {t('auth.login.comingSoon')}
              </Typography>
            </CardContent>
          </Card>
        </Box>
      </Box>
    </Box>
  )
}
