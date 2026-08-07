import { useEffect, useState } from 'react'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Link,
  Stack,
  Step,
  StepLabel,
  Stepper,
  TextField,
  Typography,
  useMediaQuery,
  useTheme
} from '@mui/material'
import { FiCheckCircle, FiKey } from 'react-icons/fi'
import { SiGoogledrive } from 'react-icons/si'
import {
  Link as RouterLink,
  useLocation,
  useNavigate,
  useSearchParams
} from 'react-router'
import { Trans, useTranslation } from 'react-i18next'
import { AuthPageHeader } from '@/components/AuthPageHeader'
import { authStyles } from '@/styles/appStyles'
import type { SubmitEvent } from 'react'
import { signUpWithPasskey, signUpWithPassphrase } from '@/session/signup'
import { isStorageUnreachable } from '@/lib/storageErrors'
import {
  PasskeyCancelledError,
  PasskeyPrfUnsupportedError,
  passkeySupported
} from '@/lib/passkey'
import { useAuthStore } from '@/stores/authStore'
import { PassphraseStrengthField } from '@/components/PassphraseStrengthField'
import { usePrfRetryPrompt } from '@/hooks/usePrfRetryPrompt'
import { DATE_FMT, PASSWORD_RULES } from '@/app.config'
import { registerWallet } from '@/lib/registerWallet'
import type { AuthLocationState } from '@/types/auth'

/**
 * The stepper labels, first entry chosen by the login method: the passkey
 * method names its first step "Passkey", the passphrase method "Passphrase".
 * The email and storage steps are shared.
 *
 * @param method {'passphrase' | 'passkey'}
 * @returns {readonly string[]}
 */
function stepI18nKeys(method: 'passphrase' | 'passkey') {
  return [
    method === 'passkey'
      ? 'auth.signup.steps.passkey'
      : 'auth.signup.steps.passphrase',
    'auth.signup.steps.email',
    'auth.signup.steps.storage'
  ] as const
}

export function SignupPage() {
  const { t, i18n } = useTranslation()
  const theme = useTheme()
  const isCompactStepper = useMediaQuery(theme.breakpoints.down('sm'))
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const login = useAuthStore(state => state.login)
  const location = useLocation()
  const state = location.state as AuthLocationState | null | undefined
  const bannerText = state?.authMessageKey
    ? t(state.authMessageKey)
    : state?.userMessage

  useEffect(() => {
    void registerWallet()
  }, [])

  const [email, setEmail] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [score, setScore] = useState(0)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [errorKey, setErrorKey] = useState<string | null>(null)
  // PRF-retry consent dialog (passkey signup): `registerPasskey` calls
  // `promptForPrfRetry` when a second ceremony is needed.
  const { promptForPrfRetry, dialog: prfRetryDialog } = usePrfRetryPrompt()

  const stepParam = searchParams.get('step')
  const activeStep = stepParam === 'storage' ? 2 : stepParam === 'email' ? 1 : 0
  // The chosen login method, tracked in the URL search params so a mid-wizard
  // reload keeps it. Passphrase is the default (an absent/other value).
  const method: 'passphrase' | 'passkey' =
    searchParams.get('method') === 'passkey' ? 'passkey' : 'passphrase'
  const stepKeys = stepI18nKeys(method)

  const handleSignup = async (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (isSubmitting) {
      return
    }
    if (activeStep !== stepKeys.length - 1 || !canSubmit) {
      return
    }
    setIsSubmitting(true)
    setErrorKey(null)

    if (method === 'passkey') {
      try {
        const userName =
          email ||
          `Freewallet ${new Date().toLocaleDateString(i18n.language, DATE_FMT)}`
        const { session } = await signUpWithPasskey({
          email: email || undefined,
          locale: i18n.language,
          userName,
          promptForPrfRetry
        })
        login(session)
        navigate('/dashboard')
      } catch (err) {
        if (err instanceof PasskeyCancelledError) {
          // The user dismissed the ceremony (or declined the PRF retry): silent.
        } else if (err instanceof PasskeyPrfUnsupportedError) {
          setErrorKey('auth.errors.passkeyPrfUnsupported')
        } else if (isStorageUnreachable(err)) {
          // The WAS storage server is unreachable -- offer a guest-mode fallback.
          setErrorKey('auth.errors.storageUnreachable')
        } else {
          console.error('Error completing signup:', err)
          setErrorKey('auth.errors.setupFailed')
        }
      } finally {
        setIsSubmitting(false)
      }
      return
    }

    try {
      const { session, userExists } = await signUpWithPassphrase({
        passphrase,
        email: email || undefined
      })
      if (userExists || !session) {
        return navigate('/login', {
          state: { authMessageKey: 'auth.errors.profileExists' }
        })
      }
      login(session)
      navigate('/dashboard')
    } catch (err) {
      // The WAS storage server is unreachable -- offer a guest-mode fallback.
      if (isStorageUnreachable(err)) {
        setErrorKey('auth.errors.storageUnreachable')
      } else {
        console.error('Error completing signup:', err)
        setErrorKey('auth.errors.setupFailed')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  // Email is optional. An empty email is allowed; a non-empty one must be
  // well-formed.
  const emailValid = email === '' || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  const lengthPassed = passphrase.length >= PASSWORD_RULES.minlength
  const scorePassed = score >= PASSWORD_RULES.minscore
  const passphraseStepComplete = lengthPassed && scorePassed
  // The passkey method has no passphrase to satisfy, so only the email must be
  // valid; the passphrase method also needs a complete passphrase step.
  const canSubmit =
    method === 'passkey' ? emailValid : emailValid && passphraseStepComplete

  const goNext = () => {
    if (!passphraseStepComplete) {
      return
    }
    // Passphrase is the default method, so omit the method param.
    setSearchParams({ ['step']: 'email' })
  }

  // Advance to the email step with the passkey method recorded in the URL.
  const goPasskey = () => {
    setSearchParams({ ['method']: 'passkey', ['step']: 'email' })
  }

  const goNextFromEmail = () => {
    if (!emailValid) {
      return
    }
    setSearchParams(
      method === 'passkey'
        ? { ['method']: 'passkey', ['step']: 'storage' }
        : { ['step']: 'storage' }
    )
  }

  // Navigate to the explicit previous step rather than popping browser
  // history. This keeps Back inside the wizard even when the user deep-linked
  // or reloaded directly into a later step (where history(-1) would escape the
  // signup flow entirely). The method param is preserved back to the email
  // step; returning to step 0 (the method choice) drops it.
  const goBack = () => {
    if (activeStep === 2) {
      setSearchParams(
        method === 'passkey'
          ? { ['method']: 'passkey', ['step']: 'email' }
          : { ['step']: 'email' }
      )
      return
    }
    setSearchParams({})
  }

  return (
    <Box component="main" className="fw-page" sx={authStyles.page}>
      <AuthPageHeader />
      <Box component="form" onSubmit={handleSignup} sx={authStyles.pageContent}>
        <Typography variant="h4" component="h1" sx={authStyles.title}>
          {t('auth.signup.heading')}
        </Typography>

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
        <Box sx={authStyles.signupStepperWrap}>
          <Stepper
            activeStep={activeStep}
            orientation={isCompactStepper ? 'vertical' : 'horizontal'}
            alternativeLabel={!isCompactStepper}
            sx={authStyles.signupStepper}
          >
            {stepKeys.map(key => (
              <Step key={key}>
                <StepLabel>{t(key)}</StepLabel>
              </Step>
            ))}
          </Stepper>
        </Box>

        {activeStep === 0 && (
          <>
            <Typography variant="h5" component="h2" sx={authStyles.title}>
              {t('auth.signup.loginSecurity')}
            </Typography>
            <Box sx={authStyles.cardsRow}>
              {/* Passphrase card */}
              <Card sx={authStyles.authCard} variant="outlined">
                <CardContent sx={authStyles.authCardContent}>
                  <Typography
                    variant="h5"
                    component="label"
                    htmlFor="signup-passphrase"
                    sx={authStyles.label}
                  >
                    {t('auth.signup.passphraseLabel')}
                  </Typography>
                  <TextField
                    id="signup-passphrase"
                    name="signup-passphrase"
                    value={passphrase}
                    onChange={e => setPassphrase(e.target.value)}
                    type="password"
                    autoComplete="new-password"
                    sx={authStyles.input}
                  />
                  <Stack spacing={0.5} sx={authStyles.input}>
                    <PassphraseStrengthField
                      password={passphrase}
                      onChangeScore={setScore}
                    />
                  </Stack>
                </CardContent>
              </Card>

              {/* Passkey card */}
              {passkeySupported() && (
                <Card sx={authStyles.passkeyCard} variant="outlined">
                  <CardContent sx={authStyles.passkeyCardContent}>
                    <Button
                      variant="contained"
                      type="button"
                      onClick={goPasskey}
                      startIcon={<FiKey />}
                      sx={authStyles.passkeyButton}
                    >
                      {t('auth.signup.passkey')}
                    </Button>
                    <Typography variant="body2" color="text.secondary">
                      {t('auth.signup.passkeyHint')}
                    </Typography>
                  </CardContent>
                </Card>
              )}
            </Box>

            <Button
              variant="contained"
              type="button"
              onClick={goNext}
              disabled={!passphraseStepComplete}
              sx={authStyles.actionButton}
            >
              {t('auth.signup.next')}
            </Button>

            <Typography
              variant="h6"
              component="p"
              sx={authStyles.authFooterText}
            >
              {t('auth.signup.hasWallet')}{' '}
              <Box component="span" sx={{ whiteSpace: 'nowrap' }}>
                <Link component={RouterLink} to="/login" underline="always">
                  {t('auth.signup.logInLink')}
                </Link>
                .
              </Box>
            </Typography>
            <Typography
              variant="body2"
              component="p"
              sx={authStyles.authFooterText}
            >
              {t('auth.signup.lostPassphrase')}{' '}
              <Link component={RouterLink} to="/recover" underline="always">
                {t('auth.signup.recoverLink')}
              </Link>
            </Typography>
          </>
        )}

        {activeStep === 1 && (
          <>
            <Typography variant="h5" component="h2" sx={authStyles.title}>
              {t('auth.signup.emailHeading')}
            </Typography>
            <Typography
              variant="h5"
              component="label"
              htmlFor="signup-email"
              sx={authStyles.label}
            >
              {t('auth.signup.emailLabel')}
            </Typography>
            <TextField
              id="signup-email"
              name="signup-email"
              placeholder="alice@example.com"
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              autoComplete="email"
              error={!emailValid}
              helperText={
                emailValid
                  ? t('auth.signup.emailOptionalHint')
                  : t('auth.signup.emailInvalid')
              }
              sx={authStyles.input}
            />

            <Stack sx={authStyles.signupWizardActions}>
              <Button
                variant="outlined"
                type="button"
                onClick={goBack}
                sx={authStyles.signupBackButton}
              >
                {t('auth.signup.back')}
              </Button>
              <Button
                variant="contained"
                type="button"
                onClick={goNextFromEmail}
                disabled={!emailValid}
                sx={authStyles.actionButton}
              >
                {t('auth.signup.next')}
              </Button>
            </Stack>
          </>
        )}

        {activeStep === 2 && (
          <>
            <Typography variant="h5" component="h2" sx={authStyles.title}>
              {t('auth.signup.storageHeading')}
            </Typography>

            <Stack spacing={2}>
              {/* Dropbox card */}
              <Card sx={authStyles.authCard} variant="outlined">
                <CardContent sx={authStyles.passkeyCardContent}>
                  <Button
                    variant="contained"
                    disabled
                    startIcon={
                      <img
                        src="https://cfl.dropboxstatic.com/static/metaserver/static/images/logo_catalog/blue_dropbox_glyph_m1-vflZvZxbS.png"
                        alt="Dropbox"
                        style={{ width: 20, height: 20, objectFit: 'contain' }}
                      />
                    }
                    sx={authStyles.passkeyButton}
                  >
                    {t('auth.signup.connectDropbox')}
                  </Button>
                </CardContent>
              </Card>

              {/* Google Drive card */}
              <Card sx={authStyles.authCard} variant="outlined">
                <CardContent sx={authStyles.passkeyCardContent}>
                  <Button
                    variant="contained"
                    disabled
                    startIcon={<SiGoogledrive />}
                    sx={authStyles.passkeyButton}
                  >
                    {t('auth.signup.connectDrive')}
                  </Button>
                </CardContent>
              </Card>

              {/* Free storage card */}
              <Card sx={authStyles.authCard} variant="outlined">
                <CardContent sx={authStyles.passkeyCardContent}>
                  <FiCheckCircle size={32} color="green" />
                  <Typography variant="h6" component="h3">
                    {t('auth.signup.courtesyStorage')}
                  </Typography>
                </CardContent>
              </Card>
            </Stack>

            <Stack sx={{ ...authStyles.signupWizardActions, mb: 10 }}>
              <Button
                variant="outlined"
                type="button"
                onClick={goBack}
                sx={authStyles.signupBackButton}
              >
                {t('auth.signup.back')}
              </Button>
              <Button
                variant="contained"
                type="submit"
                loading={isSubmitting}
                sx={authStyles.actionButton}
              >
                {t('auth.signup.createWallet')}
              </Button>
            </Stack>
          </>
        )}

        {prfRetryDialog}
      </Box>
    </Box>
  )
}
