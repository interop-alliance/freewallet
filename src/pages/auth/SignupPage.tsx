import { useEffect, useState } from 'react'
import {
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
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
import { useTranslation } from 'react-i18next'
import { LanguageSelector } from '@/components/LanguageSelector'
import { authStyles } from '@/styles/appStyles'
import type { SubmitEvent } from 'react'
import { initSessionFromSecret } from '@/session/initSession'
import { useAuthStore } from '@/stores/authStore'
import PasswordStrengthBarModule from 'react-password-strength-bar'
import { PASSWORD_RULES } from '@/app.config'
import { welcomeCredential } from '@/fixtures/welcomeCredential'
import { StorageManager } from '@/stores/storageManager'
import { registerWallet } from '@/lib/registerWallet'

const PasswordStrengthBar =
  (
    PasswordStrengthBarModule as unknown as {
      default: typeof PasswordStrengthBarModule
    }
  ).default ?? PasswordStrengthBarModule

const STEP_I18N_KEYS = [
  'auth.signup.steps.passphrase',
  'auth.signup.steps.email',
  'auth.signup.steps.storage'
] as const

type AuthLocationState = { authMessageKey?: string; userMessage?: string }

export function SignupPage() {
  const { t } = useTranslation()
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

  const stepParam = searchParams.get('step')
  const activeStep = stepParam === 'storage' ? 2 : stepParam === 'email' ? 1 : 0

  const handleSignup = async (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (isSubmitting) {
      return
    }
    if (activeStep !== STEP_I18N_KEYS.length - 1 || !canSubmit) {
      return
    }
    setIsSubmitting(true)
    try {
      const { session } = await initSessionFromSecret({
        email,
        secret: passphrase
      })
      const { storage, userExists } =
        await StorageManager.initStorageClients(session)
      session.storage = storage
      if (userExists) {
        console.log('User already exists, redirecting to login page.')
        return navigate('/login', {
          state: { authMessageKey: 'auth.errors.profileExists' }
        })
      }
      // This is a new user
      // Create Space and init collections
      await storage.ensureUserCollections({ user: session.user })
      // Now that we have somewhere to write _to_, start the history
      await session.storage.addHistoryNewAccount({ user: session.user })
      await session.storage.addHistorySpaceCreated({ user: session.user })

      // Add a "welcome" credential to storage
      await session.storage!.addCredential({ credential: welcomeCredential })
      login(session)
      navigate('/dashboard')
    } finally {
      setIsSubmitting(false)
    }
  }

  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  const lengthPassed = passphrase.length >= PASSWORD_RULES.minlength
  const scorePassed = score >= PASSWORD_RULES.minscore
  const passphraseStepComplete = lengthPassed && scorePassed
  const canSubmit = emailValid && passphraseStepComplete

  const goNext = () => {
    if (!passphraseStepComplete) {
      return
    }
    setSearchParams({ ['step']: 'email' })
  }

  const goNextFromEmail = () => {
    if (!emailValid) {
      return
    }
    setSearchParams({ ['step']: 'storage' })
  }

  const goBack = () => {
    navigate(-1)
  }

  return (
    <Box component="main" sx={authStyles.page}>
      <Box component="form" onSubmit={handleSignup} sx={authStyles.wideContent}>
        <Box sx={authStyles.languageBar}>
          <LanguageSelector />
        </Box>
        <Typography variant="h2" component="h1" sx={authStyles.title}>
          {t('landing.title')}
        </Typography>
        <Typography variant="h3" component="h2" sx={authStyles.title}>
          {t('auth.signup.heading')}
        </Typography>

        {bannerText && (
          <Typography variant="body1" color="error" sx={authStyles.userMessage}>
            {bannerText}
          </Typography>
        )}
        <Box sx={authStyles.signupStepperWrap}>
          <Stepper
            activeStep={activeStep}
            orientation={isCompactStepper ? 'vertical' : 'horizontal'}
            alternativeLabel={!isCompactStepper}
            sx={authStyles.signupStepper}
          >
            {STEP_I18N_KEYS.map(key => (
              <Step key={key}>
                <StepLabel>{t(key)}</StepLabel>
              </Step>
            ))}
          </Stepper>
        </Box>

        {activeStep === 0 && (
          <>
            <Typography variant="h4" component="h2" sx={authStyles.title}>
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
                  <Box sx={authStyles.input}>
                    <PasswordStrengthBar
                      password={passphrase}
                      onChangeScore={setScore}
                      scoreWords={
                        (t('auth.signup.passwordScores', {
                          returnObjects: true
                        }) as string[]) ?? [
                          'Weak',
                          'Weak',
                          'Fair',
                          'Strong',
                          'Very strong'
                        ]
                      }
                      shortScoreWord={t('auth.signup.passwordTooShort')}
                    />
                  </Box>
                  <Stack spacing={0.5} sx={authStyles.input}>
                    <RuleIndicator
                      passed={lengthPassed}
                      label={t('auth.signup.minChars', {
                        count: PASSWORD_RULES.minlength
                      })}
                    />
                  </Stack>
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
                    {t('auth.signup.passkey')}
                  </Button>
                  <Typography variant="body2" color="text.secondary">
                    {t('auth.signup.comingSoon')}
                  </Typography>
                </CardContent>
              </Card>
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
              <Link component={RouterLink} to="/login" underline="always">
                {t('auth.signup.logInLink')}
              </Link>
              .
            </Typography>
          </>
        )}

        {activeStep === 1 && (
          <>
            <Typography variant="h4" component="h2" sx={authStyles.title}>
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
              required
              value={email}
              onChange={e => setEmail(e.target.value)}
              autoComplete="email"
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
            <Typography variant="h4" component="h2" sx={authStyles.title}>
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
                disabled={isSubmitting}
                startIcon={
                  isSubmitting ? (
                    <CircularProgress size={18} color="inherit" />
                  ) : undefined
                }
                sx={authStyles.actionButton}
              >
                {t('auth.signup.createWallet')}
              </Button>
            </Stack>
          </>
        )}
      </Box>
    </Box>
  )
}

function RuleIndicator({ passed, label }: { passed: boolean; label: string }) {
  return (
    <Typography
      variant="body2"
      color={passed ? 'success.main' : 'text.secondary'}
    >
      {passed ? '\u2713' : '\u2717'} {label}
    </Typography>
  )
}
