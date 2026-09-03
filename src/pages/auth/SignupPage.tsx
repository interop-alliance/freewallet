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
import { PassphraseStrengthField } from '@/components/PassphraseStrengthField'
import { promptForPrfRetry } from '@/hooks/usePrfRetryPrompt'
import { DATE_FMT, PASSWORD_RULES } from '@/app.config'
import { registerWallet } from '@/lib/registerWallet'
import { forcedRememberBrowser } from '@/lib/e2eSeams'
import type { AuthLocationState } from '@/types/auth'
import { createLogger } from '@/lib/log'
import {
  beginSetup,
  failSetup,
  finishSetup,
  markSetupStage,
  type SetupMethod
} from '@/stores/setupStore'

const log = createLogger('fw:ui:signup')

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

/**
 * Maps a failed setup run onto the error key the wizard shows when the lobby
 * hands the user back. `null` is the silent failure: the user dismissed the
 * WebAuthn ceremony (or declined the PRF retry).
 *
 * @param err {unknown}
 * @returns {string | null}
 */
function signupErrorKey(err: unknown): string | null {
  if (err instanceof PasskeyCancelledError) {
    return null
  }
  if (err instanceof PasskeyPrfUnsupportedError) {
    return 'auth.errors.passkeyPrfUnsupported'
  }
  if (isStorageUnreachable(err)) {
    // The WAS storage server is unreachable -- offer a guest-mode fallback.
    return 'auth.errors.storageUnreachable'
  }
  log.error('Error completing signup', { err })
  return 'auth.errors.setupFailed'
}

/**
 * Runs the account-setup ceremony and records its outcome in the setup
 * store, which the lobby page reads. Started from the wizard's click handler
 * and deliberately not awaited there: the ceremony outlives this page, since
 * the wizard navigates to the lobby at once.
 *
 * Session creation fires `ensureUserCollections` as `session.storageReady`;
 * the collections are awaited here before the run settles, exactly as the
 * login page does. (A transient session carries no `storageReady` and falls
 * straight through.)
 *
 * @param options {object}
 * @param options.method {SetupMethod}
 * @param options.passphrase {string}
 * @param options.email {string}   empty when the user skipped the step
 * @param options.locale {string}
 * @param options.userName {string}   the WebAuthn user name
 * @returns {Promise<void>}
 */
async function runSetup({
  method,
  passphrase,
  email,
  locale,
  userName
}: {
  method: SetupMethod
  passphrase: string
  email: string
  locale: string
  userName: string
}): Promise<void> {
  try {
    if (method === 'passkey') {
      const { session } = await signUpWithPasskey({
        ...(email ? { email } : {}),
        locale,
        userName,
        promptForPrfRetry,
        onStage: markSetupStage
      })
      await session.storageReady
      finishSetup({ session, userExists: false })
      return
    }
    const { session, userExists } = await signUpWithPassphrase({
      passphrase,
      ...(email ? { email } : {}),
      // The e2e seam forces the remembered flow; without it a WAS-configured
      // signup on this (by definition non-remembered) browser runs
      // credential-anchored and ends in a transient session.
      ...(forcedRememberBrowser() ? { rememberBrowser: true } : {}),
      onStage: markSetupStage
    })
    if (userExists || !session) {
      finishSetup({ userExists })
      return
    }
    await session.storageReady
    finishSetup({ session, userExists: false })
  } catch (err) {
    failSetup({ errorKey: signupErrorKey(err) })
  }
}

export function SignupPage() {
  const { t, i18n } = useTranslation()
  const theme = useTheme()
  const isCompactStepper = useMediaQuery(theme.breakpoints.down('sm'))
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
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
  // Seeded from the key the lobby hands back after a failed setup run; a
  // silent failure (a dismissed WebAuthn ceremony) carries none.
  const [errorKey, setErrorKey] = useState<string | null>(
    state?.setupErrorKey ?? null
  )

  const stepParam = searchParams.get('step')
  const activeStep = stepParam === 'storage' ? 2 : stepParam === 'email' ? 1 : 0
  // The chosen login method, tracked in the URL search params so a mid-wizard
  // reload keeps it. Passphrase is the default (an absent/other value).
  const method: 'passphrase' | 'passkey' =
    searchParams.get('method') === 'passkey' ? 'passkey' : 'passphrase'
  const stepKeys = stepI18nKeys(method)

  const handleSignup = (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (isSubmitting) {
      return
    }
    if (activeStep !== stepKeys.length - 1 || !canSubmit) {
      return
    }
    setIsSubmitting(true)
    setErrorKey(null)
    // Timing mark: paired with the dashboard's mount mark to measure how
    // long a signup takes end to end.
    log.info('Signup submitted', { method, at: new Date().toISOString() })

    // The ceremony starts here, inside the click handler, because the passkey
    // path spends the WebAuthn user gesture; a post-navigation start would
    // have lost it. It is deliberately not awaited: the lobby page renders
    // its progress and performs the navigation its outcome calls for.
    beginSetup({ method })
    void runSetup({
      method,
      passphrase,
      email,
      locale: i18n.language,
      userName:
        email ||
        `Freewallet ${new Date().toLocaleDateString(i18n.language, DATE_FMT)}`
    })
    void navigate('/lobby')
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
                    onChange={event => setPassphrase(event.target.value)}
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
              onChange={event => setEmail(event.target.value)}
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
      </Box>
    </Box>
  )
}
