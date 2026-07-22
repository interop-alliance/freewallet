import { useEffect, useRef, useState } from 'react'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
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
import { FiCheck, FiCheckCircle, FiKey, FiX } from 'react-icons/fi'
import { SiGoogledrive } from 'react-icons/si'
import {
  Link as RouterLink,
  useLocation,
  useNavigate,
  useSearchParams
} from 'react-router'
import { Trans, useTranslation } from 'react-i18next'
import { base64urlnopad } from '@scure/base'
import { AuthPageHeader } from '@/components/AuthPageHeader'
import { authStyles } from '@/styles/appStyles'
import type { SubmitEvent } from 'react'
import { initSessionFromSeed, loginWithPassphrase } from '@/session/initSession'
import { bindPassphrase } from '@/session/keyring'
import {
  enrollPasskey,
  putUnlockMethods,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import { provisionNewWallet } from '@/session/provisionNewWallet'
import { isStorageUnreachable } from '@/lib/storageErrors'
import {
  PasskeyCancelledError,
  PasskeyPrfUnsupportedError,
  passkeySupported
} from '@/lib/passkey'
import { savePasskeySafetyNotice } from '@/lib/sessionKey'
import { useAuthStore } from '@/stores/authStore'
import { PasswordStrengthMeter } from '@/components/PasswordStrengthMeter'
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
  // PRF-retry consent dialog (passkey signup): some authenticators evaluate the
  // WebAuthn PRF only during a second (assertion) ceremony. `registerPasskey`
  // calls `promptForPrfRetry` when that is needed; the promise resolves on the
  // user's choice in the dialog below.
  const [prfRetryOpen, setPrfRetryOpen] = useState(false)
  const prfRetryResolve = useRef<((consented: boolean) => void) | null>(null)

  const promptForPrfRetry = (): Promise<boolean> => {
    setPrfRetryOpen(true)
    return new Promise<boolean>(resolve => {
      prfRetryResolve.current = resolve
    })
  }

  const resolvePrfRetry = (consented: boolean) => {
    setPrfRetryOpen(false)
    prfRetryResolve.current?.(consented)
    prfRetryResolve.current = null
  }

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
        // No `userExists` probe: a fresh credential cannot collide with an
        // existing account, so there is nothing to probe (unlike the
        // passphrase path).
        const seed = crypto.getRandomValues(new Uint8Array(32))
        const { session } = await initSessionFromSeed({
          seed,
          email: email || undefined,
          provisionStorage: false
        })

        // Register the passkey and bind its PRF output to the data seed BEFORE
        // creating the data Space: an account whose keyring failed to publish
        // must not be created, and binding first means a failed signup leaves no
        // orphaned data Space behind. A brand-new wallet has no authenticator
        // credentials yet, so there is nothing to exclude. Delegating this
        // passkey's unlock Space management zcap to the data identity keeps a
        // lost passkey revocable tap-free from Settings.
        const userHandle = crypto.getRandomValues(new Uint8Array(16))
        const userName =
          email ||
          `Freewallet ${new Date().toLocaleDateString(i18n.language, DATE_FMT)}`
        const { registration, entry } = await enrollPasskey({
          seed,
          controller: session.user.id,
          userHandle,
          userName,
          locale: i18n.language,
          // Carried inside the wrapped record so any unlock method recovers the
          // account email.
          email: email || undefined,
          delegateManagementTo: session.user.id,
          promptForPrfRetry
        })

        // Provision collections, record the initial history, and seed the
        // welcome credential.
        await provisionNewWallet({ session })

        // Write the initial unlock-methods registry only now: it lives in the
        // data Space, which `provisionNewWallet` just created, so this must run
        // after provisioning (`putUnlockMethods` needs the Space to exist).
        // Non-fatal -- the passkey already logs in.
        const record: UnlockMethodsRecord = {
          version: 1,
          userHandle: base64urlnopad.encode(userHandle),
          methods: [entry]
        }
        try {
          await putUnlockMethods({ session, record })
        } catch (err) {
          console.warn('Could not record the new passkey in the registry:', err)
        }

        // Mark this as a passkey-only account so the dashboard can prompt the
        // user to add a second unlock method. Non-fatal.
        try {
          await savePasskeySafetyNotice({
            controller: session.user.id,
            backupEligibility: registration.backupEligibility,
            backupState: registration.backupState
          })
        } catch (err) {
          console.warn('Could not save the passkey-safety notice:', err)
        }

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
      // Probe for an existing account first. loginWithPassphrase resolves the
      // passphrase through the keyring and reports whether this identity already
      // has a wallet; probing (rather than binding a raw seed straight away) is
      // what prevents a re-signup with an existing passphrase from overwriting
      // that account's keyring and orphaning the wallet. The probe session is
      // discarded after reading `userExists`, so it must not provision.
      const probe = await loginWithPassphrase({
        passphrase,
        email: email || undefined,
        provisionStorage: false
      })
      if (probe.userExists) {
        return navigate('/login', {
          state: { authMessageKey: 'auth.errors.profileExists' }
        })
      }

      // This is a new user. The data identity is a random 32-byte seed
      // (unrecoverable without the keyring), so bind the passphrase BEFORE
      // creating the data Space: an account whose keyring failed to publish
      // must not be created, and binding first means a failed signup leaves no
      // orphaned data Space behind. Session creation therefore does not
      // provision (`provisionStorage: false`); `provisionNewWallet` runs the
      // ordered provisioning sequence only after the bind succeeds.
      const seed = crypto.getRandomValues(new Uint8Array(32))
      const { session } = await initSessionFromSeed({
        seed,
        email: email || undefined,
        provisionStorage: false
      })
      await bindPassphrase({
        seed,
        controller: session.user.id,
        passphrase,
        // Carried inside the wrapped record so any unlock method (a passkey
        // login has no form to ask on) recovers the account email.
        email: email || undefined
      })

      // Provision collections, record the initial history, and seed the
      // welcome credential.
      await provisionNewWallet({ session })
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
                  <Box sx={authStyles.input}>
                    <PasswordStrengthMeter
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

        <Dialog open={prfRetryOpen} onClose={() => resolvePrfRetry(false)}>
          <DialogTitle>{t('settings.passkeyRetryTitle')}</DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('settings.passkeyRetryMessage')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => resolvePrfRetry(false)}>
              {t('settings.passkeyRetryCancel')}
            </Button>
            <Button variant="contained" onClick={() => resolvePrfRetry(true)}>
              {t('settings.passkeyRetryConfirm')}
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Box>
  )
}

function RuleIndicator({ passed, label }: { passed: boolean; label: string }) {
  return (
    <Typography
      variant="body2"
      color={passed ? 'success.main' : 'text.secondary'}
      sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.5 }}
    >
      {passed ? <FiCheck aria-hidden /> : <FiX aria-hidden />} {label}
    </Typography>
  )
}
