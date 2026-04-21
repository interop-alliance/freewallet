import { useState } from 'react'
import {
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
import { FiKey } from 'react-icons/fi'
import { Link as RouterLink, useLocation, useNavigate, useSearchParams } from 'react-router'
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

const STEPS = ['Passphrase', 'Email'] as const

export function SignupPage() {
  const theme = useTheme()
  const isCompactStepper = useMediaQuery(theme.breakpoints.down('sm'))
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const login = useAuthStore(state => state.login)
  const location = useLocation()
  const { userMessage } = location.state || {}

  const [email, setEmail] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [score, setScore] = useState(0)

  const activeStep = searchParams.get('step') === 'email' ? 1 : 0

  const handleSignup = async (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (activeStep !== STEPS.length - 1 || !canSubmit) {
      return
    }
    const { session } = await initSessionFromSecret({
      email,
      secret: passphrase
    })
    const { storage, userExists } =
      await StorageManager.initStorageClients(session)
    session.storage = storage
    if (userExists) {
      const userMessage = 'This profile already exists, please log in.'
      console.log('User already exists, redirecting to login page.')
      return navigate('/login', { state: { userMessage } })
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
    void registerWallet()
    navigate('/dashboard')
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

  const goBack = () => {
    navigate(-1)
  }

  return (
    <Box component="main" sx={authStyles.page}>
      <Box component="form" onSubmit={handleSignup} sx={authStyles.wideContent}>
        <Typography variant="h2" component="h1" sx={authStyles.title}>
          Freewallet
        </Typography>
        <Typography variant="h3" component="h2" sx={authStyles.title}>
          Sign up
        </Typography>

        {userMessage && (
          <Typography variant="body1" color="error" sx={authStyles.userMessage}>
            {userMessage}
          </Typography>
        )}

        <Box sx={authStyles.signupStepperWrap}>
          <Stepper
            activeStep={activeStep}
            orientation={isCompactStepper ? 'vertical' : 'horizontal'}
            alternativeLabel={!isCompactStepper}
            sx={authStyles.signupStepper}
          >
            {STEPS.map(label => (
              <Step key={label}>
                <StepLabel>{label}</StepLabel>
              </Step>
            ))}
          </Stepper>
        </Box>

        {activeStep === 0 && (
          <>
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
                    Passphrase:
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
                      scoreWords={['Weak', 'Weak', 'Fair', 'Strong', 'Very strong']}
                      shortScoreWord="Too short"
                    />
                  </Box>
                  <Stack spacing={0.5} sx={authStyles.input}>
                    <RuleIndicator
                      passed={lengthPassed}
                      label={`At least ${PASSWORD_RULES.minlength} characters`}
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
                    Sign up with a Passkey
                  </Button>
                  <Typography variant="body2" color="text.secondary">
                    (Coming soon.)
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
              Next
            </Button>

            <Typography variant="h6" component="p" sx={authStyles.authFooterText}>
              Already have a wallet?{' '}
              <Link component={RouterLink} to="/login" underline="always">
                Log in
              </Link>
              .
            </Typography>
          </>
        )}

        {activeStep === 1 && (
          <>
            <Typography
              variant="h5"
              component="label"
              htmlFor="signup-email"
              sx={authStyles.label}
            >
              Email:
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
                Back
              </Button>
              <Button
                variant="contained"
                type="submit"
                disabled={!canSubmit}
                sx={authStyles.actionButton}
              >
                Create Wallet
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
