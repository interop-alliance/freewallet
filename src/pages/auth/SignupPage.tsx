import { useState } from 'react'
import {
  Box,
  Button,
  Stack,
  Step,
  StepLabel,
  Stepper,
  TextField,
  Typography,
  useMediaQuery,
  useTheme
} from '@mui/material'
import { useLocation, useNavigate } from 'react-router'
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
  const login = useAuthStore(state => state.login)
  const [activeStep, setActiveStep] = useState(0)
  const [email, setEmail] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [score, setScore] = useState(0)
  const location = useLocation()
  const { userMessage } = location.state || {}

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
    await storage.ensureUserCollections({ user: session.user })
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
    if (passphraseStepComplete) {
      setActiveStep(1)
    }
  }

  const goBack = () => {
    setActiveStep(0)
  }

  return (
    <Box component="main" sx={authStyles.page}>
      <Box component="form" onSubmit={handleSignup} sx={authStyles.content}>
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

        <Box sx={{ width: '100%', maxWidth: 360, alignSelf: 'center' }}>
          <Stepper
            activeStep={activeStep}
            orientation={isCompactStepper ? 'vertical' : 'horizontal'}
            alternativeLabel={!isCompactStepper}
            sx={{
              '& .MuiStepLabel-label': { typography: 'body2' }
            }}
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
            <Typography
              variant="h5"
              component="label"
              htmlFor="signup-passphrase"
              sx={authStyles.label}
            >
              Password:
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

            <Button
              variant="contained"
              type="button"
              onClick={goNext}
              disabled={!passphraseStepComplete}
              sx={authStyles.actionButton}
            >
              Next
            </Button>
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

            <Stack
              direction="row"
              spacing={2}
              justifyContent="center"
              alignItems="center"
              sx={{ ...authStyles.input, maxWidth: 360 }}
            >
              <Button
                variant="outlined"
                type="button"
                onClick={goBack}
                sx={{ ...authStyles.actionButton, width: 'auto', minWidth: 100 }}
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
