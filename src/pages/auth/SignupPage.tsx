import { useState } from 'react'
import { Box, Button, Stack, TextField, Typography } from '@mui/material'
import { useLocation, useNavigate } from 'react-router'
import { authStyles } from '@/styles/appStyles'
import type { SubmitEvent } from 'react'
import { initSessionFromSecret } from '@/session/initSession'
import { useAuthStore } from '@/stores/authStore'
import PasswordStrengthBarModule from 'react-password-strength-bar'
import { PASSWORD_RULES } from '@/app.config'
import { welcomeCredential } from '@/fixtures/welcomeCredential'
import { StorageManager } from '@/stores/storageManager'

const PasswordStrengthBar =
  (
    PasswordStrengthBarModule as unknown as {
      default: typeof PasswordStrengthBarModule
    }
  ).default ?? PasswordStrengthBarModule

export function SignupPage() {
  const navigate = useNavigate()
  const login = useAuthStore(state => state.login)
  const [email, setEmail] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [score, setScore] = useState(0)
  const location = useLocation()
  const { userMessage } = location.state || {}

  const handleSignup = async (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!canSubmit) {
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
    navigate('/dashboard')
  }

  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  const lengthPassed = passphrase.length >= PASSWORD_RULES.minlength
  const scorePassed = score >= PASSWORD_RULES.minscore
  const canSubmit = emailValid && lengthPassed && scorePassed

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
          type="submit"
          disabled={!canSubmit}
          sx={authStyles.actionButton}
        >
          Create Wallet
        </Button>
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
