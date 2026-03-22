import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useNavigate } from 'react-router'
import { authStyles } from '@/styles/appStyles.ts'
import type { SubmitEvent } from 'react'
import { createMockSession } from '@/session/createMockSession.ts'
import { useAuthStore } from '@/stores/authStore.ts'

export function SignupPage() {
  const navigate = useNavigate()
  const login = useAuthStore(state => state.login)

  /**
   * Handles form submit event
   */
  const handleSignup = async (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const passphrase = data.get('signup-passphrase') as string
    if (!passphrase) {
      console.log('No passphrase entered.')
      return
    }
    const email = data.get('signup-email') as string
    const { session } = await createMockSession({ email, passphrase })
    login(session)
    // Login successful, send user back to where they were redirected from
    //  (or to /dashboard if no 'from' specified)
    navigate('/dashboard')
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

        <Typography variant="h5" component="label" htmlFor="signup-email">
          Email:
        </Typography>
        <TextField
          name="signup-email"
          defaultValue="alice@example.com"
          type="email"
          sx={authStyles.input}
        />

        <Typography variant="h5" component="label" htmlFor="signup-passphrase">
          Passphrase:
        </Typography>
        <TextField
          name="signup-passphrase"
          defaultValue="not a real password"
          type="password"
          autoComplete="new-password"
          sx={authStyles.input}
        />

        <Button variant="contained" type="submit" sx={authStyles.actionButton}>
          Create Wallet
        </Button>
      </Box>
    </Box>
  )
}
