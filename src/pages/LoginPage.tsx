import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Link from '@mui/material/Link'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useNavigate } from 'react-router'
import { authStyles } from '../styles/appStyles.ts'
import { useAuthStore } from '../stores/authStore.ts'
import type { SubmitEvent } from 'react'
import { createMockSession } from '../session/createMockSession.ts'

export function LoginPage() {
  const navigate = useNavigate()
  const login = useAuthStore(state => state.login)

  /**
   * Handles form submit event
   */
  const handleLogin = async (event: SubmitEvent<HTMLFormElement>) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const passphrase = data.get('login-passphrase') as string
    if (!passphrase) {
      console.log('No passphrase entered.')
      return
    }
    const email = 'alice@example.com'
    const { session } = await createMockSession({ email, passphrase })
    login(session)
    navigate('/dashboard')
  }

  return (
    <Box component="main" sx={authStyles.page}>
      <Box component="form" onSubmit={handleLogin} sx={authStyles.content}>
        <Typography variant="h2" component="h1" sx={authStyles.title}>
          Freewallet
        </Typography>
        <Typography variant="h3" component="h2" sx={authStyles.title}>
          Log in
        </Typography>

        <Typography variant="h5" component="label" htmlFor="login-passphrase">
          Passphrase:
        </Typography>
        <TextField
          name="login-passphrase"
          defaultValue="not a real password"
          type="password"
          autoComplete="current-password"
          sx={authStyles.input}
        />

        <Button variant="contained" type="submit" sx={authStyles.actionButton}>
          Log in
        </Button>

        <Typography variant="h6" component="p">
          Don&apos;t have an existing wallet?{' '}
          <Link component={RouterLink} to="/signup" underline="always">
            Sign up
          </Link>
          .
        </Typography>
      </Box>
    </Box>
  )
}
