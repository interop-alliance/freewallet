import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Link from '@mui/material/Link'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useLocation, useNavigate } from 'react-router'
import { authStyles } from '@/styles/appStyles'
import { useAuthStore } from '@/stores/authStore'
import type { SubmitEvent } from 'react'
import { initSessionFromSecret } from '@/session/initSession'

export function LoginPage() {
  const navigate = useNavigate()
  const login = useAuthStore(state => state.login)
  const location = useLocation()
  const { userMessage } = location.state || {}

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
    const { session, userExists } = await initSessionFromSecret({
      secret: passphrase
    })
    if (!userExists) {
      const userMessage = 'This profile does not exist, please sign up.'
      console.log('User does not exist, redirecting to signup page.')
      return navigate('/signup', { state: { userMessage } })
    }
    await session.storage.ensureUserCollections({ user: session.user })
    login(session)
    navigate('/dashboard', { replace: true })
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

        {userMessage && (
          <Typography variant="body1" color="error" sx={authStyles.userMessage}>
            {userMessage}
          </Typography>
        )}

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
