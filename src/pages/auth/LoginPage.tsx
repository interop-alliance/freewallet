import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Link from '@mui/material/Link'
import { FiKey } from 'react-icons/fi'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useLocation, useNavigate } from 'react-router'
import { authStyles } from '@/styles/appStyles'
import { useAuthStore } from '@/stores/authStore'
import type { SubmitEvent } from 'react'
import { initSessionFromSecret } from '@/session/initSession'
import { registerWallet } from '@/lib/registerWallet'

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
    void registerWallet()
    navigate('/dashboard', { replace: true })
  }

  return (
    <Box component="main" sx={authStyles.page}>
      <Box sx={authStyles.pageColumn}>
        <Typography variant="h2" component="h1" sx={authStyles.title}>
          Freewallet
        </Typography>

        <Typography variant="h4" component="h2" sx={authStyles.title}>
          Log in
        </Typography>

        <Box sx={authStyles.cardsRow}>
          {/* Log in card */}
          <Card sx={authStyles.authCard} variant="outlined">
            <CardContent sx={authStyles.authCardContent}>
              <Box component="form" onSubmit={handleLogin} sx={authStyles.authCardForm}>
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
                  type="password"
                  autoComplete="current-password"
                  sx={authStyles.input}
                />

                <Button variant="contained" type="submit" sx={authStyles.actionButton}>
                  Log in
                </Button>

                <Typography variant="h6" component="p" sx={authStyles.authFooterText}>
                  Don&apos;t have an existing wallet?{' '}
                  <Link component={RouterLink} to="/signup" underline="always">
                    Sign up
                  </Link>
                  .
                </Typography>
              </Box>
            </CardContent>
          </Card>

          {/* Passkey card */}
          <Card sx={authStyles.passkeyCard} variant="outlined">
            <CardContent sx={authStyles.passkeyCardContent}>
              <Button variant="contained" disabled startIcon={<FiKey />} sx={authStyles.passkeyButton}>
                Log in with a Passkey
              </Button>
              <Typography variant="body2" color="text.secondary">
                (Coming soon.)
              </Typography>
            </CardContent>
          </Card>
        </Box>
      </Box>
    </Box>
  )
}
