import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { FaGhost } from 'react-icons/fa'
import { Link as RouterLink } from 'react-router'
import { landingStyles } from '@/styles/landingStyles'
import { useEffect } from 'react'
import { useAuthStore } from '@/stores/authStore'
import { WAS_SERVER_URL } from '@/app.config'

export function LandingPage() {
  const session = useAuthStore(state => state.session)
  useEffect(() => {
    console.log('Landing page, session:', session)
    console.log('WAS_SERVER_URL:', WAS_SERVER_URL)
  }, [session])

  return (
    <Box component="main" sx={landingStyles.main}>
      <Box sx={landingStyles.content}>
        <Typography variant="h2" component="h1" sx={landingStyles.title}>
          Freewallet
        </Typography>

        <Typography variant="h6" component="p" sx={landingStyles.subtitle}>
          is an open source, open specs web app for managing{' '}
          <Link component={RouterLink} to="/docs/vcs" underline="always" sx={landingStyles.link}>
            Verifiable Credentials
          </Link>
          ,{' '}
          <Link component={RouterLink} to="/docs/dids" underline="always" sx={landingStyles.link}>
            DIDs
          </Link>
          , and{' '}
          <Link component={RouterLink} to="/docs/keys" underline="always" sx={landingStyles.link}>
            keys
          </Link>
          .
        </Typography>

        <Stack sx={landingStyles.actions}>
          <Button
            variant="contained"
            color="primary"
            size="large"
            sx={landingStyles.button}
            component={RouterLink}
            to="/login"
          >
            Log in
          </Button>
          <Button
            variant="outlined"
            color="primary"
            size="large"
            sx={landingStyles.button}
            component={RouterLink}
            to="/signup"
          >
            Sign Up
          </Button>
          <Button
            variant="contained"
            color="secondary"
            size="large"
            startIcon={<FaGhost />}
            sx={{ ...landingStyles.button, ...landingStyles.guestModeButton }}
            component={RouterLink}
            to="/guest-login"
          >
            Guest Mode
          </Button>
        </Stack>
      </Box>
    </Box>
  )
}
