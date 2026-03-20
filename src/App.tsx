import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Drawer from '@mui/material/Drawer'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Toolbar from '@mui/material/Toolbar'
import Typography from '@mui/material/Typography'
import { FaGhost } from 'react-icons/fa'
import { Link as RouterLink, Route, Routes, useNavigate } from 'react-router'
import walletIcon from './assets/wallet.svg'
import { authStyles, dashboardStyles } from './styles/appStyles.ts'
import { landingStyles } from './styles/landingStyles.ts'

function LandingPage() {
  return (
    <Box component="main" sx={landingStyles.main}>
      <Box sx={landingStyles.content}>
        <Typography variant="h2" component="h1" sx={landingStyles.title}>
          Freewallet
        </Typography>

        <Typography variant="h6" component="p" sx={landingStyles.subtitle}>
          is an open source, open specs web app for managing{' '}
          <Link href="#" underline="always" sx={landingStyles.link}>
            Verifiable Credentials
          </Link>
          ,{' '}
          <Link href="#" underline="always" sx={landingStyles.link}>
            DIDs
          </Link>
          , and{' '}
          <Link href="#" underline="always" sx={landingStyles.link}>
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
            sx={{ ...landingStyles.button, ...landingStyles.guestButton }}
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

function LoginPage() {
  const navigate = useNavigate()

  return (
    <Box component="main" sx={authStyles.page}>
      <Box sx={authStyles.content}>
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
          id="login-passphrase"
          defaultValue="not a real password"
          type="password"
          autoComplete="current-password"
          sx={authStyles.input}
        />

        <Button variant="contained" sx={authStyles.actionButton} onClick={() => navigate('/dashboard')}>
          Go
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

function SignupPage() {
  const navigate = useNavigate()

  return (
    <Box component="main" sx={authStyles.page}>
      <Box sx={authStyles.content}>
        <Typography variant="h2" component="h1" sx={authStyles.title}>
          Freewallet
        </Typography>
        <Typography variant="h3" component="h2" sx={authStyles.title}>
          Sign up
        </Typography>

        <Typography variant="h5" component="label" htmlFor="signup-email">
          Email:
        </Typography>
        <TextField id="signup-email" defaultValue="alice@example.com" type="email" sx={authStyles.input} />

        <Typography variant="h5" component="label" htmlFor="signup-passphrase">
          Passphrase:
        </Typography>
        <TextField
          id="signup-passphrase"
          defaultValue="not a real password"
          type="password"
          autoComplete="new-password"
          sx={authStyles.input}
        />

        <Button variant="contained" sx={authStyles.actionButton} onClick={() => navigate('/dashboard')}>
          Create Wallet
        </Button>
      </Box>
    </Box>
  )
}

function GuestLoginPage() {
  const navigate = useNavigate()

  return (
    <Box component="main" sx={authStyles.page}>
      <Box sx={authStyles.content}>
        <Typography variant="h2" component="h1" sx={authStyles.title}>
          Freewallet
        </Typography>
        <Typography variant="h3" component="h2" sx={authStyles.title}>
          <Box component="span" sx={authStyles.guestIcon}>
            <FaGhost />
          </Box>
          Guest Mode Login
        </Typography>

        <Typography variant="h5" component="p">
          - a random login will be created
        </Typography>
        <Typography variant="h5" component="p">
          - login and storage will be deleted at end of session
        </Typography>

        <Button variant="contained" sx={authStyles.actionButton} onClick={() => navigate('/dashboard')}>
          Go
        </Button>
      </Box>
    </Box>
  )
}

function DashboardPage() {
  const navigate = useNavigate()

  return (
    <Box sx={dashboardStyles.container}>
      <Drawer variant="permanent" sx={dashboardStyles.drawer}>
        <Toolbar />
        <Box sx={dashboardStyles.navHeader}>
          <Stack direction="row" spacing={1.5} alignItems="center">
            <Box component="img" src={walletIcon} alt="Wallet icon" sx={dashboardStyles.walletIcon} />
            <Typography variant="h5" component="p" fontWeight={600}>
              Freewallet
            </Typography>
          </Stack>
        </Box>
      </Drawer>

      <Box component="main" sx={dashboardStyles.main}>
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Typography variant="h2" component="h1" sx={dashboardStyles.title}>
            Freewallet Dashboard
          </Typography>
          <Button variant="outlined" onClick={() => navigate('/')}>
            Log out
          </Button>
        </Stack>
      </Box>
    </Box>
  )
}

function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/signup" element={<SignupPage />} />
      <Route path="/guest-login" element={<GuestLoginPage />} />
      <Route path="/dashboard" element={<DashboardPage />} />
    </Routes>
  )
}

export default App
