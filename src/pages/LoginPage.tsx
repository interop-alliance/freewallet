import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Link from '@mui/material/Link'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Link as RouterLink, useNavigate } from 'react-router'
import { authStyles } from '../styles/appStyles.ts'

export function LoginPage() {
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

        <Button
          variant="contained"
          sx={authStyles.actionButton}
          onClick={() => navigate('/dashboard')}
        >
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
