import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useNavigate } from 'react-router'
import { authStyles } from '@/styles/appStyles.ts'

export function SignupPage() {
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
        <TextField
          id="signup-email"
          defaultValue="alice@example.com"
          type="email"
          sx={authStyles.input}
        />

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

        <Button
          variant="contained"
          sx={authStyles.actionButton}
          onClick={() => navigate('/dashboard')}
        >
          Create Wallet
        </Button>
      </Box>
    </Box>
  )
}
