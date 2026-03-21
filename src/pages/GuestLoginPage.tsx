import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import { FaGhost } from 'react-icons/fa'
import { useNavigate } from 'react-router'
import { authStyles } from '../styles/appStyles.ts'

export function GuestLoginPage() {
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

        <Button
          variant="contained"
          sx={authStyles.actionButton}
          onClick={() => navigate('/dashboard')}
        >
          Go
        </Button>
      </Box>
    </Box>
  )
}
