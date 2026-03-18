import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Link from '@mui/material/Link'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { FaGhost } from 'react-icons/fa'

function App() {
  return (
    <Box
      component="main"
      sx={{
        minHeight: '100dvh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        px: 2,
      }}
    >
      <Box sx={{ textAlign: 'center', maxWidth: 760, width: '100%' }}>
        <Typography
          variant="h2"
          component="h1"
          sx={{ fontWeight: 500, mb: 2, fontSize: { xs: '2.2rem', sm: '3rem' } }}
        >
          Freewallet
        </Typography>

        <Typography
          variant="h6"
          component="p"
          sx={{
            color: 'text.secondary',
            fontWeight: 400,
            lineHeight: 1.45,
            mb: 6,
            maxWidth: 620,
            mx: 'auto',
            fontSize: { xs: '1.125rem', sm: '1.45rem' },
          }}
        >
          is an open source, open specs web app for managing{' '}
          <Link href="#" underline="always">
            Verifiable Credentials
          </Link>
          ,{' '}
          <Link href="#" underline="always">
            DIDs
          </Link>
          , and{' '}
          <Link href="#" underline="always">
            keys
          </Link>
          .
        </Typography>

        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          spacing={2}
          justifyContent="center"
          alignItems="stretch"
        >
          <Button variant="contained" color="primary" size="large" sx={{ minWidth: 180, py: 1.25 }}>
            Log in
          </Button>
          <Button variant="outlined" color="primary" size="large" sx={{ minWidth: 180, py: 1.25 }}>
            Sign Up
          </Button>
          <Button
            variant="contained"
            color="secondary"
            size="large"
            startIcon={<FaGhost />}
            sx={{ minWidth: 230, py: 1.25, textTransform: 'uppercase', letterSpacing: 0.8 }}
          >
            Guest Mode
          </Button>
        </Stack>
      </Box>
    </Box>
  )
}

export default App
