import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import { Link as RouterLink } from 'react-router'
import { notFoundStyles } from '@/styles/appStyles'

export function NotFoundPage() {
  return (
    <Box component="main" sx={notFoundStyles.page}>
      <Typography variant="h1" component="h1" fontWeight={600}>
        404
      </Typography>
      <Typography variant="h5" color="text.secondary">
        Page not found
      </Typography>
      <Button component={RouterLink} to="/" variant="outlined" sx={{ mt: 2 }}>
        Go home
      </Button>
    </Box>
  )
}
