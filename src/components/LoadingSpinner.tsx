import Box from '@mui/material/Box'
import CircularProgress from '@mui/material/CircularProgress'
import { loadingSpinnerStyles } from '@/styles/appStyles'

export function LoadingSpinner() {
  return (
    <Box sx={loadingSpinnerStyles}>
      <CircularProgress />
    </Box>
  )
}
