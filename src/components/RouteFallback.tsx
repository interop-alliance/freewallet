/**
 * Suspense fallback shown while a lazily-loaded route chunk is being fetched.
 * Renders a centered spinner that fills the available viewport.
 */
import Box from '@mui/material/Box'
import CircularProgress from '@mui/material/CircularProgress'

export function RouteFallback() {
  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh'
      }}
    >
      <CircularProgress />
    </Box>
  )
}
