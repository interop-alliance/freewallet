/**
 * The spinner both CHAPI popup pages show while they set the request up, before
 * there is anything to consent to.
 */
import Box from '@mui/material/Box'
import CircularProgress from '@mui/material/CircularProgress'
import { chapiStyles } from '@/styles/appStyles'

/**
 * Renders the CHAPI popup's initializing state.
 *
 * @returns {JSX.Element}
 */
export function ChapiInitializing() {
  return (
    <Box className="fw-page" sx={{ ...chapiStyles.page, alignItems: 'center' }}>
      <CircularProgress />
    </Box>
  )
}
