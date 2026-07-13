/**
 * Renders the app's transient feedback messages (credential deleted, saved,
 * ...) as a MUI Snackbar. Rendered once by `DashboardLayout`, so any page can
 * post feedback through `useToastStore` without owning snackbar state -- and a
 * message posted just before navigating still shows on the page landed on.
 */
import Alert from '@mui/material/Alert'
import Snackbar from '@mui/material/Snackbar'
import { useToastStore } from '@/stores/toastStore'

const AUTO_HIDE_MS = 5000

export function Toast() {
  const toast = useToastStore(state => state.toast)
  const hideToast = useToastStore(state => state.hideToast)

  return (
    <Snackbar
      // Re-keying on the toast id restarts the auto-hide timer when a second
      // toast arrives while the first is still up.
      key={toast?.id}
      open={!!toast}
      autoHideDuration={AUTO_HIDE_MS}
      onClose={(_event, reason) => {
        // A click elsewhere on the page should not swallow the message.
        if (reason !== 'clickaway') {
          hideToast()
        }
      }}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
    >
      <Alert
        severity={toast?.severity ?? 'success'}
        variant="filled"
        onClose={hideToast}
        sx={{ width: '100%' }}
      >
        {toast?.message}
      </Alert>
    </Snackbar>
  )
}
