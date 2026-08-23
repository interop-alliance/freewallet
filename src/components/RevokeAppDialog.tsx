/**
 * Confirmation dialog for revoking a connected application's access, shared by
 * the Applications list and the application detail page. An orphaned app (one
 * whose recorded grants were all signed by a since-disconnected wallet client)
 * gets its own wording, since its grants already stopped verifying.
 *
 * The same dialog confirms revoking a connected AGENT (`agent`), whose copy
 * speaks only of the storage grants: an agent holds no app key to delete and
 * is no collection's epoch recipient, so nothing is rotated.
 */
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import { useTranslation } from 'react-i18next'

/**
 * Renders the revoke-access confirmation dialog.
 *
 * @param options {object}
 * @param options.open {boolean}
 * @param options.appName {string}   the app's (or agent's) display name
 * @param [options.agent] {boolean}   whether the row is an agent rather than
 *   an App Connect application
 * @param options.orphaned {boolean}   whether the grants are orphaned
 * @param options.revoking {boolean}   whether a revocation is in flight
 * @param options.error {boolean}   whether the last attempt failed
 * @param options.onCancel {Function}
 * @param options.onConfirm {Function}
 * @returns {JSX.Element}
 */
export function RevokeAppDialog({
  open,
  appName,
  agent = false,
  orphaned,
  revoking,
  error,
  onCancel,
  onConfirm
}: {
  open: boolean
  appName: string
  agent?: boolean
  orphaned: boolean
  revoking: boolean
  error: boolean
  onCancel: () => void
  onConfirm: () => void
}) {
  const { t } = useTranslation()

  return (
    <Dialog
      open={open}
      onClose={() => {
        if (!revoking) {
          onCancel()
        }
      }}
    >
      <DialogTitle>
        {t(
          agent ? 'applications.revokeAgentTitle' : 'applications.revokeTitle'
        )}
      </DialogTitle>
      <DialogContent>
        <DialogContentText>
          {t(
            agent
              ? orphaned
                ? 'applications.revokeAgentConfirmOrphaned'
                : 'applications.revokeAgentConfirm'
              : orphaned
                ? 'applications.revokeConfirmOrphaned'
                : 'applications.revokeConfirm',
            { name: appName }
          )}
        </DialogContentText>
        {error && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {t(
              agent
                ? 'applications.revokeAgentFailed'
                : 'applications.revokeFailed'
            )}
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel} disabled={revoking}>
          {t('common.cancel')}
        </Button>
        <Button
          variant="contained"
          color="error"
          onClick={onConfirm}
          loading={revoking}
        >
          {t('applications.revokeConfirmAction')}
        </Button>
      </DialogActions>
    </Dialog>
  )
}
