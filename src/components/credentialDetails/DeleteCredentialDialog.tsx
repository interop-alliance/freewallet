import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle
} from '@mui/material'
import { useTranslation } from 'react-i18next'

/**
 * Confirmation dialog shown when deleting a credential that has a public link.
 * Lets the user keep the public copy (remove the private one only) or delete
 * everything.
 */
export function DeleteCredentialDialog({
  open,
  busy = false,
  onKeepPublic,
  onDeleteAll,
  onCancel
}: {
  open: boolean
  busy?: boolean
  onKeepPublic: () => void
  onDeleteAll: () => void
  onCancel: () => void
}) {
  const { t } = useTranslation()

  return (
    <Dialog open={open} onClose={onCancel}>
      <DialogTitle>{t('credential.deleteDialog.title')}</DialogTitle>
      <DialogContent>
        <DialogContentText>
          {t('credential.deleteDialog.message')}
        </DialogContentText>
      </DialogContent>
      <DialogActions sx={{ gap: 1, px: 3, pb: 2 }}>
        <Button onClick={onCancel} disabled={busy}>
          {t('common.cancel')}
        </Button>
        <Button onClick={onKeepPublic} disabled={busy}>
          {t('credential.deleteDialog.keepPublic')}
        </Button>
        <Button
          onClick={onDeleteAll}
          color="error"
          variant="contained"
          disabled={busy}
        >
          {t('credential.deleteDialog.deleteAll')}
        </Button>
      </DialogActions>
    </Dialog>
  )
}
