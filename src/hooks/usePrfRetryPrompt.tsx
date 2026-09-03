/**
 * The WebAuthn PRF-retry consent prompt. Some authenticators evaluate the PRF
 * extension only during a second (assertion) ceremony, so `registerPasskey`
 * asks whether it may run one. This hook bridges that callback to a dialog: it
 * returns the `promptForPrfRetry` callback to hand to the ceremony (its promise
 * resolves on the user's choice) alongside the `dialog` element to render.
 *
 * The pending question itself lives in `src/stores/prfRetryStore.ts`, outside
 * the React tree, because the page that asked it may be gone by the time the
 * authenticator answers. Every page that may be mounted while a ceremony runs
 * renders the `dialog`; whichever one is mounted answers.
 */
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import { useTranslation } from 'react-i18next'
import { promptForPrfRetry, usePrfRetryStore } from '@/stores/prfRetryStore'

/**
 * Builds the PRF-retry consent prompt.
 *
 * @returns {{ promptForPrfRetry: () => Promise<boolean>, dialog: JSX.Element }}
 */
export function usePrfRetryPrompt() {
  const { t } = useTranslation()
  const open = usePrfRetryStore(state => state.open)
  const answer = usePrfRetryStore(state => state.answer)

  const dialog = (
    <Dialog open={open} onClose={() => answer(false)}>
      <DialogTitle>{t('settings.passkeyRetryTitle')}</DialogTitle>
      <DialogContent>
        <DialogContentText>
          {t('settings.passkeyRetryMessage')}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => answer(false)}>
          {t('settings.passkeyRetryCancel')}
        </Button>
        <Button variant="contained" onClick={() => answer(true)}>
          {t('settings.passkeyRetryConfirm')}
        </Button>
      </DialogActions>
    </Dialog>
  )

  return { promptForPrfRetry, dialog }
}
