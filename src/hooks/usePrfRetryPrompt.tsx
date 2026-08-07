/**
 * The WebAuthn PRF-retry consent prompt. Some authenticators evaluate the PRF
 * extension only during a second (assertion) ceremony, so `registerPasskey`
 * asks whether it may run one. This hook bridges that callback to a dialog: it
 * returns the `promptForPrfRetry` callback to hand to the ceremony (its promise
 * resolves on the user's choice) alongside the `dialog` element to render.
 */
import { useRef, useState } from 'react'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import { useTranslation } from 'react-i18next'

/**
 * Builds the PRF-retry consent prompt.
 *
 * @returns {{ promptForPrfRetry: () => Promise<boolean>, dialog: JSX.Element }}
 */
export function usePrfRetryPrompt() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const resolveRef = useRef<((consented: boolean) => void) | null>(null)

  const promptForPrfRetry = (): Promise<boolean> => {
    setOpen(true)
    return new Promise<boolean>(resolve => {
      resolveRef.current = resolve
    })
  }

  const resolvePrfRetry = (consented: boolean) => {
    setOpen(false)
    resolveRef.current?.(consented)
    resolveRef.current = null
  }

  const dialog = (
    <Dialog open={open} onClose={() => resolvePrfRetry(false)}>
      <DialogTitle>{t('settings.passkeyRetryTitle')}</DialogTitle>
      <DialogContent>
        <DialogContentText>
          {t('settings.passkeyRetryMessage')}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => resolvePrfRetry(false)}>
          {t('settings.passkeyRetryCancel')}
        </Button>
        <Button variant="contained" onClick={() => resolvePrfRetry(true)}>
          {t('settings.passkeyRetryConfirm')}
        </Button>
      </DialogActions>
    </Dialog>
  )

  return { promptForPrfRetry, dialog }
}
