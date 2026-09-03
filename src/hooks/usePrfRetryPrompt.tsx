/**
 * The WebAuthn PRF-retry consent prompt. Some authenticators evaluate the PRF
 * extension only during a second (assertion) ceremony, so `registerPasskey`
 * asks whether it may run one. This hook bridges that callback to a dialog: it
 * returns the `promptForPrfRetry` callback to hand to the ceremony (its promise
 * resolves on the user's choice) alongside the `dialog` element to render.
 *
 * The pending prompt lives in a module-level store rather than in component
 * state, because the signup wizard starts the passkey ceremony in its click
 * handler and immediately navigates to the lobby page: the page that asked
 * the question is gone by the time the authenticator answers, and only a
 * store-held resolver survives that. Every page that may be mounted while a
 * ceremony runs renders the `dialog`; whichever one is mounted answers.
 */
import { create } from 'zustand'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import { useTranslation } from 'react-i18next'

interface PrfRetryState {
  open: boolean
  resolve: ((consented: boolean) => void) | null
  ask: (resolve: (consented: boolean) => void) => void
  answer: (consented: boolean) => void
}

const usePrfRetryStore = create<PrfRetryState>()((set, get) => ({
  open: false,
  resolve: null,
  ask: resolve => set({ open: true, resolve }),
  answer: consented => {
    const { resolve } = get()
    set({ open: false, resolve: null })
    resolve?.(consented)
  }
}))

/**
 * Asks the user whether a second (assertion) WebAuthn ceremony may run.
 *
 * @returns {Promise<boolean>}   the user's choice
 */
export function promptForPrfRetry(): Promise<boolean> {
  return new Promise<boolean>(resolve => {
    usePrfRetryStore.getState().ask(resolve)
  })
}

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
