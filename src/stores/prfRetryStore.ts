/**
 * The pending WebAuthn PRF-retry question: whether a second (assertion)
 * ceremony may run, and the resolver waiting on the answer.
 *
 * It lives in a module-level store rather than in component state because the
 * signup wizard starts the passkey ceremony in its click handler and
 * immediately navigates to the lobby: the page that asked the question is
 * gone by the time the authenticator answers, and only a store-held resolver
 * survives that. `usePrfRetryPrompt` renders the dialog over this state;
 * whichever page is mounted answers.
 */
import { create } from 'zustand'

interface PrfRetryState {
  open: boolean
  resolve: ((consented: boolean) => void) | null
  ask: (resolve: (consented: boolean) => void) => void
  answer: (consented: boolean) => void
  reset: () => void
}

export const usePrfRetryStore = create<PrfRetryState>()((set, get) => ({
  open: false,
  resolve: null,
  ask: resolve => {
    // A pending question is settled before this one takes its place.
    // Overwriting the resolver would leave the ceremony that installed it
    // awaiting an answer nobody can give any more.
    const pending = get().resolve
    set({ open: true, resolve })
    pending?.(false)
  },
  answer: consented => {
    const { resolve } = get()
    set({ open: false, resolve: null })
    resolve?.(consented)
  },
  reset: () => {
    const { resolve } = get()
    set({ open: false, resolve: null })
    resolve?.(false)
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
 * Drops any pending question: the dialog closes and the question resolves
 * `false` (declined). The setup store calls it whenever a run is cleared or
 * abandoned, and the auth store on logout, so an unanswered question can
 * never outlive the ceremony that raised it and pop on the next page that
 * renders the dialog.
 */
export function resetPrfRetryPrompt(): void {
  usePrfRetryStore.getState().reset()
}
