/**
 * Zustand store holding the single transient toast (snackbar) message the app
 * shows at a time. It lives outside the React tree on purpose: a page can post
 * a toast and immediately navigate away (deleting a credential posts
 * "Credential deleted." then routes back to the dashboard), and the message
 * still reaches the `Toast` component the destination page renders. In-memory
 * only; not persisted.
 */
import { create } from 'zustand'

export type ToastSeverity = 'success' | 'info' | 'warning' | 'error'

export interface Toast {
  /** Already-translated text -- callers pass `t(...)`, not a key. */
  message: string
  severity: ToastSeverity
  /** Bumped per toast so two identical messages in a row still re-open. */
  id: number
}

interface ToastState {
  toast: Toast | null
  showToast: (options: { message: string; severity?: ToastSeverity }) => void
  hideToast: () => void
}

export const useToastStore = create<ToastState>()((set, get) => ({
  toast: null,
  showToast: ({ message, severity = 'success' }) =>
    set({ toast: { message, severity, id: (get().toast?.id ?? 0) + 1 } }),
  hideToast: () => set({ toast: null })
}))

/**
 * Posts a toast from outside a component (event handlers, plain modules).
 *
 * @param options {object}
 * @param options.message {string} Translated message text.
 * @param [options.severity] {ToastSeverity} Defaults to `success`.
 */
export function showToast(options: {
  message: string
  severity?: ToastSeverity
}) {
  useToastStore.getState().showToast(options)
}
