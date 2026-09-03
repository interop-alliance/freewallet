import { create } from 'zustand'
import type { Session } from '@/types/auth'
import { isBrowserLocalSession } from '@/session/persistence'
import { setTransientPrefs } from '@/lib/prefsStorage'
import { syncController } from '@/stores/syncController'
import { discardSession } from '@/stores/sessionTeardown'
import { clearSetup } from '@/stores/setupStore'

/**
 * E2E test seam. Space export / import (and the collection delete a round-trip
 * needs) are ZCap-signed operations that only the live in-memory session can
 * authorize,
 * and the session is never otherwise reachable from page context. In
 * non-production builds only, publish the active `StorageManager` on
 * `window.__E2E_STORAGE__` so a Playwright spec can drive an export -> import
 * round-trip through the real signer. Cleared on logout. No-op in production.
 */
function publishStorageSeam(session: Session | null): void {
  if (import.meta.env.MODE === 'production') {
    return
  }
  ;(
    window as unknown as { __E2E_STORAGE__?: Session['storage'] }
  ).__E2E_STORAGE__ = session?.storage
}

/**
 * E2E test seam. Navigation to the dashboard waits on storage provisioning
 * alone, so the login-time pass chain (`session.registryReady`) and the annex
 * GC sweep forked off its tail (`session.clientAnnexGcSweep`) are still in
 * flight when a spec's fixture reaches the dashboard. A fixture that closes
 * its browser context there aborts the chain wherever it happens to be, and
 * the account it leaves behind depends on which pass got in first. In
 * non-production builds only, publish a waiter on
 * `window.__E2E_LOGIN_CHAIN_SETTLED__` so a Playwright fixture can let the
 * chain finish before it tears the context down. Neither promise rejects.
 * Cleared on logout. No-op in production.
 */
function publishLoginChainSeam(session: Session | null): void {
  if (import.meta.env.MODE === 'production') {
    return
  }
  ;(
    window as unknown as {
      __E2E_LOGIN_CHAIN_SETTLED__?: () => Promise<void>
    }
  ).__E2E_LOGIN_CHAIN_SETTLED__ = session
    ? async () => {
        await session.registryReady
        await session.clientAnnexGcSweep
      }
    : undefined
}

interface AuthState {
  // The session lives in-memory only (the passphrase-derived keys are never
  // persisted); a page refresh discards it and logs the user out.
  session: Session | null
  login: (session: Session) => void
  logout: () => Promise<void>
}

export const useAuthStore = create<AuthState>()((set, get) => ({
  session: null,
  login: (session: Session) => {
    const previous = get().session
    set({ session })
    publishStorageSeam(session)
    publishLoginChainSeam(session)
    // The UI-prefs sibling of the persistence strategy: while a transient
    // session is live, theme/language toggles land in an in-memory overlay
    // instead of localStorage (`src/lib/prefsStorage.ts`).
    setTransientPrefs({
      active: !isBrowserLocalSession(session.profile.persistence)
    })
    // Kick off background replication (no-op for guests / no remote replica).
    // `restart` (not `start`) so a controller left running by a previous
    // session -- a switch to a second account without an intervening logout --
    // is stopped before the new one starts; a bare `start()` would no-op on
    // its already-running guard and silently never replicate. Fire-and-forget
    // keeps login non-blocking; `restart` serializes the stop-then-start
    // internally so the ordering holds. The controller self-manages its errors
    // and status.
    //
    // Switching accounts without an intervening /logout is reachable (/login has
    // no logged-in redirect), so the replaced session's storage must be closed
    // or its RxDB/IndexedDB connection would leak. Mirror logout's teardown
    // order -- replication stopped before the database closes -- then restart
    // for the new session. All fire-and-forget, so login stays non-blocking.
    void (async () => {
      if (previous && previous !== session) {
        await discardSession(previous)
      }
      await syncController.restart({ session })
    })()
  },
  logout: async () => {
    // Replication stopped, then the local RxDB database released (data stays
    // in IndexedDB; only the passphrase-derived session is discarded).
    await discardSession(get().session)
    // A setup run parked in the setup store outlives this session otherwise,
    // and a later `/lobby` mount would enter the account it holds.
    clearSetup()
    publishStorageSeam(null)
    publishLoginChainSeam(null)
    setTransientPrefs({ active: false })
    set({ session: null })
  }
}))
