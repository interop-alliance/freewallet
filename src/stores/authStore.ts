import { create } from 'zustand'
import type { Session } from '@/types/auth'
import { syncController } from '@/stores/syncController'

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
        await syncController.stop()
        try {
          await previous.storage.close()
        } catch (err) {
          console.warn('Could not close the replaced session storage:', err)
        }
      }
      await syncController.restart({ session })
    })()
  },
  logout: async () => {
    await syncController.stop()
    // Release the local RxDB database owned by the session's storage (data
    // stays in IndexedDB; only the passphrase-derived session is discarded).
    await get().session?.storage.close()
    publishStorageSeam(null)
    set({ session: null })
  }
}))
