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
  // The full session lives in-memory only (the passphrase-derived keys are
  // never persisted). What survives a refresh is the *delegated* session:
  // zcaps persisted at login alongside a non-extractable browser session key
  // (src/session/delegatedSession.ts), restored once by `restore()`.
  session: Session | null
  // Boot-time restore gate: ProtectedRoute waits for 'done' before treating
  // a missing session as logged-out (otherwise a refresh would bounce to
  // /logout and wipe the persisted session records).
  restoreStatus: 'idle' | 'restoring' | 'done'
  login: (session: Session) => void
  restore: () => Promise<void>
  logout: () => Promise<void>
}

export const useAuthStore = create<AuthState>()((set, get) => ({
  session: null,
  restoreStatus: 'idle',
  login: (session: Session) => {
    set({ session, restoreStatus: 'done' })
    publishStorageSeam(session)
    // Kick off background replication (no-op for guests / no remote replica).
    // `restart` (not `start`) so a controller left running by a previous
    // session -- a restored delegated session being upgraded by re-login, or a
    // switch to a second account without an intervening logout -- is stopped
    // before the new one starts; a bare `start()` would no-op on its already-
    // running guard and silently never replicate. Fire-and-forget keeps login
    // non-blocking; `restart` serializes the stop-then-start internally so the
    // ordering holds. The controller self-manages its errors and status.
    void syncController.restart({ session })
    // Mint and persist the refresh-survival zcaps (full sessions only --
    // a delegated session cannot delegate). Fire-and-forget: failure only
    // costs refresh-survival, never the login. Dynamically imported so the
    // eager auth store stays light.
    if (session.tier === 'full') {
      void import('@/session/delegatedSession')
        .then(({ persistDelegatedSession }) =>
          persistDelegatedSession({ session })
        )
        .catch((err: unknown) => {
          console.warn('Could not persist the delegated session:', err)
        })
    }
  },
  restore: async () => {
    if (get().session || get().restoreStatus !== 'idle') {
      return
    }
    set({ restoreStatus: 'restoring' })
    try {
      const { restoreDelegatedSession } =
        await import('@/session/delegatedSession')
      const session = await restoreDelegatedSession()
      if (session) {
        // Opens the local RxDB collections (and rebuilds the remote
        // collection map) so pages and replication find them, exactly as a
        // fresh login does -- without any remote provisioning writes.
        await session.storage.ensureUserCollections({ user: session.user })
        set({ session })
        publishStorageSeam(session)
        // At boot the controller singleton is freshly constructed, so no prior
        // session's replication can be running here; `restart` (rather than
        // `start`) is nonetheless used for uniformity with the login path and
        // to defensively tear down any stale controller before starting. The
        // internal stop-then-start is a no-op on an empty controller.
        void syncController.restart({ session })
      }
    } catch (err) {
      console.warn('Could not restore a delegated session:', err)
    } finally {
      set({ restoreStatus: 'done' })
    }
  },
  logout: async () => {
    await syncController.stop()
    const { session } = get()
    // Revoke the persisted session's keystore zcap (best-effort) and delete
    // the local session records + session key, so the next load cannot
    // restore a session the user just ended.
    try {
      const { endDelegatedSession } = await import('@/session/delegatedSession')
      await endDelegatedSession({ session })
    } catch (err) {
      console.warn('Could not end the persisted session:', err)
    }
    // Release the local RxDB database owned by the session's storage (data
    // stays in IndexedDB; only the passphrase-derived session is discarded).
    await get().session?.storage.close()
    publishStorageSeam(null)
    set({ session: null, restoreStatus: 'done' })
  }
}))
