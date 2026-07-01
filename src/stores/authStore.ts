import { create } from 'zustand'
import type { Session } from '@/types/auth'
import { syncController } from '@/stores/syncController'

interface AuthState {
  // Typically, Session would be persisted to sessionStorage
  // or a cookie
  // For the moment, we're keeping these in-memory only,
  // which means it will get cleared on page refresh
  session: Session | null
  login: (session: Session) => void
  logout: () => Promise<void>
}

export const useAuthStore = create<AuthState>()((set, get) => ({
  session: null,
  login: (session: Session) => {
    set({ session })
    // Kick off background replication (no-op for guests / no remote replica).
    // Fire-and-forget: the controller self-manages its errors and status.
    void syncController.start({ session })
  },
  logout: async () => {
    console.log('Clearing session...')
    await syncController.stop()
    // Release the local RxDB database owned by the session's storage (data
    // stays in IndexedDB; only the passphrase-derived session is discarded).
    await get().session?.storage.close()
    set({ session: null })
  }
}))
