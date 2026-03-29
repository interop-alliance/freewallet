import { create } from 'zustand'
import type { Session } from '@/types/auth'

interface AuthState {
  // Typically, Session would be persisted to sessionStorage
  // or a cookie
  // For the moment, we're keeping these in-memory only,
  // which means it will get cleared on page refresh
  session: Session | null
  login: (session: Session) => void
  logout: (session: Session) => Promise<void>
}

export const useAuthStore = create<AuthState>()(set => ({
  session: null,
  login: (session: Session) => set({ session }),
  logout: async (session: Session) => {
    console.log('Clearing session...')
    try {
      await session.storage?.wipeStorage({ profile: session.profile })
    } catch (e) {
      console.error('Error wiping session:', e)
    }

    set({ session: null })
  }
}))
