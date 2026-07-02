import { useEffect } from 'react'
import { Navigate, Outlet } from 'react-router'
import { useAuthStore } from '@/stores/authStore'
import { RouteFallback } from '@/components/RouteFallback'

export function ProtectedRoute() {
  const session = useAuthStore(state => state.session)
  const restoreStatus = useAuthStore(state => state.restoreStatus)
  const restore = useAuthStore(state => state.restore)

  // With no in-memory session, first try to restore the persisted delegated
  // session (a refresh survivor). Only after that attempt settles does a
  // missing session mean logged-out -- redirecting to /logout any earlier
  // would delete the very records the restore needs.
  useEffect(() => {
    if (!session && restoreStatus === 'idle') {
      void restore()
    }
  }, [session, restoreStatus, restore])

  if (session) {
    return <Outlet />
  }
  if (restoreStatus !== 'done') {
    return <RouteFallback />
  }
  return <Navigate to="/logout" replace />
}
