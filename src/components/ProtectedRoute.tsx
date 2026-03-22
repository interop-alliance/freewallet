import { Navigate, Outlet, useLocation } from 'react-router'
import { useAuthStore } from '@/stores/authStore.ts'

export function ProtectedRoute() {
  const session = useAuthStore(state => state.session)
  const location = useLocation()

  if (!session) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }
  return <Outlet />
}
