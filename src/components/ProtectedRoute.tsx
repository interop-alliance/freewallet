import { Navigate, Outlet } from 'react-router'
import { useAuthStore } from '@/stores/authStore'

export function ProtectedRoute() {
  const session = useAuthStore(state => state.session)

  if (!session) {
    return <Navigate to="/logout" replace />
  }

  return <Outlet />
}
