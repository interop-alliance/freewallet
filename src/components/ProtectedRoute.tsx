import { Navigate, Outlet } from 'react-router'
import { useAuthStore } from '@/stores/authStore.ts'

export function ProtectedRoute() {
  const session = useAuthStore(state => state.session)

  if (!session) {
    return <Navigate to="/" replace />
  }
  return <Outlet />
}
