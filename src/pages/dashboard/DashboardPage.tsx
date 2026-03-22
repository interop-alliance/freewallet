import Button from '@mui/material/Button'
import { useAuthStore } from '@/stores/authStore'
import { useEffect } from 'react'
import { DashboardLayout } from '@/components/DashboardLayout'

export function DashboardPage() {
  const session = useAuthStore(state => state.session)
  const logout = useAuthStore(state => state.logout)

  useEffect(() => {
    console.log('Dashboard, logged in:', session)
  }, [session])

  const handleLogout = () => {
    logout() // clears session
  }

  return (
    <DashboardLayout
      title="Freewallet Dashboard"
      actions={
        <Button variant="outlined" onClick={handleLogout}>
          Log out
        </Button>
      }
    />
  )
}
