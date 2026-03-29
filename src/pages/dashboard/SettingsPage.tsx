import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { DashboardLayout } from '@/components/DashboardLayout'
import { dashboardStyles } from '@/styles/appStyles'
import { useEffect } from 'react'
import { useAuthStore } from '@/stores/authStore'

export function SettingsPage() {
  const session = useAuthStore(state => state.session)

  useEffect(() => {
    console.log('Session:', session)
  })

  const handleDeleteAccount = async () => {
    if (!session) {
      return
    }
    const confirmed = window.confirm(
      'Are you sure you want to delete your account? This action cannot be undone.'
    )
    if (!confirmed) {
      return
    }
    try {
      console.log('Wiping user data...')
      await session.storage?.wipeStorage({ profile: session.profile })
    } catch (e) {
      console.error('Error wiping user data:', e)
    }
    window.location.href = '/' // hard reload
    return
  }

  return (
    <DashboardLayout title="Settings">
      <Stack direction="row" sx={dashboardStyles.settingsRow}>
        <Button
          variant="contained"
          disableElevation
          sx={dashboardStyles.deleteAccountButton}
          onClick={handleDeleteAccount}
        >
          Delete Account
        </Button>
        <Typography
          variant="h5"
          component="p"
          sx={dashboardStyles.deleteAccountDescription}
        >
          Your login, keys, and all data will be deleted.
        </Typography>
      </Stack>
    </DashboardLayout>
  )
}
