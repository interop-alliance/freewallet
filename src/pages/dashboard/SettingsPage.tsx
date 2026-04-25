import Button from '@mui/material/Button'
import Divider from '@mui/material/Divider'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { DashboardLayout } from '@/components/DashboardLayout'
import { useInfoBox } from '@/hooks/useInfoBox'
import { dashboardStyles } from '@/styles/appStyles'
import { useEffect } from 'react'
import { useAuthStore } from '@/stores/authStore'

export function SettingsPage() {
  const session = useAuthStore(state => state.session)
  const { displayInfoBox } = useInfoBox()

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
      <Stack sx={{ mt: 4, gap: 4, maxWidth: 640 }}>
        <Stack direction="row" sx={{ alignItems: 'center', gap: 3 }}>
          <Typography variant="h6">
            Verifiable Credentials
          </Typography>
          <Button
            variant="outlined"
            size="small"
            sx={{
              textTransform: 'none',
              borderRadius: 2,
              whiteSpace: 'nowrap'
            }}
            onClick={() =>
              displayInfoBox({ docUrl: 'vcs', title: 'Verifiable Credentials' })
            }
          >
            More Info
          </Button>
        </Stack>

        <Divider />

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

        <Divider />

        <Stack sx={{ gap: 1 }}>
          <Typography variant="h6">
            About
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Freewallet version {__APP_VERSION__}
          </Typography>
        </Stack>
      </Stack>
    </DashboardLayout>
  )
}
