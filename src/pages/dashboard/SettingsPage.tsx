import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { DashboardLayout } from '@/components/DashboardLayout'
import { dashboardStyles } from '@/styles/appStyles'
import { deleteAccount } from '@/lib/deleteAccount'

export function SettingsPage() {
  return (
    <DashboardLayout title="Settings">
      <Stack direction="row" sx={dashboardStyles.settingsRow}>
        <Button
          variant="contained"
          disableElevation
          sx={dashboardStyles.deleteAccountButton}
          onClick={deleteAccount}
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
