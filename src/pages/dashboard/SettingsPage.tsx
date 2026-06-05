import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Divider from '@mui/material/Divider'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { useInfoBox } from '@/hooks/useInfoBox'
import { dashboardStyles } from '@/styles/appStyles'
import { useState } from 'react'
import { useAuthStore } from '@/stores/authStore'

export function SettingsPage() {
  const { t } = useTranslation()
  const session = useAuthStore(state => state.session)
  const { displayInfoBox } = useInfoBox()
  const [deleteError, setDeleteError] = useState(false)

  const handleDeleteAccount = async () => {
    if (!session) {
      return
    }
    const confirmed = window.confirm(t('settings.deleteConfirm'))
    if (!confirmed) {
      return
    }
    setDeleteError(false)
    try {
      console.log('Wiping user data...')
      await session.storage?.wipeStorage({ profile: session.profile })
    } catch (err: any) {
      // Do not log the user out if the wipe failed -- surface the error so
      // they know their remote data is still present.
      console.error('Error wiping user data:', err)
      setDeleteError(true)
      return
    }
    window.location.href = '/' // hard reload
    return
  }

  return (
    <DashboardLayout title={t('settings.title')}>
      <Stack sx={{ mt: 4, gap: 4, maxWidth: 640 }}>
        <Stack direction="row" sx={{ alignItems: 'center', gap: 3 }}>
          <Typography variant="h6">{t('settings.vcSection')}</Typography>
          <Button
            variant="outlined"
            size="small"
            sx={{
              textTransform: 'none',
              borderRadius: 2,
              whiteSpace: 'nowrap'
            }}
            onClick={() =>
              displayInfoBox({
                docUrl: 'vcs',
                title: t('settings.vcSection')
              })
            }
          >
            {t('settings.moreInfo')}
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
            {t('settings.deleteAccount')}
          </Button>
          <Typography
            variant="h5"
            component="p"
            sx={dashboardStyles.deleteAccountDescription}
          >
            {t('settings.deleteAccountHint')}
          </Typography>
        </Stack>

        {deleteError && (
          <Alert severity="error">{t('settings.deleteError')}</Alert>
        )}

        <Divider />

        <Stack sx={{ gap: 1 }}>
          <Typography variant="h6">{t('settings.about')}</Typography>
          <Typography variant="body2" color="text.secondary">
            {t('settings.version', { version: __APP_VERSION__ })}
          </Typography>
        </Stack>
      </Stack>
    </DashboardLayout>
  )
}
