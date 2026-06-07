import { useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { BsAward } from 'react-icons/bs'
import { useLocation, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { useAuthStore } from '@/stores/authStore'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { getDisplayFields } from '@/lib/viewMappers/credentialDisplayFields'
import { DashboardLayout } from '@/components/DashboardLayout'
import { credentialCardStyles, dashboardStyles } from '@/styles/appStyles'

export function AcceptCredentialsPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const session = useAuthStore(state => state.session)
  const [saving, setSaving] = useState(false)
  const [storeError, setStoreError] = useState(false)

  const credentials = (location.state?.credentials ??
    []) as IVerifiableCredential[]

  if (credentials.length === 0) {
    navigate('/dashboard')
    return
  }

  async function handleAcceptAll() {
    if (!session) {
      return
    }
    setSaving(true)
    setStoreError(false)
    try {
      for (const credential of credentials) {
        console.log('Storing credential:', credentialTitle(credential))
        await session.storage.addCredential({ credential })
      }
      navigate('/dashboard')
    } catch (err) {
      console.error('Error storing credentials:', err)
      setStoreError(true)
      setSaving(false)
    }
  }

  function handleCancel() {
    navigate('/dashboard')
  }

  return (
    <DashboardLayout title={t('acceptCredentials.title')}>
      {storeError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {t('acceptCredentials.storeError')}
        </Alert>
      )}
      <Stack sx={dashboardStyles.acceptCredentialsList}>
        {credentials.map((vc, i) => {
          const { credentialDescription } = getDisplayFields(vc)
          const description =
            credentialDescription.trim() !== ''
              ? credentialDescription
              : t('common.noDescription')

          return (
            <Card key={i} variant="outlined">
              <CardContent sx={credentialCardStyles.cardContent}>
                <Typography
                  variant="subtitle1"
                  gutterBottom
                  sx={credentialCardStyles.title}
                >
                  {credentialTitle(vc)}
                </Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={credentialCardStyles.description}
                >
                  {description}
                </Typography>
                <Box sx={credentialCardStyles.badge}>
                  <BsAward size={28} />
                </Box>
              </CardContent>
            </Card>
          )
        })}
      </Stack>

      <Stack direction="row" spacing={2} sx={{ mt: 3 }}>
        <Button
          variant="contained"
          onClick={handleAcceptAll}
          disabled={saving}
          sx={dashboardStyles.addCredentialButton}
        >
          {saving ? t('common.saving') : t('acceptCredentials.acceptAll')}
        </Button>
        <Button
          variant="outlined"
          onClick={handleCancel}
          disabled={saving}
          sx={dashboardStyles.addCredentialButton}
        >
          {t('common.cancel')}
        </Button>
      </Stack>
    </DashboardLayout>
  )
}
