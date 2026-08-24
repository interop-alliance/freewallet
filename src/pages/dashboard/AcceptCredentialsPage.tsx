import { useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { BsAward } from 'react-icons/bs'
import { Navigate, useLocation, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import {
  AppKeyRefusedError,
  presentsAsAppKey
} from '@interop/wallet-core/request'
import { useAuthStore } from '@/stores/authStore'
import { showToast } from '@/stores/toastStore'
import { cidFrom } from '@interop/was-client/sync'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { getDisplayFields } from '@/lib/viewMappers/credentialDisplayFields'
import { DashboardLayout } from '@/components/DashboardLayout'
import { credentialCardStyles, dashboardStyles } from '@/styles/appStyles'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:accept')

export function AcceptCredentialsPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const session = useAuthStore(state => state.session)
  const [saving, setSaving] = useState(false)
  const [storeError, setStoreError] = useState<string | null>(null)

  const credentials = (location.state?.credentials ??
    []) as IVerifiableCredential[]
  const importSummary = location.state?.importSummary as
    | {
        collectionsCreated: number
        collectionsSkipped: number
        resourcesCreated: number
        resourcesSkipped: number
      }
    | undefined

  if (credentials.length === 0) {
    // A render-phase navigate() is a silent no-op in React Router; returning a
    // <Navigate> element performs the redirect so a deep-linked visitor with no
    // incoming credentials is not left on a permanently blank page.
    return <Navigate to="/dashboard" replace />
  }

  async function handleAcceptAll() {
    if (!session) {
      return
    }
    setSaving(true)
    setStoreError(null)
    try {
      // Dedupe the incoming batch by content cid up front purely as an
      // optimization: `addCredential` is idempotent by content cid on its own
      // (its in-memory cid index no-ops a re-add regardless of batching), so this
      // just avoids a redundant encrypt per repeated VC and keeps the "stored"
      // toast count accurate.
      const uniqueCredentials: IVerifiableCredential[] = []
      const seenCids = new Set<string>()
      for (const credential of credentials) {
        const cid = await cidFrom({ doc: credential })
        if (seenCids.has(cid)) {
          continue
        }
        seenCids.add(cid)
        uniqueCredentials.push(credential)
      }
      // App keys are wallet-minted, never imported (`addCredential` refuses
      // them unconditionally), so screen them out of the batch up front
      // rather than letting the first one abort the loop half-stored -- the
      // user's own exported archive legitimately contains their app keys,
      // and the rest of the batch must still land. The skipped count is
      // reported alongside the stored count below.
      const storable = uniqueCredentials.filter(
        credential => !presentsAsAppKey(credential)
      )
      const appKeysSkipped = uniqueCredentials.length - storable.length
      for (const credential of storable) {
        log.debug('Storing credential', { title: credentialTitle(credential) })
        // addCredential records the credential-created history entry itself,
        // gated on an actual insert.
        await session.storage.addCredential({
          credential,
          user: session.user
        })
      }
      const storedMessage = importSummary
        ? t('storage.importSuccess', {
            ...importSummary,
            credentialsNote: t('storage.importCredentialsNote', {
              count: storable.length
            })
          })
        : t('acceptCredentials.stored', { count: storable.length })
      showToast({
        message:
          appKeysSkipped > 0
            ? `${storedMessage} ${t('acceptCredentials.appKeysSkipped', {
                count: appKeysSkipped
              })}`
            : storedMessage,
        severity: appKeysSkipped > 0 ? 'warning' : 'success'
      })
      navigate('/dashboard')
    } catch (err) {
      log.error('Error storing credentials', { err })
      setStoreError(
        err instanceof AppKeyRefusedError
          ? t('common.appKeyRefused')
          : t('acceptCredentials.storeError')
      )
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
          {storeError}
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
          loading={saving}
          sx={dashboardStyles.addCredentialButton}
        >
          {t('acceptCredentials.acceptAll')}
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
