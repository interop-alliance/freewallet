import { useState, useEffect, useCallback } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import Button from '@mui/material/Button'
import { MdAddCircleOutline, MdQrCodeScanner, MdSync } from 'react-icons/md'
import { Link as RouterLink, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { useAuthStore } from '@/stores/authStore'
import { syncController } from '@/stores/syncController'
import { dashboardStyles } from '@/styles/appStyles'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialCard } from '@/components/CredentialCard'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import { ScanCredentialQrDialog } from '@/components/ScanCredentialQrDialog'
import type { StoredCredential } from '@/types/credential'

export function DashboardPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const session = useAuthStore(state => state.session)
  const [credentials, setCredentials] = useState<StoredCredential[]>([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [syncCount, setSyncCount] = useState(0)
  const [scanQrOpen, setScanQrOpen] = useState(false)
  const [loadError, setLoadError] = useState(false)
  // Rows the vault is unlocked for but that still would not decrypt (corrupted
  // or written under a mismatched KAK). Skipped by the list read; surfaced here
  // so the user can see and clear them rather than one poisoned row hanging the
  // page.
  const [undecryptableCount, setUndecryptableCount] = useState(0)

  const handleQrCredentialsReady = useCallback(
    (resolved: IVerifiableCredential[]) => {
      setScanQrOpen(false)
      navigate('/accept-credentials', { state: { credentials: resolved } })
    },
    [navigate]
  )

  const loadCredentials = useCallback(async () => {
    if (!session?.storage) {
      throw new Error('Storage not initialized')
    }
    const vcs = await session.storage.listCredentials()
    setCredentials(vcs)
    setUndecryptableCount(session.storage.undecryptableCredentials)
    setLoadError(false)
  }, [session])

  useEffect(() => {
    let cancelled = false

    async function initialLoad() {
      if (!session?.storage) {
        return
      }
      try {
        const vcs = await session.storage.listCredentials()
        if (!cancelled) {
          setCredentials(vcs)
          setUndecryptableCount(session.storage.undecryptableCredentials)
          setLoadError(false)
        }
      } catch (err) {
        // A failed read must not leave the page spinning forever.
        console.error('Could not load credentials:', err)
        if (!cancelled) {
          setLoadError(true)
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }
    initialLoad()

    // clean up effect
    return () => {
      cancelled = true
    }
  }, [session])

  async function handleSync() {
    setSyncing(true)
    try {
      // Kick an immediate replication cycle (no-op for guests / no remote);
      // pulled changes land in the local replica in the background.
      syncController.reSync()
      await loadCredentials()
      setSyncCount(count => count + 1)
    } catch (err) {
      console.error('Could not refresh credentials:', err)
      setLoadError(true)
    } finally {
      // Always release the Sync button, even on a failed refresh.
      setSyncing(false)
    }
  }

  async function handleRemoveUndecryptable() {
    if (!session?.storage) {
      return
    }
    try {
      await session.storage.purgeUndecryptableCredentials()
      await loadCredentials()
      setSyncCount(count => count + 1)
    } catch (err) {
      console.error('Could not remove undecryptable credentials:', err)
      setLoadError(true)
    }
  }

  return (
    <DashboardLayout title={t('dashboard.title')}>
      <Stack
        direction="row"
        spacing={2}
        sx={dashboardStyles.dashboardCredentialActions}
      >
        <Button
          variant="outlined"
          component={RouterLink}
          to="/add-credential"
          startIcon={<MdAddCircleOutline size={20} />}
          sx={dashboardStyles.addCredentialLink}
        >
          {t('dashboard.addCredential')}
        </Button>
        <Button
          variant="outlined"
          startIcon={<MdQrCodeScanner size={20} />}
          sx={dashboardStyles.addCredentialLink}
          onClick={() => setScanQrOpen(true)}
        >
          {t('dashboard.scanQr.button')}
        </Button>
      </Stack>

      <ScanCredentialQrDialog
        open={scanQrOpen}
        onClose={() => setScanQrOpen(false)}
        onCredentialsReady={handleQrCredentialsReady}
      />

      {loadError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {t('dashboard.loadError')}
        </Alert>
      )}

      {undecryptableCount > 0 && (
        <Alert
          severity="warning"
          sx={{ mb: 2 }}
          action={
            <Button
              color="inherit"
              size="small"
              onClick={handleRemoveUndecryptable}
            >
              {t('dashboard.removeUndecryptable')}
            </Button>
          }
        >
          {t('dashboard.undecryptable', { count: undecryptableCount })}
        </Alert>
      )}

      <Box sx={dashboardStyles.credentialsSection}>
        <Stack sx={dashboardStyles.credentialsHeadingRow}>
          <Typography variant="h5" sx={dashboardStyles.credentialsHeading}>
            {t('dashboard.credentialsHeading')}
          </Typography>
          <Button
            variant="outlined"
            size="small"
            onClick={handleSync}
            disabled={syncing}
            startIcon={
              <MdSync size={16} style={dashboardStyles.syncIcon(syncing)} />
            }
            sx={dashboardStyles.syncButton}
          >
            {t('common.sync')}
          </Button>
        </Stack>
        {loading ? (
          <LoadingSpinner />
        ) : (
          <Box sx={dashboardStyles.credentialsGrid}>
            {credentials.map(({ cid, vc }) => (
              <CredentialCard
                key={`${cid}-${syncCount}`}
                cid={cid}
                credential={vc}
              />
            ))}
          </Box>
        )}
      </Box>
    </DashboardLayout>
  )
}
