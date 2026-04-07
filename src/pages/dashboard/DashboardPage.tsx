import { useState, useEffect, useCallback } from 'react'
import Box from '@mui/material/Box'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import Button from '@mui/material/Button'
import { MdAddCircleOutline, MdSync } from 'react-icons/md'
import { Link as RouterLink } from 'react-router'
import { useAuthStore } from '@/stores/authStore'
import { dashboardStyles } from '@/styles/appStyles'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialCard } from '@/components/CredentialCard'
import { LoadingSpinner } from '@/components/LoadingSpinner'
import type { StoredCredential } from '@/types/credential'

export function DashboardPage() {
  const session = useAuthStore(state => state.session)
  const [credentials, setCredentials] = useState<StoredCredential[]>([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)

  const loadCredentials = useCallback(async () => {
    if (!session?.storage) {
      throw new Error('Storage not initialized')
    }
    const vcs = await session.storage.listCredentials()
    setCredentials(vcs)
  }, [session])

  useEffect(() => {
    let cancelled = false

    async function initialLoad() {
      if (!session?.storage) {
        return
      }
      const vcs = await session.storage.listCredentials()
      if (!cancelled) {
        setCredentials(vcs)
        setLoading(false)
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
    await loadCredentials()
    setSyncing(false)
  }

  return (
    <DashboardLayout title="Freewallet Dashboard">
      <Button
        variant="outlined"
        component={RouterLink}
        to="/add-credential"
        startIcon={<MdAddCircleOutline size={20} />}
        sx={dashboardStyles.addCredentialLink}
      >
        Add Credential
      </Button>

      <Box sx={dashboardStyles.credentialsSection}>
        <Stack sx={dashboardStyles.credentialsHeadingRow}>
          <Typography variant="h5" sx={dashboardStyles.credentialsHeading}>
            Credentials
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
            Sync
          </Button>
        </Stack>
        {loading ? (
          <LoadingSpinner />
        ) : (
          <Box sx={dashboardStyles.credentialsGrid}>
            {credentials.map(({ cid, vc }) => (
              <CredentialCard key={cid} cid={cid} credential={vc} />
            ))}
          </Box>
        )}
      </Box>
    </DashboardLayout>
  )
}
