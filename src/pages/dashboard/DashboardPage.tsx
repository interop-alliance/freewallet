import { useState, useEffect } from 'react'
import Box from '@mui/material/Box'
import CircularProgress from '@mui/material/CircularProgress'
import Typography from '@mui/material/Typography'
import { useAuthStore } from '@/stores/authStore'
import { dashboardStyles } from '@/styles/appStyles'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialCard } from '@/components/CredentialCard'
import type { StoredCredential } from '@/types/credential'
import { delay } from '@/lib/delay'

export function DashboardPage() {
  const session = useAuthStore(state => state.session)
  const [credentials, setCredentials] = useState<StoredCredential[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!session?.storage) {
      return
    }
    let cancelled = false

    async function load() {
      const [vcs] = await Promise.all([
        session!.storage!.listCredentials(),
        delay(3000)
      ])
      if (!cancelled) {
        setCredentials(vcs)
        setLoading(false)
      }
    }
    load()

    return () => {
      cancelled = true
    }
  }, [session])

  return (
    <DashboardLayout title="Freewallet Dashboard">
      <Box sx={dashboardStyles.credentialsSection}>
        <Typography variant="h5" sx={dashboardStyles.credentialsHeading}>
          Credentials
        </Typography>
        {loading ? (
          <Box sx={dashboardStyles.credentialsLoading}>
            <CircularProgress />
          </Box>
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
