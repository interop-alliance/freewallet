import { useState, useEffect } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Button from '@mui/material/Button'
import { MdAddCircleOutline } from 'react-icons/md'
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

  useEffect(() => {
    if (!session?.storage) {
      return
    }
    let cancelled = false

    async function load() {
      const vcs = await session!.storage!.listCredentials()
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
        <Typography variant="h5" sx={dashboardStyles.credentialsHeading}>
          Credentials
        </Typography>
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
