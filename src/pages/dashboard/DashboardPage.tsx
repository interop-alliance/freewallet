import { useState, useEffect } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { useAuthStore } from '@/stores/authStore'
import { dashboardStyles } from '@/styles/appStyles'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialCard } from '@/components/CredentialCard'
import type { StoredCredential } from '@/types/credential'

export function DashboardPage() {
  const session = useAuthStore(state => state.session)
  const [credentials, setCredentials] = useState<StoredCredential[]>([])

  useEffect(() => {
    session?.storage?.listCredentials().then(vcs => {
      setCredentials(vcs)
    })
  }, [session])

  return (
    <DashboardLayout title="Freewallet Dashboard">
      <Box sx={dashboardStyles.credentialsSection}>
        <Typography variant="h5" sx={dashboardStyles.credentialsHeading}>
          Credentials
        </Typography>
        <Box sx={dashboardStyles.credentialsGrid}>
          {credentials.map(({ cid, vc }) => (
            <CredentialCard key={cid} cid={cid} credential={vc} />
          ))}
        </Box>
      </Box>
    </DashboardLayout>
  )
}
