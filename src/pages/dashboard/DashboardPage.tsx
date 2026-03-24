import { useState, useEffect } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { useAuthStore } from '@/stores/authStore'
import { dashboardStyles } from '@/styles/appStyles'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialCard } from '@/components/CredentialCard'

interface StoredCredential {
  cid: string
  vc: IVerifiableCredential
}

export function DashboardPage() {
  const session = useAuthStore(state => state.session)
  const logout = useAuthStore(state => state.logout)
  const [credentials, setCredentials] = useState<StoredCredential[]>([])

  useEffect(() => {
    session?.storage?.listCredentials().then(docs => {
      setCredentials(
        docs.map(d => ({
          cid: d.cid as string,
          vc: d.doc as IVerifiableCredential
        }))
      )
    })
  }, [session])

  const handleLogout = () => {
    logout(session!) // clears session
  }

  return (
    <DashboardLayout
      title="Freewallet Dashboard"
      actions={
        <Button variant="outlined" onClick={handleLogout}>
          Log out
        </Button>
      }
    >
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
