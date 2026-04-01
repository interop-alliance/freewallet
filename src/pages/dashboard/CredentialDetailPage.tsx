import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import Button from '@mui/material/Button'
import { useParams, useNavigate } from 'react-router'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialDetail } from '@/components/credentialDetails/CredentialDetail'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { useAuthStore } from '@/stores/authStore'
import { credentialDetailStyles, dashboardStyles } from '@/styles/appStyles'
import type { StoredCredential } from '@/types/credential'

export function CredentialDetailPage() {
  const session = useAuthStore(state => state.session)
  const navigate = useNavigate()
  const { cid } = useParams()
  const [credential, setCredential] = useState<StoredCredential | null>(null)
  const [isNotFound, setIsNotFound] = useState(false)

  useEffect(() => {
    if (!session || !cid) {
      return
    }
    session.storage?.loadCredential({ cid }).then(vc => {
      if (!vc) {
        setIsNotFound(true)
        setCredential(null)
        return
      }
      setIsNotFound(false)
      setCredential({ cid, vc })
    })
  }, [cid, session])

  async function handleDelete() {
    if (!session) {
      return
    }
    await session.storage.deleteCredential({ cid: cid! })
    navigate('/dashboard')
  }

  if (!cid || isNotFound) {
    return <NotFoundPage />
  }

  return (
    <DashboardLayout title="Credential">
      <Box sx={credentialDetailStyles.wrapper}>
        {credential ? (
          <>
            <CredentialDetail vc={credential.vc} />
            <Button
              variant="contained"
              sx={dashboardStyles.deleteCredentialButton}
              onClick={handleDelete}
            >
              Delete Credential
            </Button>
          </>
        ) : (
          <Typography variant="h5" color="text.secondary">
            Loading credential...
          </Typography>
        )}
      </Box>
    </DashboardLayout>
  )
}
