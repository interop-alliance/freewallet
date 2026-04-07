import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { useParams, useNavigate } from 'react-router'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialDetail } from '@/components/credentialDetails/CredentialDetail'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { useAuthStore } from '@/stores/authStore'
import { credentialDetailStyles } from '@/styles/credentialStyles'
import type { StoredCredential } from '@/types/credential'
import { isResumeCredential } from '@/lib/isResumeCredential'

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

  let title = 'Credential'
  if (credential?.vc) {
    if (isResumeCredential(credential.vc)) {
      title = 'Resume'
    } else {
      title = 'Credential'
    }
  }
  return (
    <DashboardLayout title={title}>
      <Box sx={credentialDetailStyles.wrapper}>
        {credential ? (
          <>
            <CredentialDetail vc={credential.vc} onDelete={handleDelete} />
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
