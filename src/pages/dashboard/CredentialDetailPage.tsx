import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { useParams, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialDetail } from '@/components/credentialDetails/CredentialDetail'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { useAuthStore } from '@/stores/authStore'
import { credentialDetailStyles } from '@/styles/credentialStyles'
import type { StoredCredential } from '@/types/credential'
import { isResumeCredential } from '@/lib/isResumeCredential'

export function CredentialDetailPage() {
  const { t } = useTranslation()
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

  let title = t('credential.title')
  if (credential?.vc) {
    if (isResumeCredential(credential.vc)) {
      title = t('credential.resumeTitle')
    } else {
      title = t('credential.title')
    }
  }
  return (
    <DashboardLayout title={title}>
      <Box sx={credentialDetailStyles.wrapper}>
        {credential ? (
          <>
            <CredentialDetail
              vc={credential.vc}
              cid={cid}
              onDelete={handleDelete}
            />
          </>
        ) : (
          <Typography variant="h5" color="text.secondary">
            {t('credential.loading')}
          </Typography>
        )}
      </Box>
    </DashboardLayout>
  )
}
