import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
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
  const [loadError, setLoadError] = useState(false)
  const [deleteError, setDeleteError] = useState(false)

  useEffect(() => {
    if (!session || !cid) {
      return
    }
    session.storage
      ?.loadCredential({ cid })
      .then(vc => {
        if (!vc) {
          setIsNotFound(true)
          setCredential(null)
          return
        }
        setIsNotFound(false)
        setLoadError(false)
        setCredential({ cid, vc })
      })
      .catch((err: unknown) => {
        console.error('Error loading credential:', err)
        setLoadError(true)
      })
  }, [cid, session])

  async function handleDelete() {
    if (!session) {
      return
    }
    setDeleteError(false)
    try {
      await session.storage.deleteCredential({ cid: cid! })
    } catch (err: any) {
      console.error('Error deleting credential:', err)
      setDeleteError(true)
      return
    }
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
        {deleteError && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {t('credential.deleteError')}
          </Alert>
        )}
        {credential ? (
          <>
            <CredentialDetail
              vc={credential.vc}
              cid={cid}
              onDelete={handleDelete}
            />
          </>
        ) : loadError ? (
          <Alert severity="error">{t('credential.loadError')}</Alert>
        ) : (
          <Typography variant="h5" color="text.secondary">
            {t('credential.loading')}
          </Typography>
        )}
      </Box>
    </DashboardLayout>
  )
}
