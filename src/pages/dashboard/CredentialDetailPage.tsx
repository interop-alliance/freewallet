import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { useParams, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialDetail } from '@/components/credentialDetails/CredentialDetail'
import { DeleteCredentialDialog } from '@/components/credentialDetails/DeleteCredentialDialog'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { useCredentialPublicLink } from '@/hooks/useCredentialPublicLink'
import { useCredentialDelete } from '@/hooks/useCredentialDelete'
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

  const { share, error: shareError } = useCredentialPublicLink({
    credential: credential?.vc,
    session
  })
  const {
    deleteError,
    deleteDialogOpen,
    deleting,
    requestDelete,
    runDelete,
    cancelDelete
  } = useCredentialDelete({
    session,
    cid,
    onSuccess: () => navigate('/dashboard')
  })

  const vaultLocked = !!session?.storage?.vaultLocked

  useEffect(() => {
    if (!session || !cid) {
      return
    }
    // With the vault locked, encrypted credentials are unreadable until a
    // passphrase re-login. `loadCredential` fails closed (returns undefined),
    // so skip the load entirely and render the locked state below rather than
    // mapping the empty result to a misleading 404.
    if (session.storage.vaultLocked) {
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

  function handleDelete() {
    void requestDelete()
  }

  // A locked vault is not a missing credential -- keep the user inside the
  // dashboard layout (which shows the unlock banner) instead of a 404.
  if (!cid || (isNotFound && !vaultLocked)) {
    return <NotFoundPage />
  }

  const title =
    credential?.vc && isResumeCredential(credential.vc)
      ? t('credential.resumeTitle')
      : t('credential.title')

  return (
    <DashboardLayout title={title}>
      <Box sx={credentialDetailStyles.wrapper}>
        {deleteError && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {t('credential.deleteError')}
          </Alert>
        )}
        {shareError && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {t('credential.shareError')}
          </Alert>
        )}
        {vaultLocked ? (
          <Alert severity="info">{t('credential.lockedVault')}</Alert>
        ) : credential ? (
          <CredentialDetail
            vc={credential.vc}
            cid={cid}
            actions={{ onDelete: handleDelete, share }}
          />
        ) : loadError ? (
          <Alert severity="error">{t('credential.loadError')}</Alert>
        ) : (
          <Typography variant="h5" color="text.secondary">
            {t('credential.loading')}
          </Typography>
        )}
      </Box>

      <DeleteCredentialDialog
        open={deleteDialogOpen}
        busy={deleting}
        onKeepPublic={() => void runDelete({ alsoRemovePublic: false })}
        onDeleteAll={() => void runDelete({ alsoRemovePublic: true })}
        onCancel={cancelDelete}
      />
    </DashboardLayout>
  )
}
