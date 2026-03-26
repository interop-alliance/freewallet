import { useEffect, useMemo, useState } from 'react'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import { useParams } from 'react-router'
import { reset as microlightReset } from 'microlight'
import { DashboardLayout } from '@/components/DashboardLayout'
import { credentialTitle } from '@/lib/credentialTitle'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { useAuthStore } from '@/stores/authStore'
import { credentialDetailStyles } from '@/styles/appStyles'
import type { StoredCredential } from '@/types/credential'

export function CredentialDetailPage() {
  const session = useAuthStore(state => state.session)
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
      setCredential({
        cid,
        vc
      })
    })
  }, [cid, session])

  useEffect(() => {
    microlightReset()
  }, [credential])

  const rawVc = useMemo(() => {
    if (!credential) {
      return ''
    }
    return JSON.stringify(credential.vc, null, 2)
  }, [credential])

  if (!cid || isNotFound) {
    return <NotFoundPage />
  }

  return (
    <DashboardLayout title="Credential">
      <Box sx={credentialDetailStyles.wrapper}>
        <Typography
          variant="h4"
          component="h2"
          sx={credentialDetailStyles.title}
        >
          {credential
            ? credentialTitle(credential.vc)
            : 'Loading credential...'}
        </Typography>
        {credential && (
          <Box
            component="pre"
            className="microlight"
            sx={credentialDetailStyles.codeBlock}
          >
            {rawVc}
          </Box>
        )}
      </Box>
    </DashboardLayout>
  )
}
