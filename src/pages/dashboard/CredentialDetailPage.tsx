import { useEffect, useMemo, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { useParams } from 'react-router'
import { reset as microlightReset } from 'microlight'
import { DashboardLayout } from '@/components/DashboardLayout'
import { credentialTitle } from '@/lib/credentialTitle'
import { useAuthStore } from '@/stores/authStore'
import { credentialDetailStyles } from '@/styles/appStyles'

interface StoredCredential {
  cid: string
  vc: IVerifiableCredential
}

export function CredentialDetailPage() {
  const session = useAuthStore(state => state.session)
  const { cid } = useParams()
  const [credential, setCredential] = useState<StoredCredential | null>(null)
  const [isNotFound, setIsNotFound] = useState(false)

  useEffect(() => {
    if (!session || !cid) {
      return
    }
    session.storage?.listCredentials().then(docs => {
      const match = docs.find(doc => (doc.cid as string) === cid)
      if (!match) {
        setIsNotFound(true)
        setCredential(null)
        return
      }
      setIsNotFound(false)
      setCredential({
        cid: match.cid as string,
        vc: match.doc as IVerifiableCredential
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

  if (!cid) {
    return (
      <DashboardLayout title="Credential">
        <Alert severity="error">No credential id provided in route.</Alert>
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout title="Credential">
      {isNotFound ? (
        <Alert severity="warning">
          Credential with cid <code>{cid}</code> was not found.
        </Alert>
      ) : (
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
      )}
    </DashboardLayout>
  )
}
