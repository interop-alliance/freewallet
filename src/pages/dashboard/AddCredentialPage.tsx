import { useState } from 'react'
import Box from '@mui/material/Box'
import TextField from '@mui/material/TextField'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import Stack from '@mui/material/Stack'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import { CredentialJsonUploadPanel } from '@/components/CredentialJsonFileUpload'
import { resolveCredentialsFromJsonFiles } from '@/lib/resolveCredentialJsonFiles'
import { resolveCredentialsInput } from '@/lib/resolveCredentialsInput'
import { resolveCredentialsInputErrorMessage } from '@/lib/resolveCredentialsInputErrorMessage'
import { dashboardStyles } from '@/styles/appStyles'
import { credentialJsonUploadStyles } from '@/styles/credentialJsonUploadStyles'

export function AddCredentialPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [input, setInput] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleAdd() {
    setError(null)

    const trimmed = input.trimStart()
    if (!trimmed) {
      setError(t('addCredential.errors.empty'))
      return
    }

    setLoading(true)
    try {
      const credentials = await resolveCredentialsInput(trimmed)
      navigate('/accept-credentials', { state: { credentials } })
    } catch (err: unknown) {
      setError(resolveCredentialsInputErrorMessage(err, t, { trimmed }))
    } finally {
      setLoading(false)
    }
  }

  async function handleFiles(files: File[]) {
    setError(null)
    setLoading(true)
    try {
      const credentials = await resolveCredentialsFromJsonFiles(files)
      navigate('/accept-credentials', { state: { credentials } })
    } catch (err: unknown) {
      setError(resolveCredentialsInputErrorMessage(err, t))
    } finally {
      setLoading(false)
    }
  }

  return (
    <DashboardLayout title={t('addCredential.title')}>
      <Box sx={dashboardStyles.addCredentialForm}>
        {error ? (
          <Typography variant="body2" color="error">
            {error}
          </Typography>
        ) : null}

        <TextField
          multiline
          minRows={4}
          placeholder={t('addCredential.placeholder')}
          value={input}
          onChange={e => {
            setInput(e.target.value)
            if (error) {
              setError(null)
            }
          }}
          error={!!error}
          fullWidth
          disabled={loading}
        />

        <Typography
          variant="body2"
          color="text.secondary"
          sx={credentialJsonUploadStyles.orUploadDivider}
        >
          {t('addCredential.upload.orUpload')}
        </Typography>

        <CredentialJsonUploadPanel onFiles={handleFiles} disabled={loading} />

        <Stack direction="row" spacing={2} sx={{ flexWrap: 'wrap' }}>
          <Button
            variant="outlined"
            onClick={handleAdd}
            disabled={loading}
            sx={dashboardStyles.addCredentialButton}
          >
            {loading ? t('common.loading') : t('addCredential.add')}
          </Button>
          <Button
            variant="outlined"
            onClick={() => navigate('/dashboard')}
            disabled={loading}
            sx={dashboardStyles.addCredentialButton}
          >
            {t('common.cancel')}
          </Button>
        </Stack>
      </Box>
    </DashboardLayout>
  )
}
