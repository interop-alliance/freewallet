import { useState } from 'react'
import Box from '@mui/material/Box'
import TextField from '@mui/material/TextField'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import Stack from '@mui/material/Stack'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { DashboardLayout } from '@/components/DashboardLayout'
import {
  ResolveCredentialsInputError,
  resolveCredentialsInput
} from '@/lib/resolveCredentialsInput'
import { dashboardStyles } from '@/styles/appStyles'

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
      if (err instanceof ResolveCredentialsInputError) {
        const keys = {
          empty: 'addCredential.errors.empty',
          invalid_input: 'addCredential.errors.invalidInput',
          none_found: 'addCredential.errors.noneFound'
        } as const
        setError(t(keys[err.code]))
        return
      }
      const isUrl =
        trimmed.startsWith('https://') || trimmed.startsWith('http://')
      const prefix = isUrl
        ? t('addCredential.errors.urlFetch')
        : t('addCredential.errors.jsonParse')
      console.error(prefix, err)
      const msg = err instanceof Error ? err.message : String(err)
      setError(`${prefix} Error: ${msg}`)
    } finally {
      setLoading(false)
    }
  }

  function handleCancel() {
    navigate('/dashboard')
  }

  return (
    <DashboardLayout title={t('addCredential.title')}>
      <Box sx={dashboardStyles.addCredentialForm}>
        <TextField
          multiline
          minRows={4}
          placeholder={t('addCredential.placeholder')}
          value={input}
          onChange={e => setInput(e.target.value)}
          error={!!error}
          fullWidth
        />
        {error && (
          <Typography variant="body2" color="error">
            {error}
          </Typography>
        )}
        <Stack direction="row" spacing={2}>
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
            onClick={handleCancel}
            sx={dashboardStyles.addCredentialButton}
          >
            {t('common.cancel')}
          </Button>
        </Stack>
      </Box>
    </DashboardLayout>
  )
}
