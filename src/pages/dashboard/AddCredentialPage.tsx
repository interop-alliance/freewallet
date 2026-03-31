import { useState } from 'react'
import Box from '@mui/material/Box'
import TextField from '@mui/material/TextField'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import Stack from '@mui/material/Stack'
import { useNavigate } from 'react-router'
import { DashboardLayout } from '@/components/DashboardLayout'
import { fetchFromURL } from '@/lib/fetchFromURL'
import { credentialsFromJSON } from '@/lib/credentialsFromJSON'
import { dashboardStyles } from '@/styles/appStyles'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'

export function AddCredentialPage() {
  const navigate = useNavigate()
  const [input, setInput] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleAdd() {
    setError(null)

    const trimmed = input.trimStart()
    if (!trimmed) {
      setError('No credential entered.')
      return
    }

    setLoading(true)

    try {
      let credentials: IVerifiableCredential[]

      if (trimmed.startsWith('https://') || trimmed.startsWith('http://')) {
        const text = await fetchFromURL(trimmed)
        credentials = credentialsFromJSON(text)
      } else if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        credentials = credentialsFromJSON(trimmed)
      } else {
        setError('Input must be a URL or a JSON credential.')
        setLoading(false)
        return
      }

      if (credentials.length === 0) {
        setError('No credentials found in the provided input.')
        setLoading(false)
        return
      }

      navigate('/accept-credentials', { state: { credentials } })
    } catch (err: any) {
      const isUrl = trimmed.startsWith('https://') || trimmed.startsWith('http://')
      const prefix = isUrl
        ? 'Could not retrieve credential from URL.'
        : 'Could not parse credential JSON.'
      console.error(prefix, err)
      setError(`${prefix} Error: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  function handleCancel() {
    navigate('/dashboard')
  }

  return (
    <DashboardLayout title="Add Credential">
      <Box sx={dashboardStyles.addCredentialForm}>
        <TextField
          multiline
          minRows={4}
          placeholder="Paste a URL or full credential JSON."
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
            {loading ? 'Loading…' : 'Add'}
          </Button>
          <Button
            variant="outlined"
            onClick={handleCancel}
            sx={dashboardStyles.addCredentialButton}
          >
            Cancel
          </Button>
        </Stack>
      </Box>
    </DashboardLayout>
  )
}
