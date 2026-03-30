import { type SubmitEvent, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'

interface ChapiLoginFormProps {
  onSubmit: (passphrase: string) => Promise<void>
  error: string | null
}

export function ChapiLoginForm({ onSubmit, error }: ChapiLoginFormProps) {
  const [passphrase, setPassphrase] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: SubmitEvent<HTMLFormElement>) {
    e.preventDefault()
    if (!passphrase) {
      return
    }
    setLoading(true)
    await onSubmit(passphrase)
    setLoading(false)
  }

  return (
    <Box
      component="form"
      onSubmit={handleSubmit}
      sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}
    >
      <Typography variant="body2">
        Enter your wallet passphrase to continue:
      </Typography>

      {error && (
        <Typography variant="body2" color="error">
          {error}
        </Typography>
      )}

      <TextField
        type="password"
        placeholder="Passphrase"
        value={passphrase}
        onChange={e => setPassphrase(e.target.value)}
        autoComplete="current-password"
        size="small"
        fullWidth
      />

      <Button
        type="submit"
        variant="contained"
        disabled={loading || !passphrase}
        sx={{ alignSelf: 'flex-start', textTransform: 'none' }}
      >
        {loading ? 'Verifying…' : 'Continue'}
      </Button>
    </Box>
  )
}
