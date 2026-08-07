import { type SubmitEvent, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { useTranslation } from 'react-i18next'

export function CHAPILoginForm({
  onSubmit,
  error
}: {
  onSubmit: (passphrase: string) => Promise<void>
  error: string | null
}) {
  const { t } = useTranslation()
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
      <Typography variant="body2">{t('chapi.loginPrompt')}</Typography>

      {error && (
        <Typography variant="body2" color="error">
          {error}
        </Typography>
      )}

      <TextField
        type="password"
        placeholder={t('chapi.passphrasePlaceholder')}
        value={passphrase}
        onChange={e => setPassphrase(e.target.value)}
        autoComplete="current-password"
        size="small"
        fullWidth
      />

      <Button
        type="submit"
        variant="contained"
        loading={loading}
        disabled={!passphrase}
        sx={{ alignSelf: 'flex-start' }}
      >
        {t('common.continue')}
      </Button>
    </Box>
  )
}
