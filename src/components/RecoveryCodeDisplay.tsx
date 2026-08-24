/**
 * One recovery code, shown for the person to write down: the formatted code in
 * monospace with a copy button beside it and a transient "copied" note. Shared
 * by the Settings issuance dialog and the `/recover` page's replacement code --
 * both show a code exactly once, so both show it the same way.
 */
import IconButton from '@mui/material/IconButton'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { MdContentCopy } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { formatRecoveryCode } from '@/session/recovery'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:recovery')

export function RecoveryCodeDisplay({
  code,
  copyLabel,
  testId
}: {
  code: string
  copyLabel: string
  testId?: string
}) {
  const { t } = useTranslation()
  const { copied, copy } = useCopyToClipboard({
    onError: (err: unknown) => {
      log.error('Could not copy the recovery code', { err })
    }
  })
  const formatted = formatRecoveryCode({ code })

  return (
    <Stack direction="row" sx={{ alignItems: 'center', gap: 1 }}>
      <Typography
        variant="h6"
        component="code"
        {...(testId ? { 'data-testid': testId } : {})}
        sx={{ fontFamily: 'monospace', letterSpacing: 1 }}
      >
        {formatted}
      </Typography>
      <IconButton
        size="small"
        aria-label={copyLabel}
        onClick={() => void copy(formatted)}
      >
        <MdContentCopy />
      </IconButton>
      {copied && (
        <Typography variant="body2" color="text.secondary">
          {t('common.copied')}
        </Typography>
      )}
    </Stack>
  )
}
