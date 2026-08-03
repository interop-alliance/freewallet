import {
  Box,
  Button,
  CircularProgress,
  Collapse,
  Divider,
  Paper,
  Stack,
  Typography
} from '@mui/material'
import { MdCheckCircle, MdCancel } from 'react-icons/md'
import { JsonHighlight } from '@/components/JsonHighlight'
import { getIssuerDetails } from '@/lib/viewMappers/issuerName'
import { getSubject } from '@/lib/viewMappers/getSubject'

import { formatDate } from '@/lib/viewMappers/formatDate'
import {
  asRecord,
  resolvePersonFullName
} from '@/lib/viewMappers/displayFieldsHelpers'
import { credentialDetailStyles } from '@/styles/credentialStyles'
import type { UseVerificationReturn } from '@/hooks/useVerification'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { useTranslation } from 'react-i18next'

function CheckRow({
  label,
  valid,
  loading
}: {
  label: string
  valid?: boolean
  loading: boolean
}) {
  let checkColor: string
  if (loading) {
    checkColor = 'text.disabled'
  } else if (valid) {
    checkColor = 'success.main'
  } else {
    checkColor = 'error.main'
  }
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Box
        sx={{
          display: 'flex',
          lineHeight: 0,
          color: checkColor
        }}
        aria-hidden
      >
        {loading ? (
          <CircularProgress size={16} color="inherit" />
        ) : valid ? (
          <MdCheckCircle size={18} />
        ) : (
          <MdCancel size={18} />
        )}
      </Box>
      <Typography variant="subtitle2">{label}</Typography>
    </Box>
  )
}

interface Props {
  vc: IVerifiableCredential
  createdDate: string | null
  verification: UseVerificationReturn
  showRaw: boolean
  rawJson: string
  onToggleRaw: () => void
}

export function ResumeCredentialCard({
  vc,
  createdDate,
  verification,
  showRaw,
  rawJson,
  onToggleRaw
}: Props) {
  const { t, i18n } = useTranslation()
  const subject = asRecord(getSubject(vc)) ?? {}
  const personName =
    resolvePersonFullName(subject) || getIssuerDetails(vc.issuer).name

  const { result, loading } = verification

  return (
    <Paper variant="outlined" sx={{ borderRadius: 3, overflow: 'hidden' }}>
      <Box
        sx={{
          display: 'flex',
          flexDirection: { xs: 'column', sm: 'row' },
          alignItems: { sm: 'center' },
          justifyContent: 'space-between',
          gap: 2,
          px: { xs: 2, sm: 3 },
          py: 2.5
        }}
      >
        <Stack spacing={1.5}>
          <Box>
            <Typography
              variant="body2"
              sx={{ fontWeight: 700, display: 'inline' }}
            >
              {t('resumeCard.issuer')}{' '}
            </Typography>
            <Typography variant="body2" sx={{ display: 'inline' }}>
              {personName} {t('resumeCard.selfIssued')}
            </Typography>
          </Box>
          <Box>
            <Typography
              variant="body2"
              sx={{ fontWeight: 700, display: 'inline' }}
            >
              {t('resumeCard.signed')}{' '}
            </Typography>
            <Typography variant="body2" sx={{ display: 'inline' }}>
              {createdDate
                ? formatDate({ isoDate: createdDate, locale: i18n.language })
                : t('common.na')}
            </Typography>
          </Box>
        </Stack>

        <Divider
          orientation="vertical"
          flexItem
          sx={{ display: { xs: 'none', sm: 'block' } }}
        />

        <Stack spacing={1}>
          <CheckRow
            label={t('resumeCard.signature')}
            valid={result?.signature.valid}
            loading={loading}
          />
          <CheckRow
            label={t('resumeCard.notExpired')}
            valid={result?.expiry.valid}
            loading={loading}
          />
          <CheckRow
            label={t('resumeCard.notRevoked')}
            valid={result?.status.valid}
            loading={loading}
          />
        </Stack>
      </Box>

      <Divider />

      <Box sx={{ px: { xs: 2, sm: 3 }, py: 1 }}>
        <Button
          size="small"
          variant="text"
          onClick={onToggleRaw}
          sx={{ color: 'text.secondary', px: 0 }}
        >
          {showRaw ? t('credential.hideJson') : t('credential.viewSource')}
        </Button>
        <Collapse in={showRaw} unmountOnExit>
          <JsonHighlight
            code={rawJson}
            sx={{
              ...credentialDetailStyles.codeBlock,
              mt: 1,
              mb: 1
            }}
          />
        </Collapse>
      </Box>
    </Paper>
  )
}
