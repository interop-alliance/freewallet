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
import { getIssuerDetails } from '@/lib/viewMappers/issuerName'
import { getSubject } from '@/lib/viewMappers/getSubject'

import { formatDate } from '@/lib/viewMappers/formatDate'
import {
  asRecord,
  resolvePersonFullName
} from '@/lib/viewMappers/displayFieldsHelpers'
import type { UseVerificationReturn } from '@/hooks/useVerification'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'

function CheckRow({
  label,
  valid,
  loading
}: {
  label: string
  valid?: boolean
  loading: boolean
}) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Box
        sx={{
          display: 'flex',
          lineHeight: 0,
          color: loading
            ? 'text.disabled'
            : valid
              ? 'success.main'
              : 'error.main'
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
      <Typography variant="body2" sx={{ fontWeight: 500 }}>
        {label}
      </Typography>
    </Box>
  )
}

interface Props {
  vc: IVerifiableCredential
  signatureCreatedIso: string | null
  verification: UseVerificationReturn
  showRaw: boolean
  rawJson: string
  onToggleRaw: () => void
}

export function ResumeCredentialCard({
  vc,
  signatureCreatedIso,
  verification,
  showRaw,
  rawJson,
  onToggleRaw
}: Props) {
  const subject = asRecord(getSubject(vc)) ?? {}
  const personName =
    resolvePersonFullName(subject) || getIssuerDetails(vc.issuer).name

  const { result, loading } = verification

  return (
    <Paper variant="outlined" sx={{ borderRadius: '10px', overflow: 'hidden' }}>
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
              Issuer:{' '}
            </Typography>
            <Typography variant="body2" sx={{ display: 'inline' }}>
              {personName} (self-issued)
            </Typography>
          </Box>
          <Box>
            <Typography
              variant="body2"
              sx={{ fontWeight: 700, display: 'inline' }}
            >
              Signed:{' '}
            </Typography>
            <Typography variant="body2" sx={{ display: 'inline' }}>
              {signatureCreatedIso
                ? formatDate({ isoDate: signatureCreatedIso })
                : 'N/A'}
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
            label="Signature"
            valid={result?.signature.valid}
            loading={loading}
          />
          <CheckRow
            label="Not expired"
            valid={result?.expiry.valid}
            loading={loading}
          />
          <CheckRow
            label="Not revoked"
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
          sx={{ textTransform: 'none', color: 'text.secondary', px: 0 }}
        >
          {showRaw ? 'Hide JSON' : 'View Source'}
        </Button>
        <Collapse in={showRaw} unmountOnExit>
          <Box
            component="pre"
            className="microlight"
            sx={{
              mt: 1,
              p: { xs: 1.5, sm: 2 },
              borderRadius: 2,
              backgroundColor: '#111',
              color: '#e5e7eb',
              overflowX: 'auto',
              fontSize: { xs: 12, sm: 13 },
              lineHeight: 1.6,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
              maxHeight: '60vh',
              overflowY: 'auto',
              m: 0,
              mb: 1
            }}
          >
            {rawJson}
          </Box>
        </Collapse>
      </Box>
    </Paper>
  )
}
