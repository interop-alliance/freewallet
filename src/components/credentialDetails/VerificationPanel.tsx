import {
  Box,
  CircularProgress,
  Divider,
  Stack,
  Typography
} from '@mui/material'
import { MdCancel, MdCheckCircle } from 'react-icons/md'
import type { UseVerificationReturn } from '@/hooks/useVerification'
import { formatDateTime } from '@/lib/formatDate'
import {
  isFullyVerified,
  getVerificationNarrative
} from '@/lib/verificationMessages'
import { credentialDetailCardStyles as sx } from '@/styles/credentialStyles'
import type { VerificationStep } from '@/types/credential'

function ChecklistRow({
  label,
  step
}: {
  label: string
  step: VerificationStep
}) {
  const ok = step.valid
  return (
    <Box sx={sx.vpChecklistRow}>
      <Box
        sx={ok ? sx.verificationIconSuccess : sx.verificationIconError}
        aria-hidden
      >
        {ok ? <MdCheckCircle size={16} /> : <MdCancel size={16} />}
      </Box>
      <Typography variant="caption" color="text.secondary" sx={{ flex: 1 }}>
        <Box component="span" sx={{ fontWeight: 600, color: 'text.primary' }}>
          {label}:{' '}
        </Box>
        {step.message}
        {step.error ? ` — ${step.error}` : ''}
      </Typography>
    </Box>
  )
}

export function VerificationPanel({
  verification
}: {
  verification: UseVerificationReturn
}) {
  const { result, loading, error, lastCheckedAt } = verification
  const pending = loading || (!result && !error)
  const narrative = getVerificationNarrative(result, error)
  const summaryOk =
    !error && result != null && isFullyVerified(result) && !pending

  return (
    <Box sx={sx.vpCard}>
      <Box sx={sx.vpCardColumns}>
        <Box sx={sx.vpGrayBox}>
          <Typography variant="caption" sx={sx.vpGrayTitle}>
            Credential Verification and Validation
          </Typography>

          {pending && (
            <Box sx={sx.verificationLoadingRow}>
              <CircularProgress size={18} sx={sx.verificationSpinner} />
              <Typography variant="body2" color="text.secondary">
                Verifying credential…
              </Typography>
            </Box>
          )}

          {!pending && (
            <>
              <Typography
                variant="subtitle1"
                sx={sx.vpHeadline}
                color="text.primary"
              >
                {narrative.headline}
              </Typography>
              {narrative.body && (
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={sx.vpBody}
                >
                  {narrative.body}
                </Typography>
              )}
              {result && (
                <Stack spacing={0.75} sx={{ mt: 2 }}>
                  <ChecklistRow label="Signature" step={result.signature} />
                  <ChecklistRow label="Expiry" step={result.expiry} />
                  <ChecklistRow label="Revocation" step={result.status} />
                </Stack>
              )}
              {lastCheckedAt && (
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={sx.vpLastChecked}
                >
                  Last checked: {formatDateTime(lastCheckedAt)}
                </Typography>
              )}
            </>
          )}
        </Box>

        <Divider
          orientation="vertical"
          flexItem
          sx={{ display: { xs: 'none', md: 'block' }, borderColor: 'divider' }}
        />

        <Box sx={sx.vpSummaryColumn}>
          <Typography
            variant="body1"
            color="text.secondary"
            sx={sx.vpSummaryText}
          >
            {pending
              ? ''
              : summaryOk
                ? 'This credential was verified successfully.'
                : 'This credential was not verified successfully.'}
          </Typography>
        </Box>
      </Box>
    </Box>
  )
}

export function VerificationStatusBadge({
  loading,
  result,
  error
}: Pick<UseVerificationReturn, 'loading' | 'result' | 'error'>) {
  const verified = !error && result != null && isFullyVerified(result)

  if (loading) {
    return (
      <Box sx={sx.vpStatusBadge} aria-live="polite">
        <CircularProgress size={14} sx={sx.vpStatusSpinner} />
        <Typography variant="body2" sx={sx.vpStatusBadgeLabel}>
          Verifying…
        </Typography>
      </Box>
    )
  }

  if (error || (result && !verified)) {
    return (
      <Box
        sx={{ ...sx.vpStatusBadge, ...sx.vpStatusBadgeError }}
        aria-live="polite"
      >
        <Box sx={sx.vpStatusIconWrap} aria-hidden>
          <MdCancel size={16} />
        </Box>
        <Typography variant="body2" sx={sx.vpStatusBadgeLabel}>
          Not Verified
        </Typography>
      </Box>
    )
  }

  if (verified) {
    return (
      <Box
        sx={{ ...sx.vpStatusBadge, ...sx.vpStatusBadgeOk }}
        aria-live="polite"
      >
        <Box sx={sx.vpStatusIconWrap} aria-hidden>
          <MdCheckCircle size={16} />
        </Box>
        <Typography variant="body2" sx={sx.vpStatusBadgeLabel}>
          Verified
        </Typography>
      </Box>
    )
  }

  return (
    <Box sx={sx.vpStatusBadge} aria-live="polite">
      <Typography
        variant="body2"
        sx={sx.vpStatusBadgeLabel}
        color="text.secondary"
      >
        Pending verification
      </Typography>
    </Box>
  )
}
