import {
  Box,
  CircularProgress,
  Divider,
  Stack,
  Typography
} from '@mui/material'
import { MdCancel, MdCheckCircle, MdWarning } from 'react-icons/md'
import type { UseVerificationReturn } from '@/hooks/useVerification'
import { formatDateTime } from '@/lib/viewMappers/formatDate'
import {
  isFullyVerified,
  isExpiredOnly,
  getVerificationNarrative
} from '@/lib/viewMappers/verificationMessages'
import { credentialDetailCardStyles as sx } from '@/styles/credentialStyles'
import type { VerificationStep } from '@/types/credential'

function ChecklistRow({
  step,
  warn = false
}: {
  step: VerificationStep
  warn?: boolean
}) {
  const ok = step.valid

  let iconSx
  let icon
  if (ok) {
    iconSx = sx.verificationIconSuccess
    icon = <MdCheckCircle size={16} />
  } else if (warn) {
    iconSx = sx.verificationIconWarning
    icon = <MdWarning size={16} />
  } else {
    iconSx = sx.verificationIconError
    icon = <MdCancel size={16} />
  }

  return (
    <Box sx={sx.vpChecklistRow}>
      <Box sx={iconSx} aria-hidden>
        {icon}
      </Box>
      <Typography variant="caption" color="text.secondary" sx={{ flex: 1 }}>
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
  const expiredOnly = !error && result != null && isExpiredOnly(result)

  let summaryMessage = ''
  if (!pending) {
    if (summaryOk) {
      summaryMessage = 'This credential was verified successfully.'
    } else if (expiredOnly) {
      summaryMessage =
        'This credential has expired but its cryptographic proof is still valid.'
    } else {
      summaryMessage = 'This credential was not verified successfully.'
    }
  }

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
                  <ChecklistRow step={result.signature} />
                  <ChecklistRow step={result.expiry} warn={expiredOnly} />
                  <ChecklistRow step={result.status} />
                </Stack>
              )}
              {lastCheckedAt && (
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={sx.vpLastChecked}
                >
                  Last Checked: {formatDateTime(lastCheckedAt)}
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
            {summaryMessage}
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
  const expiredOnly = !error && result != null && isExpiredOnly(result)

  if (loading) {
    return (
      <Box sx={sx.vpStatusBadge} aria-live="polite">
        <CircularProgress size={12} sx={sx.vpStatusSpinner} />
        <Typography variant="body2" sx={sx.vpStatusBadgeLabel}>
          Verifying…
        </Typography>
      </Box>
    )
  }

  if (expiredOnly) {
    return (
      <Box
        sx={{ ...sx.vpStatusBadge, ...sx.vpStatusBadgeWarning }}
        aria-live="polite"
      >
        <Box sx={sx.vpStatusIconWrap} aria-hidden>
          <MdWarning size={14} />
        </Box>
        <Typography variant="body2" sx={sx.vpStatusBadgeLabel}>
          Warning
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
          <MdCancel size={14} />
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
          <MdCheckCircle size={14} />
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
