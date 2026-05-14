import {
  Box,
  CircularProgress,
  Divider,
  Stack,
  Typography
} from '@mui/material'
import { useTranslation } from 'react-i18next'
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
  const { t } = useTranslation()
  const { result, loading, error, lastCheckedAt } = verification
  const pending = loading || (!result && !error)
  const narrative = getVerificationNarrative(result, error, t)
  const summaryOk =
    !error && result != null && isFullyVerified(result) && !pending
  const expiredOnly = !error && result != null && isExpiredOnly(result)

  let summaryMessage = ''
  if (!pending) {
    if (summaryOk) {
      summaryMessage = t('verification.summaryOk')
    } else if (expiredOnly) {
      summaryMessage = t('verification.summaryExpired')
    } else {
      summaryMessage = t('verification.summaryFail')
    }
  }

  return (
    <Box sx={sx.vpCard}>
      <Box sx={sx.vpCardColumns}>
        <Box sx={sx.vpGrayBox}>
          <Typography variant="caption" sx={sx.vpGrayTitle}>
            {t('verification.panelTitle')}
          </Typography>

          {pending && (
            <Box sx={sx.verificationLoadingRow}>
              <CircularProgress size={18} sx={sx.verificationSpinner} />
              <Typography variant="body2" color="text.secondary">
                {t('verification.verifyingCredential')}
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
                  {t('verification.lastChecked', {
                    datetime: formatDateTime(lastCheckedAt)
                  })}
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
  const { t } = useTranslation()
  const verified = !error && result != null && isFullyVerified(result)
  const expiredOnly = !error && result != null && isExpiredOnly(result)

  if (loading) {
    return (
      <Box sx={sx.vpStatusBadge} aria-live="polite">
        <CircularProgress size={10} sx={sx.vpStatusSpinner} />
        <Typography variant="body2" sx={sx.vpStatusBadgeLabel}>
          {t('verification.badgeVerifying')}
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
          <MdWarning size={11} />
        </Box>
        <Typography variant="body2" sx={sx.vpStatusBadgeLabel}>
          {t('verification.badgeWarning')}
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
          <MdCancel size={11} />
        </Box>
        <Typography variant="body2" sx={sx.vpStatusBadgeLabel}>
          {t('verification.badgeNotVerified')}
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
          <MdCheckCircle size={11} />
        </Box>
        <Typography variant="body2" sx={sx.vpStatusBadgeLabel}>
          {t('verification.badgeVerified')}
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
        {t('verification.badgePending')}
      </Typography>
    </Box>
  )
}
