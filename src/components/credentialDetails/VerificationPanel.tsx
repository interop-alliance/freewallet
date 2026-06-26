import {
  Box,
  CircularProgress,
  Divider,
  Typography
} from '@mui/material'
import { useTranslation } from 'react-i18next'
import { MdCancel, MdCheckCircle } from 'react-icons/md'
import type { UseVerificationReturn } from '@/hooks/useVerification'
import { formatDateTime } from '@/lib/viewMappers/formatDate'
import {
  getVerificationAggregateStatus,
  hasVerificationWarning,
  isExpiredOnly,
  isFullyVerified
} from '@/lib/viewMappers/verificationMessages'
import { credentialDetailCardStyles as sx } from '@/styles/credentialStyles'
import type {
  VerificationStep,
  VerificationStepStatus
} from '@/types/credential'

const CHECKLIST_STEP_KEYS = [
  'supportedFormat',
  'signature',
  'issuer',
  'revocation',
  'expiration'
] as const

function checklistSteps(result: NonNullable<UseVerificationReturn['result']>) {
  return CHECKLIST_STEP_KEYS.map(key => ({ key, step: result[key] }))
}

function StepIcon({ status }: { status: VerificationStepStatus }) {
  if (status === 'positive') {
    return (
      <Box sx={sx.verificationIconSuccess} aria-hidden>
        <MdCheckCircle size={20} />
      </Box>
    )
  }

  if (status === 'negative') {
    return (
      <Box sx={sx.verificationIconError} aria-hidden>
        <MdCancel size={20} />
      </Box>
    )
  }

  return (
    <Box sx={sx.verificationWarningCircle} aria-hidden>
      <Typography component="span" sx={sx.verificationWarningMark}>
        !
      </Typography>
    </Box>
  )
}

function ChecklistRow({ step }: { step: VerificationStep }) {
  return (
    <Box sx={sx.vpChecklistRow}>
      <StepIcon status={step.status} />
      <Typography component="span" sx={sx.vpChecklistText}>
        {step.message}
      </Typography>
    </Box>
  )
}

function summaryMessageFor(
  error: Error | null,
  pending: boolean,
  result: UseVerificationReturn['result'],
  t: ReturnType<typeof useTranslation>['t']
): string {
  if (pending) {
    return ''
  }
  if (error) {
    return t('verification.summaryFail')
  }

  const aggregate = getVerificationAggregateStatus(result)
  if (aggregate === 'verified') {
    return t('verification.summaryOk')
  }
  if (aggregate === 'warning') {
    if (result && isExpiredOnly(result)) {
      return t('verification.summaryExpired')
    }
    return t('verification.summaryWarning')
  }
  if (aggregate === 'not_verified') {
    return t('verification.summaryFail')
  }
  return ''
}

export function VerificationPanel({
  verification
}: {
  verification: UseVerificationReturn
}) {
  const { t } = useTranslation()
  const { result, loading, error, lastCheckedAt } = verification
  const pending = loading || (!result && !error)
  const summaryMessage = summaryMessageFor(error, pending, result, t)

  return (
    <Box sx={sx.vpCard}>
      <Box sx={sx.vpCardColumns}>
        <Box sx={sx.vpGrayBox}>
          <Typography component="h3" variant="subtitle2" sx={sx.vpGrayTitle}>
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

          {!pending && error && (
            <Typography variant="body2" color="error.main" sx={sx.vpBody}>
              {error.message}
            </Typography>
          )}

          {!pending && !error && result && (
            <>
              <Typography component="p" sx={sx.vpSubTitle}>
                {t('verification.checklistSubtitle')}
              </Typography>
              {checklistSteps(result).map(({ key, step }) => (
                <ChecklistRow key={key} step={step} />
              ))}
              {lastCheckedAt && (
                <Typography sx={sx.vpLastCheckedInline}>
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
  const warning = !error && result != null && hasVerificationWarning(result)
  const notVerified =
    !!error ||
    (result != null && getVerificationAggregateStatus(result) === 'not_verified')

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

  if (notVerified) {
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

  if (warning) {
    return (
      <Box
        sx={{ ...sx.vpStatusBadge, ...sx.vpStatusBadgeWarning }}
        aria-live="polite"
      >
        <Box sx={sx.vpStatusWarningCircle} aria-hidden>
          <Typography component="span" sx={sx.vpStatusWarningMark}>
            !
          </Typography>
        </Box>
        <Typography variant="body2" sx={sx.vpStatusBadgeLabel}>
          {t('verification.badgeWarning')}
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
