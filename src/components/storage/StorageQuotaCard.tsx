import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  LinearProgress,
  Paper,
  Skeleton,
  Stack,
  Typography
} from '@mui/material'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { MdAccessTime, MdCheckCircle, MdStorage } from 'react-icons/md'
import { formatBytes, formatBytesParts } from '@/lib/formatBytes'
import type {
  BackendState,
  StorageQuotaStatus,
  StorageQuotaView
} from '@/types/storageQuota'
import { storageStyles as sx } from '@/styles/appStyles'

const STATE_BADGE_COLOR: Record<BackendState, 'success' | 'warning' | 'error'> =
  {
    ok: 'success',
    'near-limit': 'warning',
    'over-quota': 'error',
    unreachable: 'error'
  }

const STATE_BADGE_KEY: Record<BackendState, string> = {
  ok: 'storage.quota.stateOk',
  'near-limit': 'storage.quota.stateNearLimit',
  'over-quota': 'storage.quota.stateOverQuota',
  unreachable: 'storage.quota.stateOverQuota'
}

const PROGRESS_COLOR: Record<BackendState, 'primary' | 'warning' | 'error'> = {
  ok: 'primary',
  'near-limit': 'warning',
  'over-quota': 'error',
  unreachable: 'error'
}

function usageHeroMeta(t: TFunction, unit: string): string {
  if (unit === 'B') {
    return t('storage.quota.bytesUsed')
  }
  return t('storage.quota.unitUsed', { unit })
}

function formatMeasuredLabel(
  t: TFunction,
  locale: string,
  measuredAt: string
): string {
  const date = new Date(measuredAt)
  if (Number.isNaN(date.getTime())) {
    return t('storage.quota.measuredRecently')
  }
  return t('storage.quota.measuredAt', {
    date: date.toLocaleString(locale)
  })
}

function formatLimitedSummary(t: TFunction, quota: StorageQuotaView): string {
  const used = formatBytes(quota.usageBytes)
  const capacity = formatBytes(quota.capacityBytes ?? 0)
  if (quota.freeBytes != null) {
    return t('storage.quota.limitedSummaryWithFree', {
      used,
      capacity,
      free: formatBytes(quota.freeBytes)
    })
  }
  return t('storage.quota.limitedSummary', { used, capacity })
}

function QuotaReadyContent({ quota }: { quota: StorageQuotaView }) {
  const { t, i18n } = useTranslation()
  const { amount, unit } = formatBytesParts(quota.usageBytes)
  const heroMeta = usageHeroMeta(t, unit)
  const measuredLabel = formatMeasuredLabel(t, i18n.language, quota.measuredAt)

  return (
    <Stack spacing={2}>
      {quota.state === 'over-quota' && (
        <Alert severity="error">{t('storage.quota.overQuotaAlert')}</Alert>
      )}
      {quota.state === 'near-limit' && (
        <Alert severity="warning">{t('storage.quota.nearLimitAlert')}</Alert>
      )}

      <Stack
        direction="row"
        sx={{ alignItems: 'flex-end', justifyContent: 'space-between', gap: 2 }}
      >
        <Box>
          <Typography variant="caption" sx={sx.quotaBackendLabel}>
            {quota.backendName}
          </Typography>
          {/* Unlimited quota */}
          {quota.isUnlimited && (
            // Show usage amount + unit (e.g. "2.4 MB")
            <Stack direction="row" sx={sx.quotaHeroAmountRow}>
              <Typography component="span" sx={sx.quotaHeroAmount}>
                {amount}
              </Typography>
              <Typography component="span" sx={sx.quotaHeroMeta}>
                {heroMeta}
              </Typography>
            </Stack>
          )}
          {/* Limited quota (show usage + progress bar) */}
          {!quota.isUnlimited && (
            <Stack spacing={0.75} sx={{ mt: 0.5 }}>
              <Typography variant="body2" sx={sx.quotaLimitedSummary}>
                {formatLimitedSummary(t, quota)}
              </Typography>
              {quota.percentUsed != null && (
                <LinearProgress
                  variant="determinate"
                  value={quota.percentUsed}
                  color={PROGRESS_COLOR[quota.state]}
                  sx={sx.quotaBar}
                />
              )}
            </Stack>
          )}
        </Box>
        {quota.isUnlimited && (
          <Chip
            size="small"
            variant="outlined"
            color="success"
            icon={
              <Box component="span" sx={sx.quotaUnlimitedSymbol} aria-hidden>
                ∞
              </Box>
            }
            label={t('storage.quota.unlimited')}
          />
        )}
      </Stack>

      <Stack direction="row" spacing={0.75} sx={sx.quotaMeasuredRow}>
        <Box sx={sx.quotaMeasuredIcon} aria-hidden>
          <MdAccessTime size={14} />
        </Box>
        <Typography variant="caption" color="text.secondary">
          {measuredLabel}
        </Typography>
      </Stack>

      {quota.maxUploadBytes != null && (
        <Typography variant="caption" color="text.secondary">
          {t('storage.quota.maxUploadSize', {
            size: formatBytes(quota.maxUploadBytes)
          })}
        </Typography>
      )}
    </Stack>
  )
}

export function StorageQuotaCard({
  status,
  onRetry
}: {
  status: StorageQuotaStatus
  onRetry?: () => void
}) {
  const { t } = useTranslation()

  if (status.kind === 'unavailable') {
    return null
  }

  const headerState: BackendState | null =
    status.kind === 'ready' ? status.quota.state : null

  return (
    <Paper variant="outlined" sx={sx.quotaCard}>
      <Stack direction="row" sx={sx.quotaCardHeader}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
          <Box sx={sx.quotaTitleIcon} aria-hidden>
            <MdStorage size={22} />
          </Box>
          <Typography variant="h6" sx={sx.connectedLabel}>
            {t('storage.quota.title')}
          </Typography>
        </Stack>
        {headerState && (
          <Chip
            size="small"
            variant="outlined"
            color={STATE_BADGE_COLOR[headerState]}
            icon={
              headerState === 'ok' ? <MdCheckCircle size={14} /> : undefined
            }
            label={t(STATE_BADGE_KEY[headerState])}
          />
        )}
      </Stack>

      <Divider sx={sx.quotaDivider} />

      {status.kind === 'loading' && (
        <Stack spacing={2}>
          <Skeleton variant="text" width="40%" />
          <Skeleton variant="text" width="25%" height={40} />
          <Skeleton variant="text" width="100%" height={28} />
        </Stack>
      )}

      {status.kind === 'error' && (
        <Stack spacing={1.5}>
          <Typography variant="body2" color="error">
            {t('storage.quota.loadError')}
          </Typography>
          {onRetry && (
            <Button size="small" variant="outlined" onClick={onRetry}>
              {t('storage.quota.retry')}
            </Button>
          )}
        </Stack>
      )}

      {status.kind === 'ready' && <QuotaReadyContent quota={status.quota} />}
    </Paper>
  )
}
