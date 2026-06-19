import {
  Alert,
  Box,
  Button,
  Divider,
  LinearProgress,
  Paper,
  Skeleton,
  Stack,
  Typography
} from '@mui/material'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import type { IconType } from 'react-icons'
import {
  MdAccessTime,
  MdBadge,
  MdCheckCircle,
  MdFolder,
  MdShare,
  MdStorage,
  MdTimeline
} from 'react-icons/md'
import { formatBytes, formatBytesParts } from '@/lib/formatBytes'
import { buildCollectionQuotaRows } from '@/lib/storageQuota'
import type { StorageCollection } from '@/lib/storage'
import type {
  BackendState,
  StorageQuotaStatus,
  StorageQuotaView
} from '@/types/storageQuota'
import { storageStyles as sx } from '@/styles/appStyles'

interface StorageQuotaCardProps {
  status: StorageQuotaStatus
  collections?: StorageCollection[]
  onRetry?: () => void
}

const COLLECTION_ICONS: Record<string, IconType> = {
  'private-credentials': MdBadge,
  'wallet-activity': MdTimeline,
  'public-credentials': MdShare
}

const STATE_BADGE_TONE: Record<BackendState, (typeof sx)[keyof typeof sx]> = {
  ok: sx.quotaBadgeOk,
  'near-limit': sx.quotaBadgeWarning,
  'over-quota': sx.quotaBadgeError,
  unreachable: sx.quotaBadgeError
}

const STATE_BADGE_KEY: Record<BackendState, string> = {
  ok: 'storage.quota.stateOk',
  'near-limit': 'storage.quota.stateNearLimit',
  'over-quota': 'storage.quota.stateOverQuota',
  unreachable: 'storage.quota.stateOverQuota'
}

const PROGRESS_COLOR: Record<
  BackendState,
  'primary' | 'warning' | 'error'
> = {
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

function QuotaReadyContent({
  quota,
  collections
}: {
  quota: StorageQuotaView
  collections: StorageCollection[]
}) {
  const { t, i18n } = useTranslation()
  const collectionRows = buildCollectionQuotaRows(quota, collections)
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
          <Box sx={[sx.quotaStatusBadge, sx.quotaBadgeUnlimited]}>
            <Typography component="span" variant="caption" sx={sx.quotaUnlimitedSymbol}>
              ∞
            </Typography>
            <Typography component="span" variant="caption" sx={sx.quotaStatusBadgeLabel}>
              {t('storage.quota.unlimited')}
            </Typography>
          </Box>
        )}
      </Stack>

      {collectionRows.length > 0 && (
        <Stack spacing={1.25} sx={sx.quotaCollectionList}>
          {collectionRows.map(row => {
            const Icon = COLLECTION_ICONS[row.id] ?? MdFolder
            const { amount: rowAmount, unit: rowUnit } = formatBytesParts(
              row.usageBytes
            )

            return (
              <Stack key={row.id} direction="row" sx={sx.quotaCollectionRow}>
                <Box sx={sx.quotaCollectionIcon} aria-hidden>
                  <Icon size={18} />
                </Box>
                <Typography variant="body2" sx={sx.quotaCollectionName}>
                  {row.name}
                </Typography>
                <Box sx={sx.quotaCollectionValueWrap}>
                  <Typography component="span" sx={sx.quotaCollectionValueAmount}>
                    {rowAmount}
                  </Typography>
                  {rowUnit && (
                    <Typography component="span" sx={sx.quotaCollectionValueUnit}>
                      {rowUnit}
                    </Typography>
                  )}
                  {!quota.isUnlimited && row.capacityBytes != null && (
                    <>
                      <Typography component="span" sx={sx.quotaCollectionValueOf}>
                        {t('storage.quota.of')}
                      </Typography>
                      <Typography
                        component="span"
                        sx={sx.quotaCollectionValueCapacity}
                      >
                        {formatBytes(row.capacityBytes)}
                      </Typography>
                    </>
                  )}
                </Box>
              </Stack>
            )
          })}
        </Stack>
      )}

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
  collections = [],
  onRetry
}: StorageQuotaCardProps) {
  const { t } = useTranslation()

  if (status.kind === 'unavailable') {
    return null
  }

  let headerState: BackendState | null = null
  if (status.kind === 'ready') {
    headerState = status.quota.state
  }

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
          <Box sx={[sx.quotaStatusBadge, STATE_BADGE_TONE[headerState]]}>
            {status.kind === 'ready' && status.quota.state === 'ok' && (
              <MdCheckCircle size={14} />
            )}
            <Typography component="span" variant="caption" sx={sx.quotaStatusBadgeLabel}>
              {t(STATE_BADGE_KEY[headerState])}
            </Typography>
          </Box>
        )}
      </Stack>

      <Divider sx={sx.quotaDivider} />

      {status.kind === 'loading' && (
        <Stack spacing={2}>
          <Skeleton variant="text" width="40%" />
          <Skeleton variant="text" width="25%" height={40} />
          <Skeleton variant="text" width="100%" height={28} />
          <Skeleton variant="text" width="100%" height={28} />
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

      {status.kind === 'ready' && (
        <QuotaReadyContent quota={status.quota} collections={collections} />
      )}
    </Paper>
  )
}
