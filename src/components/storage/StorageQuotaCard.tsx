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

const STATE_BADGE: Record<
  BackendState,
  { label: string; tone: (typeof sx)[keyof typeof sx] }
> = {
  ok: { label: 'OK', tone: sx.quotaBadgeOk },
  'near-limit': { label: 'Almost full', tone: sx.quotaBadgeWarning },
  'over-quota': { label: 'Full', tone: sx.quotaBadgeError }
}

const PROGRESS_COLOR: Record<
  BackendState,
  'primary' | 'warning' | 'error'
> = {
  ok: 'primary',
  'near-limit': 'warning',
  'over-quota': 'error'
}

function usageHeroMeta(unit: string): string {
  if (unit === 'B') {
    return 'bytes used'
  }
  return `${unit.toLowerCase()} used`
}

function formatMeasuredLabel(measuredAt: string): string {
  const date = new Date(measuredAt)
  if (Number.isNaN(date.getTime())) {
    return 'Measured recently'
  }
  return `Measured ${date.toLocaleString()}`
}

function formatLimitedSummary(quota: StorageQuotaView): string {
  let summary = `${formatBytes(quota.usageBytes)} of ${formatBytes(quota.capacityBytes ?? 0)}`
  if (quota.freeBytes != null) {
    summary += ` · ${formatBytes(quota.freeBytes)} free`
  }
  return summary
}

function QuotaReadyContent({
  quota,
  collections
}: {
  quota: StorageQuotaView
  collections: StorageCollection[]
}) {
  const collectionRows = buildCollectionQuotaRows(quota, collections)
  const { amount, unit } = formatBytesParts(quota.usageBytes)
  const heroMeta = usageHeroMeta(unit)
  const measuredLabel = formatMeasuredLabel(quota.measuredAt)

  return (
    <Stack spacing={2}>
      {quota.state === 'over-quota' && (
        <Alert severity="error">
          Storage is full. New uploads and imports may be blocked until you free
          space.
        </Alert>
      )}
      {quota.state === 'near-limit' && (
        <Alert severity="warning">
          Storage is almost full. Consider exporting or removing old content.
        </Alert>
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
                {formatLimitedSummary(quota)}
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
              Unlimited
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
                        of
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
          Max upload size: {formatBytes(quota.maxUploadBytes)} per file
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
  if (status.kind === 'unavailable') {
    return null
  }

  let headerBadge: (typeof STATE_BADGE)[BackendState] | null = null
  if (status.kind === 'ready') {
    headerBadge = STATE_BADGE[status.quota.state]
  }

  return (
    <Paper variant="outlined" sx={sx.quotaCard}>
      <Stack direction="row" sx={sx.quotaCardHeader}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
          <Box sx={sx.quotaTitleIcon} aria-hidden>
            <MdStorage size={22} />
          </Box>
          <Typography variant="h6" sx={sx.connectedLabel}>
            Storage usage
          </Typography>
        </Stack>
        {headerBadge && (
          <Box sx={[sx.quotaStatusBadge, headerBadge.tone]}>
            {status.kind === 'ready' && status.quota.state === 'ok' && (
              <MdCheckCircle size={14} />
            )}
            <Typography component="span" variant="caption" sx={sx.quotaStatusBadgeLabel}>
              {headerBadge.label}
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
            {status.message}
          </Typography>
          {onRetry && (
            <Button size="small" variant="outlined" onClick={onRetry}>
              Retry
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
