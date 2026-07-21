import type { SpaceQuotaReport, StorageQuotaView } from '@/types/storageQuota'

export function quotaViewFromReport(
  report: SpaceQuotaReport
): StorageQuotaView | null {
  const backend = report.backends[0]
  if (!backend) {
    return null
  }

  const usageByCollection = new Map<string, number>()
  for (const entry of backend.usageByCollection ?? []) {
    usageByCollection.set(entry.id, entry.usageBytes)
  }

  const isUnlimited = backend.limit.isUnlimited
  const capacityBytes = backend.limit.capacityBytes
  let percentUsed: number | undefined
  let freeBytes: number | undefined

  if (!isUnlimited && capacityBytes != null && capacityBytes > 0) {
    percentUsed = Math.min(
      100,
      Math.round((backend.usageBytes / capacityBytes) * 100)
    )
    freeBytes = Math.max(0, capacityBytes - backend.usageBytes)
  }

  return {
    backendName: backend.name ?? backend.id,
    usageBytes: backend.usageBytes,
    capacityBytes,
    isUnlimited,
    state: backend.state,
    restrictedActions: backend.restrictedActions,
    maxUploadBytes: backend.constraints?.maxUploadBytes,
    measuredAt: backend.measuredAt,
    usageByCollection,
    percentUsed,
    freeBytes
  }
}

export function writesRestricted(quota: StorageQuotaView): boolean {
  if (quota.state !== 'over-quota') {
    return false
  }
  return quota.restrictedActions.some(
    action => action === 'POST' || action === 'PUT'
  )
}
