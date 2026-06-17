import type {
  CollectionQuotaRow,
  SpaceQuotaReport,
  StorageQuotaView
} from '@/types/storageQuota'

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
    backendName: backend.name,
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

function collectionDisplayName(collection: {
  id: string
  name?: string
}): string {
  if (collection.name && collection.name.trim().length > 0) {
    return collection.name.trim()
  }
  return collection.id
}

export function buildCollectionQuotaRows(
  quota: StorageQuotaView,
  collections: Array<{ id: string; name?: string }>
): CollectionQuotaRow[] {
  const seen = new Set<string>()
  const rows: CollectionQuotaRow[] = []

  for (const collection of collections) {
    seen.add(collection.id)
    rows.push({
      id: collection.id,
      name: collectionDisplayName(collection),
      usageBytes: quota.usageByCollection.get(collection.id) ?? 0
    })
  }

  for (const [id, usageBytes] of quota.usageByCollection) {
    if (!seen.has(id)) {
      rows.push({ id, name: id, usageBytes })
    }
  }

  const perCollectionCapacity =
    !quota.isUnlimited &&
    quota.capacityBytes != null &&
    quota.capacityBytes > 0 &&
    rows.length > 0
      ? quota.capacityBytes / rows.length
      : undefined

  if (perCollectionCapacity == null) {
    return rows
  }

  return rows.map(row => ({ ...row, capacityBytes: perCollectionCapacity }))
}
