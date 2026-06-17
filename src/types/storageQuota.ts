export type BackendState = 'ok' | 'near-limit' | 'over-quota'

export type CollectionUsage = {
  id: string
  usageBytes: number
}

export type BackendUsage = {
  id: string
  name: string
  managedBy: string
  usageBytes: number
  state: BackendState
  limit: { isUnlimited: boolean; capacityBytes?: number }
  restrictedActions: string[]
  measuredAt: string
  constraints?: { maxUploadBytes?: number }
  usageByCollection?: CollectionUsage[]
}

export type SpaceQuotaReport = {
  respondedAt: string
  backends: BackendUsage[]
}

export type StorageQuotaView = {
  backendName: string
  usageBytes: number
  capacityBytes?: number
  isUnlimited: boolean
  state: BackendState
  restrictedActions: string[]
  maxUploadBytes?: number
  measuredAt: string
  usageByCollection: Map<string, number>
  percentUsed?: number
  freeBytes?: number
}

export type StorageQuotaStatus =
  | { kind: 'loading' }
  | { kind: 'unavailable' }
  | { kind: 'error' }
  | { kind: 'ready'; quota: StorageQuotaView }

export type CollectionQuotaRow = {
  id: string
  name: string
  usageBytes: number
  capacityBytes?: number
}
