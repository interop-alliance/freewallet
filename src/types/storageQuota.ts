import type { BackendState } from '@interop/storage-core'

export type {
  BackendState,
  BackendUsage,
  CollectionUsage,
  SpaceQuotaReport
} from '@interop/storage-core'

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
