export type StorageBackend = {
  id: string
  displayName: string
  description: string
  enabled?: boolean
  comingSoon?: boolean
}

export type StorageCollection = {
  id: string
  url: string
  name?: string
  type?: string[]
  totalItems?: number
}

export type StorageCollectionList = {
  url: string
  totalItems: number
  items: StorageCollection[]
}

export type StorageResource = {
  id: string
  url: string
  name?: string
  contentType?: string
  type?: string[]
  created?: string
  modified?: string
  updated?: string
  size?: number
}

export type StorageResourceList = {
  id?: string
  url: string
  name?: string
  type?: string[]
  totalItems: number
  items: StorageResource[]
}

export const getBackends = (): StorageBackend[] => {
  return [
    {
      id: 'default',
      displayName: 'Default Backend',
      description: 'Wallet Attached Storage',
      enabled: true
    },
    {
      id: 'google-drive',
      displayName: 'Google Drive',
      description: 'Coming soon',
      enabled: false,
      comingSoon: true
    }
  ]
}
