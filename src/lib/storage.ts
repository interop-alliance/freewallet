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
}

export type StorageCollectionList = {
  url: string
  totalItems: number
  items: StorageCollection[]
}

export const getBackends = (): StorageBackend[] => {
  return [
    {
      id: '0',
      displayName: 'Default Backend',
      description: 'Wallet Attached Storage',
      enabled: true
    },
    {
      id: '1',
      displayName: 'Google Drive',
      description: 'Coming soon',
      enabled: false,
      comingSoon: true
    }
  ]
}
