export type StorageBackend = {
  id: string
  displayName: string
  description: string
  enabled?: boolean
  comingSoon?: boolean
}

export type StorageCollection = {
  id: string
  displayName: string
  backendId: string
}

export const getCollections = (): StorageCollection[] => {
  return [
    {
      id: '0',
      displayName: 'Private Credentials',
      backendId: 'default'
    },
    {
      id: '1',
      displayName: 'Public Credentials',
      backendId: 'default'
    },
    {
      id: '2',
      displayName: 'History',
      backendId: 'default'
    }
  ]
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
