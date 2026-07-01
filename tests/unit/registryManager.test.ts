import { afterEach, describe, expect, it, vi } from 'vitest'

const { lookupIssuersForMock, registryClientUseMock } = vi.hoisted(() => ({
  lookupIssuersForMock: vi.fn(async () => ({
    matchingIssuers: [],
    uncheckedRegistries: []
  })),
  registryClientUseMock: vi.fn()
}))

vi.mock('@digitalcredentials/issuer-registry-client', () => ({
  RegistryClient: class {
    use = registryClientUseMock
    lookupIssuersFor = lookupIssuersForMock
  }
}))

const DIRECT_REGISTRIES_URL =
  'https://digitalcredentials.github.io/dcc-known-registries/known-did-registries.json'
const PROXY_BASE_URL = 'https://was.example'
const REGISTRY_PAYLOAD = [
  {
    type: 'dcc-legacy',
    name: 'Example Registry',
    url: 'https://example.org/registry.json'
  }
]

async function loadRegistryManager(wasServerUrl: string | undefined) {
  vi.resetModules()
  vi.doMock('@/app.config', () => ({
    KNOWN_REGISTRIES_URL: DIRECT_REGISTRIES_URL,
    KnownDidRegistries: REGISTRY_PAYLOAD,
    WAS_SERVER_URL: wasServerUrl
  }))

  return import('@/lib/registryManager')
}

describe('registryManager', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  it('fetches registries directly when the browser request succeeds', async () => {
    const fetchMock = vi.fn(async (url: URL | RequestInfo) => {
      expect(url).toBe(DIRECT_REGISTRIES_URL)
      return new Response(JSON.stringify(REGISTRY_PAYLOAD), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager } = await loadRegistryManager(PROXY_BASE_URL)

    await registryManager.lookupDid('did:key:z123')

    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('falls back to the WAS proxy when the direct request fails', async () => {
    const proxyUrl =
      `${PROXY_BASE_URL}/api/cors?url=` +
      encodeURIComponent(DIRECT_REGISTRIES_URL)
    const fetchMock = vi.fn(async (url: URL | RequestInfo) => {
      if (url === DIRECT_REGISTRIES_URL) {
        throw new TypeError('Failed to fetch')
      }
      if (url === proxyUrl) {
        return new Response(JSON.stringify(REGISTRY_PAYLOAD), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        })
      }
      throw new Error(`Unexpected fetch url: ${String(url)}`)
    })
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager } = await loadRegistryManager(PROXY_BASE_URL)

    await registryManager.lookupDid('did:key:z123')

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock).toHaveBeenNthCalledWith(1, DIRECT_REGISTRIES_URL)
    expect(fetchMock).toHaveBeenNthCalledWith(2, proxyUrl)
  })
})
