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

async function loadRegistryManager(
  corsProxyFetch: (url: string) => ReturnType<typeof fetch>
) {
  vi.resetModules()
  vi.doMock('@/app.config', () => ({
    KNOWN_REGISTRIES_URL: DIRECT_REGISTRIES_URL,
    KnownDidRegistries: REGISTRY_PAYLOAD
  }))
  vi.doMock('@/lib/corsProxy', () => ({ corsProxyFetch }))

  return import('@/lib/registryManager')
}

describe('registryManager', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  it('loads registries via corsProxyFetch when the request succeeds', async () => {
    const fetchMock = vi.fn(async (url: URL | RequestInfo) => {
      expect(url).toBe(DIRECT_REGISTRIES_URL)
      return new Response(JSON.stringify(REGISTRY_PAYLOAD), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager } = await loadRegistryManager(url => fetch(url))

    await registryManager.lookupDid('did:key:z123')

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(registryClientUseMock).toHaveBeenCalledWith({
      registries: REGISTRY_PAYLOAD
    })
  })

  it('loads registries via the WAS proxy URL when corsProxyFetch wraps fetch', async () => {
    const proxyUrl =
      `${PROXY_BASE_URL}/api/cors?url=` +
      encodeURIComponent(DIRECT_REGISTRIES_URL)
    const fetchMock = vi.fn(async (url: URL | RequestInfo) => {
      expect(url).toBe(proxyUrl)
      return new Response(JSON.stringify(REGISTRY_PAYLOAD), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager } = await loadRegistryManager(url =>
      fetch(`${PROXY_BASE_URL}/api/cors?url=${encodeURIComponent(url)}`)
    )

    await registryManager.lookupDid('did:key:z123')

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock).toHaveBeenCalledWith(proxyUrl)
  })

  it('uses fallback KnownDidRegistries when corsProxyFetch fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch')
      })
    )

    const { registryManager } = await loadRegistryManager(url => fetch(url))

    await registryManager.lookupDid('did:key:z123')

    expect(registryClientUseMock).toHaveBeenCalledWith({
      registries: REGISTRY_PAYLOAD
    })
  })
})
