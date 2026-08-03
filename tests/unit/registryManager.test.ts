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
const FALLBACK_REGISTRIES = [
  {
    type: 'dcc-legacy',
    name: 'Fallback Registry',
    url: 'https://example.org/fallback.json'
  }
]

async function loadRegistryManager(
  corsProxyFetch: (options: { url: string }) => ReturnType<typeof fetch>
) {
  vi.resetModules()
  vi.doMock('@/app.config', () => ({
    KNOWN_REGISTRIES_URL: DIRECT_REGISTRIES_URL,
    KnownDidRegistries: FALLBACK_REGISTRIES
  }))
  vi.doMock('@/lib/corsProxy', () => ({ corsProxyFetch }))

  return import('@/lib/registryManager')
}

/**
 * A corsProxyFetch stub that hits the (stubbed) global fetch directly, i.e. the
 * no-proxy-configured shape.
 */
function directProxyFetch({ url }: { url: string }) {
  return fetch(url)
}

function registriesResponse() {
  return new Response(JSON.stringify(REGISTRY_PAYLOAD), {
    status: 200,
    headers: { 'content-type': 'application/json' }
  })
}

describe('registryManager', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  it('loads registries via corsProxyFetch when the request succeeds', async () => {
    const fetchMock = vi.fn(async (url: URL | RequestInfo) => {
      expect(url).toBe(DIRECT_REGISTRIES_URL)
      return registriesResponse()
    })
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager } = await loadRegistryManager(directProxyFetch)

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
      return registriesResponse()
    })
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager } = await loadRegistryManager(({ url }) =>
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

    const { registryManager } = await loadRegistryManager(directProxyFetch)

    await registryManager.lookupDid('did:key:z123')

    expect(registryClientUseMock).toHaveBeenCalledWith({
      registries: FALLBACK_REGISTRIES
    })
  })

  it('does not cache the fallback: a later lookup retries the fetch', async () => {
    let attempt = 0
    const fetchMock = vi.fn(async () => {
      attempt += 1
      if (attempt === 1) {
        throw new TypeError('Failed to fetch')
      }
      return registriesResponse()
    })
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager } = await loadRegistryManager(directProxyFetch)

    await registryManager.lookupDid('did:key:z123')
    expect(registryClientUseMock).toHaveBeenLastCalledWith({
      registries: FALLBACK_REGISTRIES
    })

    await registryManager.lookupDid('did:key:z456')

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(registryClientUseMock).toHaveBeenLastCalledWith({
      registries: REGISTRY_PAYLOAD
    })
  })

  it('retries after a non-ok response too', async () => {
    let attempt = 0
    const fetchMock = vi.fn(async () => {
      attempt += 1
      if (attempt === 1) {
        return new Response('nope', { status: 502 })
      }
      return registriesResponse()
    })
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager } = await loadRegistryManager(directProxyFetch)

    await registryManager.lookupDid('did:key:z123')
    await registryManager.lookupDid('did:key:z456')

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(registryClientUseMock).toHaveBeenLastCalledWith({
      registries: REGISTRY_PAYLOAD
    })
  })

  it('caches a successful load: a later lookup does not refetch', async () => {
    const fetchMock = vi.fn(async () => registriesResponse())
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager } = await loadRegistryManager(directProxyFetch)

    await registryManager.lookupDid('did:key:z123')
    await registryManager.lookupDid('did:key:z456')

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(registryClientUseMock).toHaveBeenCalledOnce()
  })

  it('__resetRegistryCacheForTests clears the cached client', async () => {
    const fetchMock = vi.fn(async () => registriesResponse())
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager, __resetRegistryCacheForTests } =
      await loadRegistryManager(directProxyFetch)

    await registryManager.lookupDid('did:key:z123')
    __resetRegistryCacheForTests()
    await registryManager.lookupDid('did:key:z456')

    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})
