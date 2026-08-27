import { afterEach, describe, expect, it, vi } from 'vitest'

const { lookupIssuersForMock, registryClientUseMock } = vi.hoisted(() => ({
  lookupIssuersForMock: vi.fn(
    async (): Promise<{
      matchingIssuers: Record<string, unknown>[]
      uncheckedRegistries: Record<string, unknown>[]
    }> => ({
      matchingIssuers: [],
      uncheckedRegistries: []
    })
  ),
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
const PROXY_BASE_URL = 'https://was.example/api/cors'
const TRUST_ANCHOR_EC = 'https://registry.example/.well-known/openid-federation'
const FEDERATION_FETCH = 'https://registry.example/fetch'
const REGISTRY_PAYLOAD = [
  {
    type: 'dcc-legacy',
    name: 'Example Registry',
    url: 'https://example.org/registry.json'
  }
]
const OIDF_REGISTRY = {
  type: 'oidf',
  name: 'Example Federation Registry',
  trustAnchorEC: TRUST_ANCHOR_EC
}
const FALLBACK_REGISTRIES = [
  {
    type: 'dcc-legacy',
    name: 'Fallback Registry',
    url: 'https://example.org/fallback.json'
  }
]

const REGISTRY_METADATA = {
  federation_entity: {
    organization_name: 'Example Federation',
    federation_fetch_endpoint: FEDERATION_FETCH
  }
}
const ISSUER_METADATA = {
  federation_entity: { organization_name: 'Ünïvérsity of Example' },
  institution_additional_information: { legal_name: 'Example University Inc' }
}

async function loadRegistryManager() {
  vi.resetModules()
  vi.doMock('@/app.config', () => ({
    KNOWN_REGISTRIES_URL: DIRECT_REGISTRIES_URL,
    KnownDidRegistries: FALLBACK_REGISTRIES,
    CORS_PROXY_URL: PROXY_BASE_URL
  }))

  return import('@/lib/registryManager')
}

function registriesResponse(payload: unknown = REGISTRY_PAYLOAD) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { 'content-type': 'application/json' }
  })
}

/**
 * Builds an unsigned entity statement: the registry client and this module
 * both read only the payload, so the header and signature segments are inert
 * filler.
 */
function entityStatement(payload: unknown): string {
  const encode = (value: unknown) =>
    btoa(
      String.fromCharCode(...new TextEncoder().encode(JSON.stringify(value)))
    )
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
  return `${encode({ alg: 'ES256' })}.${encode(payload)}.signature`
}

function proxied(url: string): string {
  return `${PROXY_BASE_URL}?url=${encodeURIComponent(url)}`
}

function jwtResponse(payload: unknown, status = 200) {
  return new Response(entityStatement(payload), {
    status,
    headers: { 'content-type': 'application/entity-statement+jwt' }
  })
}

describe('registryManager', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  it('loads registries directly from KNOWN_REGISTRIES_URL, no proxy', async () => {
    const fetchMock = vi.fn(async (url: URL | RequestInfo) => {
      expect(url).toBe(DIRECT_REGISTRIES_URL)
      return registriesResponse()
    })
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager } = await loadRegistryManager()

    await registryManager.lookupDid('did:key:z123')

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock).toHaveBeenCalledWith(
      DIRECT_REGISTRIES_URL,
      expect.anything()
    )
    expect(registryClientUseMock).toHaveBeenCalledWith({
      registries: REGISTRY_PAYLOAD
    })
  })

  it('falls back when the load stalls past the deadline', async () => {
    vi.useFakeTimers()
    const fetchMock = vi.fn(
      (_url: URL | RequestInfo, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(new DOMException('Aborted', 'AbortError'))
          )
        })
    )
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager, LOAD_TIMEOUT_MS } = await loadRegistryManager()

    const lookup = registryManager.lookupDid('did:key:z123')
    await vi.advanceTimersByTimeAsync(LOAD_TIMEOUT_MS)
    await lookup

    expect(registryClientUseMock).toHaveBeenCalledWith({
      registries: FALLBACK_REGISTRIES
    })
  })

  it('uses fallback KnownDidRegistries when the direct fetch fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch')
      })
    )

    const { registryManager } = await loadRegistryManager()

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

    const { registryManager } = await loadRegistryManager()

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

    const { registryManager } = await loadRegistryManager()

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

    const { registryManager } = await loadRegistryManager()

    await registryManager.lookupDid('did:key:z123')
    await registryManager.lookupDid('did:key:z456')

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(registryClientUseMock).toHaveBeenCalledOnce()
  })

  describe('oidf registries', () => {
    /**
     * Stubs the registries list plus both oidf hops, routing anything that is
     * not one of the three known URLs to a 404 so an unexpected direct request
     * fails the case loudly.
     */
    function stubOidfFetch(
      overrides: Record<string, () => Response | Promise<Response>> = {}
    ) {
      const routes: Record<string, () => Response | Promise<Response>> = {
        [DIRECT_REGISTRIES_URL]: () =>
          registriesResponse([...REGISTRY_PAYLOAD, OIDF_REGISTRY]),
        [proxied(TRUST_ANCHOR_EC)]: () =>
          jwtResponse({ metadata: REGISTRY_METADATA }),
        [proxied(`${FEDERATION_FETCH}?sub=did%3Akey%3Az123`)]: () =>
          jwtResponse({ metadata: ISSUER_METADATA }),
        ...overrides
      }
      const fetchMock = vi.fn(async (url: URL | RequestInfo) => {
        const route = routes[String(url)]
        if (!route) {
          return new Response('unrouted', { status: 404 })
        }
        return route()
      })
      vi.stubGlobal('fetch', fetchMock)
      return fetchMock
    }

    it('looks oidf registries up through the CORS proxy, both hops', async () => {
      const fetchMock = stubOidfFetch()

      const { registryManager } = await loadRegistryManager()
      const result = await registryManager.lookupDid('did:key:z123')

      expect(fetchMock).toHaveBeenCalledWith(
        proxied(TRUST_ANCHOR_EC),
        expect.anything()
      )
      expect(fetchMock).toHaveBeenCalledWith(
        proxied(`${FEDERATION_FETCH}?sub=did%3Akey%3Az123`),
        expect.anything()
      )
      expect(result.matchingIssuers).toEqual([
        { issuer: ISSUER_METADATA, registry: REGISTRY_METADATA }
      ])
      expect(result.uncheckedRegistries).toEqual([])
    })

    it('withholds oidf entries from the RegistryClient, which cannot reach them', async () => {
      stubOidfFetch()

      const { registryManager } = await loadRegistryManager()
      await registryManager.lookupDid('did:key:z123')

      expect(registryClientUseMock).toHaveBeenCalledWith({
        registries: REGISTRY_PAYLOAD
      })
    })

    it('reads a 404 from the federation fetch as not-registered, not unchecked', async () => {
      stubOidfFetch({
        [proxied(`${FEDERATION_FETCH}?sub=did%3Akey%3Az123`)]: () =>
          new Response('', { status: 404 })
      })

      const { registryManager } = await loadRegistryManager()
      const result = await registryManager.lookupDid('did:key:z123')

      expect(result.matchingIssuers).toEqual([])
      expect(result.uncheckedRegistries).toEqual([])
    })

    it('reports an unreachable trust anchor as unchecked, keeping the other half', async () => {
      stubOidfFetch({
        [proxied(TRUST_ANCHOR_EC)]: () => {
          throw new TypeError('Failed to fetch')
        }
      })
      lookupIssuersForMock.mockResolvedValueOnce({
        matchingIssuers: [{ issuer: { name: 'Legacy hit' }, registry: {} }],
        uncheckedRegistries: []
      })

      const { registryManager } = await loadRegistryManager()
      const result = await registryManager.lookupDid('did:key:z123')

      expect(result.matchingIssuers).toEqual([
        { issuer: { name: 'Legacy hit' }, registry: {} }
      ])
      expect(result.uncheckedRegistries).toEqual([OIDF_REGISTRY])
    })

    it('reports an entity configuration naming no fetch endpoint as unchecked', async () => {
      stubOidfFetch({
        [proxied(TRUST_ANCHOR_EC)]: () =>
          jwtResponse({ metadata: { federation_entity: {} } })
      })

      const { registryManager } = await loadRegistryManager()
      const result = await registryManager.lookupDid('did:key:z123')

      expect(result.matchingIssuers).toEqual([])
      expect(result.uncheckedRegistries).toEqual([OIDF_REGISTRY])
    })
  })

  it('__resetRegistryCacheForTests clears the cached client', async () => {
    const fetchMock = vi.fn(async () => registriesResponse())
    vi.stubGlobal('fetch', fetchMock)

    const { registryManager, __resetRegistryCacheForTests } =
      await loadRegistryManager()

    await registryManager.lookupDid('did:key:z123')
    __resetRegistryCacheForTests()
    await registryManager.lookupDid('did:key:z456')

    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})
