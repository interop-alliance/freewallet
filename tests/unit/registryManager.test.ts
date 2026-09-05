import { afterEach, describe, expect, it, vi } from 'vitest'

const DIRECT_REGISTRIES_URL =
  'https://digitalcredentials.github.io/dcc-known-registries/known-did-registries.json'
const PROXY_BASE_URL = 'https://was.example/api/cors'
const TRUST_ANCHOR_EC = 'https://registry.example/.well-known/openid-federation'
const FEDERATION_FETCH = 'https://registry.example/fetch'
const DID = 'did:key:z123'

const LEGACY_URL = 'https://example.org/registry.json'
const FALLBACK_URL = 'https://example.org/fallback.json'

const LEGACY_REGISTRY = {
  type: 'dcc-legacy',
  name: 'Example Registry',
  url: LEGACY_URL
}
const REGISTRY_PAYLOAD = [LEGACY_REGISTRY]
const OIDF_REGISTRY = {
  type: 'oidf',
  name: 'Example Federation Registry',
  trustAnchorEC: TRUST_ANCHOR_EC
}
const FALLBACK_REGISTRIES = [
  {
    type: 'dcc-legacy',
    name: 'Fallback Registry',
    url: FALLBACK_URL
  }
]

/**
 * A `dcc-legacy` registry file listing one issuer under the DID every case
 * looks up. The client remaps this into the `federation_entity` shape below.
 */
const LEGACY_BODY = {
  registry: {
    [DID]: {
      name: 'Example University',
      url: 'https://example.edu',
      location: 'Cambridge, MA, USA'
    }
  }
}
const LEGACY_MATCH = {
  issuer: {
    federation_entity: {
      organization_name: 'Example University',
      homepage_uri: 'https://example.edu',
      location: 'Cambridge, MA, USA'
    }
  },
  registry: {
    type: 'dcc-legacy',
    federation_entity: { organization_name: 'Example Registry' },
    institution_additional_information: { legacy_list: LEGACY_URL }
  }
}

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

function jsonResponse(payload: unknown) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { 'content-type': 'application/json' }
  })
}

/**
 * Builds an unsigned entity statement: the registry client reads only the
 * payload, so the header and signature segments are inert filler.
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

function jwtResponse(payload: unknown) {
  return new Response(entityStatement(payload), {
    status: 200,
    headers: { 'content-type': 'application/entity-statement+jwt' }
  })
}

function proxied(url: string): string {
  return `${PROXY_BASE_URL}?url=${encodeURIComponent(url)}`
}

type Route = () => Response | Promise<Response>

/**
 * Stubs the global fetch against an exact-URL route table, answering anything
 * unrouted with a 404 so an unexpected direct (unproxied) request shows up as
 * a failed expectation rather than a silent pass.
 */
function stubFetch(routes: Record<string, Route>) {
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

describe('registryManager', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  it('fetches the registries list and the legacy registries directly', async () => {
    const fetchMock = stubFetch({
      [DIRECT_REGISTRIES_URL]: () => registriesResponse(),
      [LEGACY_URL]: () => jsonResponse(LEGACY_BODY)
    })

    const { registryManager } = await loadRegistryManager()
    const result = await registryManager.lookupDid(DID)

    expect(fetchMock).toHaveBeenCalledWith(
      DIRECT_REGISTRIES_URL,
      expect.anything()
    )
    expect(fetchMock).toHaveBeenCalledWith(LEGACY_URL, expect.anything())
    expect(result.matchingIssuers).toEqual([LEGACY_MATCH])
    expect(result.uncheckedRegistries).toEqual([])
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

    const { registryManager, HOP_TIMEOUT_MS } = await loadRegistryManager()

    const lookup = registryManager.lookupDid(DID)
    // One deadline per hop: the registries load, then the fallback registry.
    await vi.advanceTimersByTimeAsync(HOP_TIMEOUT_MS)
    await vi.advanceTimersByTimeAsync(HOP_TIMEOUT_MS)
    const result = await lookup

    expect(fetchMock).toHaveBeenCalledWith(FALLBACK_URL, expect.anything())
    expect(result.uncheckedRegistries).toEqual(FALLBACK_REGISTRIES)
    // A hop the deadline aborted is not retried through the proxy.
    expect(fetchMock).not.toHaveBeenCalledWith(
      proxied(FALLBACK_URL),
      expect.anything()
    )
  })

  it('retries a blocked legacy registry through the CORS proxy', async () => {
    const fetchMock = stubFetch({
      [DIRECT_REGISTRIES_URL]: () => registriesResponse(),
      [LEGACY_URL]: () => {
        // What a browser does when the host stops sending `ACAO: *`.
        throw new TypeError('Failed to fetch')
      },
      [proxied(LEGACY_URL)]: () => jsonResponse(LEGACY_BODY)
    })

    const { registryManager } = await loadRegistryManager()
    const result = await registryManager.lookupDid(DID)

    expect(fetchMock).toHaveBeenCalledWith(LEGACY_URL, expect.anything())
    expect(fetchMock).toHaveBeenCalledWith(
      proxied(LEGACY_URL),
      expect.anything()
    )
    expect(result.matchingIssuers).toEqual([LEGACY_MATCH])
    expect(result.uncheckedRegistries).toEqual([])
  })

  it('reports a legacy registry unchecked when the proxy retry fails too', async () => {
    stubFetch({
      [DIRECT_REGISTRIES_URL]: () => registriesResponse(),
      [LEGACY_URL]: () => {
        throw new TypeError('Failed to fetch')
      },
      [proxied(LEGACY_URL)]: () => {
        throw new TypeError('Failed to fetch')
      }
    })

    const { registryManager } = await loadRegistryManager()
    const result = await registryManager.lookupDid(DID)

    expect(result.matchingIssuers).toEqual([])
    expect(result.uncheckedRegistries).toEqual([LEGACY_REGISTRY])
  })

  it('uses fallback KnownDidRegistries when the direct fetch fails', async () => {
    const fetchMock = stubFetch({
      [DIRECT_REGISTRIES_URL]: () => {
        throw new TypeError('Failed to fetch')
      },
      [FALLBACK_URL]: () => jsonResponse(LEGACY_BODY)
    })

    const { registryManager } = await loadRegistryManager()
    const result = await registryManager.lookupDid(DID)

    expect(fetchMock).toHaveBeenCalledWith(FALLBACK_URL, expect.anything())
    expect(result.matchingIssuers).toHaveLength(1)
  })

  it('does not cache the fallback: a later lookup retries the fetch', async () => {
    let attempt = 0
    const fetchMock = stubFetch({
      [DIRECT_REGISTRIES_URL]: () => {
        attempt += 1
        if (attempt === 1) {
          throw new TypeError('Failed to fetch')
        }
        return registriesResponse()
      },
      [FALLBACK_URL]: () => jsonResponse({ registry: {} }),
      [LEGACY_URL]: () => jsonResponse(LEGACY_BODY)
    })

    const { registryManager } = await loadRegistryManager()

    await registryManager.lookupDid(DID)
    expect(fetchMock).toHaveBeenCalledWith(FALLBACK_URL, expect.anything())

    const result = await registryManager.lookupDid(DID)

    expect(attempt).toBe(2)
    expect(result.matchingIssuers).toEqual([LEGACY_MATCH])
  })

  it('retries after a non-ok response too', async () => {
    let attempt = 0
    const fetchMock = stubFetch({
      [DIRECT_REGISTRIES_URL]: () => {
        attempt += 1
        if (attempt === 1) {
          return new Response('nope', { status: 502 })
        }
        return registriesResponse()
      },
      [FALLBACK_URL]: () => jsonResponse({ registry: {} }),
      [LEGACY_URL]: () => jsonResponse(LEGACY_BODY)
    })

    const { registryManager } = await loadRegistryManager()

    await registryManager.lookupDid(DID)
    await registryManager.lookupDid(DID)

    expect(attempt).toBe(2)
    expect(fetchMock).toHaveBeenCalledWith(LEGACY_URL, expect.anything())
  })

  it('caches a successful load: a later lookup does not refetch the list', async () => {
    let listFetches = 0
    stubFetch({
      [DIRECT_REGISTRIES_URL]: () => {
        listFetches += 1
        return registriesResponse()
      },
      [LEGACY_URL]: () => jsonResponse(LEGACY_BODY)
    })

    const { registryManager } = await loadRegistryManager()

    await registryManager.lookupDid(DID)
    await registryManager.lookupDid('did:key:z456')

    expect(listFetches).toBe(1)
  })

  it('answers an empty DID without touching the network', async () => {
    const fetchMock = stubFetch({})

    const { registryManager } = await loadRegistryManager()
    const result = await registryManager.lookupDid('')

    expect(fetchMock).not.toHaveBeenCalled()
    expect(result).toEqual({ matchingIssuers: [], uncheckedRegistries: [] })
  })

  describe('oidf registries', () => {
    function stubOidfFetch(overrides: Record<string, Route> = {}) {
      return stubFetch({
        [DIRECT_REGISTRIES_URL]: () =>
          registriesResponse([...REGISTRY_PAYLOAD, OIDF_REGISTRY]),
        [LEGACY_URL]: () => jsonResponse({ registry: {} }),
        [proxied(TRUST_ANCHOR_EC)]: () =>
          jwtResponse({ metadata: REGISTRY_METADATA }),
        [proxied(`${FEDERATION_FETCH}?sub=${DID}`)]: () =>
          jwtResponse({ metadata: ISSUER_METADATA }),
        ...overrides
      })
    }

    it('looks oidf registries up through the CORS proxy, both hops', async () => {
      const fetchMock = stubOidfFetch()

      const { registryManager } = await loadRegistryManager()
      const result = await registryManager.lookupDid(DID)

      expect(fetchMock).toHaveBeenCalledWith(
        proxied(TRUST_ANCHOR_EC),
        expect.anything()
      )
      expect(fetchMock).toHaveBeenCalledWith(
        proxied(`${FEDERATION_FETCH}?sub=${DID}`),
        expect.anything()
      )
      expect(result.matchingIssuers).toEqual([
        { issuer: ISSUER_METADATA, registry: REGISTRY_METADATA }
      ])
      expect(result.uncheckedRegistries).toEqual([])
    })

    it('checks the oidf and legacy registries in the same lookup', async () => {
      const fetchMock = stubOidfFetch({
        [LEGACY_URL]: () => jsonResponse(LEGACY_BODY)
      })

      const { registryManager } = await loadRegistryManager()
      const result = await registryManager.lookupDid(DID)

      expect(fetchMock).toHaveBeenCalledWith(LEGACY_URL, expect.anything())
      // Results come back in registry-list order: the legacy entry, then oidf.
      expect(result.matchingIssuers).toEqual([
        LEGACY_MATCH,
        { issuer: ISSUER_METADATA, registry: REGISTRY_METADATA }
      ])
    })

    it('reads a 404 from the federation fetch as not-registered, not unchecked', async () => {
      stubOidfFetch({
        [proxied(`${FEDERATION_FETCH}?sub=${DID}`)]: () =>
          new Response('', { status: 404 })
      })

      const { registryManager } = await loadRegistryManager()
      const result = await registryManager.lookupDid(DID)

      expect(result.matchingIssuers).toEqual([])
      expect(result.uncheckedRegistries).toEqual([])
    })

    it('reports an unreachable trust anchor as unchecked, keeping the other half', async () => {
      stubOidfFetch({
        [proxied(TRUST_ANCHOR_EC)]: () => {
          throw new TypeError('Failed to fetch')
        },
        [LEGACY_URL]: () => jsonResponse(LEGACY_BODY)
      })

      const { registryManager } = await loadRegistryManager()
      const result = await registryManager.lookupDid(DID)

      expect(result.matchingIssuers).toEqual([LEGACY_MATCH])
      expect(result.uncheckedRegistries).toEqual([OIDF_REGISTRY])
    })

    it('reports an entity configuration with no metadata as unchecked', async () => {
      stubOidfFetch({
        [proxied(TRUST_ANCHOR_EC)]: () => jwtResponse({})
      })

      const { registryManager } = await loadRegistryManager()
      const result = await registryManager.lookupDid(DID)

      expect(result.matchingIssuers).toEqual([])
      expect(result.uncheckedRegistries).toEqual([OIDF_REGISTRY])
    })
  })

  describe('caching', () => {
    function countingRoutes(extra: Record<string, Route> = {}) {
      const counts: Record<string, number> = {}
      const counted =
        (url: string, route: Route): Route =>
        () => {
          counts[url] = (counts[url] ?? 0) + 1
          return route()
        }
      stubFetch({
        [DIRECT_REGISTRIES_URL]: counted(DIRECT_REGISTRIES_URL, () =>
          registriesResponse([...REGISTRY_PAYLOAD, OIDF_REGISTRY])
        ),
        [LEGACY_URL]: counted(LEGACY_URL, () => jsonResponse(LEGACY_BODY)),
        [proxied(TRUST_ANCHOR_EC)]: counted(proxied(TRUST_ANCHOR_EC), () =>
          jwtResponse({ metadata: REGISTRY_METADATA })
        ),
        [proxied(`${FEDERATION_FETCH}?sub=${DID}`)]: counted(
          proxied(`${FEDERATION_FETCH}?sub=${DID}`),
          () => jwtResponse({ metadata: ISSUER_METADATA })
        ),
        [proxied(`${FEDERATION_FETCH}?sub=did:key:z456`)]: counted(
          proxied(`${FEDERATION_FETCH}?sub=did:key:z456`),
          () => new Response('', { status: 404 })
        ),
        ...extra
      })
      return counts
    }

    it('memoizes a lookup by DID: the second makes no request at all', async () => {
      const counts = countingRoutes()
      const { registryManager } = await loadRegistryManager()

      const first = await registryManager.lookupDid(DID)
      const second = await registryManager.lookupDid(DID)

      expect(second).toEqual(first)
      expect(counts).toEqual({
        [DIRECT_REGISTRIES_URL]: 1,
        [LEGACY_URL]: 1,
        [proxied(TRUST_ANCHOR_EC)]: 1,
        [proxied(`${FEDERATION_FETCH}?sub=${DID}`)]: 1
      })
    })

    it('downloads each DID-independent body once across distinct DIDs', async () => {
      const counts = countingRoutes()
      const { registryManager } = await loadRegistryManager()

      const first = await registryManager.lookupDid(DID)
      const second = await registryManager.lookupDid('did:key:z456')

      expect(first.matchingIssuers).toHaveLength(2)
      expect(second.matchingIssuers).toEqual([])
      expect(second.uncheckedRegistries).toEqual([])
      // The legacy file and the entity configuration are shared; only the
      // federation fetch, which carries the DID, runs per lookup.
      expect(counts[LEGACY_URL]).toBe(1)
      expect(counts[proxied(TRUST_ANCHOR_EC)]).toBe(1)
      expect(counts[proxied(`${FEDERATION_FETCH}?sub=${DID}`)]).toBe(1)
      expect(counts[proxied(`${FEDERATION_FETCH}?sub=did:key:z456`)]).toBe(1)
    })

    it('shares one run between concurrent lookups of one DID', async () => {
      const counts = countingRoutes()
      const { registryManager } = await loadRegistryManager()

      const results = await Promise.all(
        Array.from({ length: 5 }, () => registryManager.lookupDid(DID))
      )

      expect(results.every(result => result.matchingIssuers.length === 2)).toBe(
        true
      )
      expect(counts[LEGACY_URL]).toBe(1)
      expect(counts[proxied(TRUST_ANCHOR_EC)]).toBe(1)
      expect(counts[proxied(`${FEDERATION_FETCH}?sub=${DID}`)]).toBe(1)
    })

    it('does not memoize a lookup that left a registry unchecked', async () => {
      let anchorAttempt = 0
      const counts = countingRoutes({
        [proxied(TRUST_ANCHOR_EC)]: () => {
          anchorAttempt += 1
          if (anchorAttempt === 1) {
            throw new TypeError('Failed to fetch')
          }
          return jwtResponse({ metadata: REGISTRY_METADATA })
        }
      })
      const { registryManager } = await loadRegistryManager()

      const first = await registryManager.lookupDid(DID)
      expect(first.uncheckedRegistries).toEqual([OIDF_REGISTRY])

      const second = await registryManager.lookupDid(DID)
      expect(second.uncheckedRegistries).toEqual([])
      expect(second.matchingIssuers).toHaveLength(2)
      // The retry re-fetched only the hop that failed; the legacy body was
      // served from the cache.
      expect(anchorAttempt).toBe(2)
      expect(counts[LEGACY_URL]).toBe(1)
    })

    it('does not cache a non-ok registry body', async () => {
      let legacyAttempt = 0
      countingRoutes({
        [LEGACY_URL]: () => {
          legacyAttempt += 1
          return legacyAttempt === 1
            ? new Response('nope', { status: 502 })
            : jsonResponse(LEGACY_BODY)
        }
      })
      const { registryManager } = await loadRegistryManager()

      const first = await registryManager.lookupDid(DID)
      expect(first.uncheckedRegistries).toEqual([LEGACY_REGISTRY])

      const second = await registryManager.lookupDid(DID)
      expect(second.uncheckedRegistries).toEqual([])
      expect(legacyAttempt).toBe(2)
    })

    it('shares one body fetch between concurrent misses of distinct DIDs', async () => {
      const counts = countingRoutes()
      const { registryManager } = await loadRegistryManager()

      const [first, second] = await Promise.all([
        registryManager.lookupDid(DID),
        registryManager.lookupDid('did:key:z456')
      ])

      expect(first.matchingIssuers).toHaveLength(2)
      expect(second.matchingIssuers).toEqual([])
      expect(counts[LEGACY_URL]).toBe(1)
      expect(counts[proxied(TRUST_ANCHOR_EC)]).toBe(1)
    })

    it('does not cache an ok body the client cannot parse', async () => {
      let legacyAttempt = 0
      countingRoutes({
        [LEGACY_URL]: () => {
          legacyAttempt += 1
          return legacyAttempt === 1
            ? new Response('<html>captive portal</html>', { status: 200 })
            : jsonResponse(LEGACY_BODY)
        }
      })
      const { registryManager } = await loadRegistryManager()

      const first = await registryManager.lookupDid(DID)
      expect(first.uncheckedRegistries).toEqual([LEGACY_REGISTRY])

      const second = await registryManager.lookupDid(DID)
      expect(second.uncheckedRegistries).toEqual([])
      expect(legacyAttempt).toBe(2)
    })

    it('lets a lookup that joined a failed body read fetch for itself', async () => {
      let legacyAttempt = 0
      let failFirst: (err: Error) => void = () => undefined
      countingRoutes({
        [LEGACY_URL]: () => {
          legacyAttempt += 1
          if (legacyAttempt === 1) {
            return new Promise<Response>((_resolve, reject) => {
              failFirst = reject
            })
          }
          return jsonResponse(LEGACY_BODY)
        }
      })
      const { registryManager } = await loadRegistryManager()

      const first = registryManager.lookupDid(DID)
      // The second lookup joins the first's in-flight legacy read...
      await new Promise(resolve => setTimeout(resolve, 0))
      const second = registryManager.lookupDid('did:key:z456')
      await new Promise(resolve => setTimeout(resolve, 0))
      // ...which then fails (its hop's deadline fired).
      failFirst(new DOMException('aborted', 'AbortError'))

      expect((await first).uncheckedRegistries).toEqual([LEGACY_REGISTRY])
      const joined = await second
      expect(joined.uncheckedRegistries).toEqual([])
      expect(legacyAttempt).toBe(2)
    })

    it('expires a memoized lookup and a cached body after the TTL', async () => {
      vi.useFakeTimers()
      try {
        const counts = countingRoutes()
        const { registryManager, LOOKUP_CACHE_TTL_MS } =
          await loadRegistryManager()

        await registryManager.lookupDid(DID)
        vi.setSystemTime(Date.now() + LOOKUP_CACHE_TTL_MS + 1)
        await registryManager.lookupDid(DID)

        expect(counts[LEGACY_URL]).toBe(2)
        expect(counts[proxied(TRUST_ANCHOR_EC)]).toBe(2)
      } finally {
        vi.useRealTimers()
      }
    })

    it('clearRegistryLookupCaches drops both layers but keeps the list', async () => {
      const counts = countingRoutes()
      const { registryManager, clearRegistryLookupCaches } =
        await loadRegistryManager()

      await registryManager.lookupDid(DID)
      clearRegistryLookupCaches()
      await registryManager.lookupDid(DID)

      expect(counts[DIRECT_REGISTRIES_URL]).toBe(1)
      expect(counts[LEGACY_URL]).toBe(2)
    })

    it('does not memoize a lookup that ran on the fallback list', async () => {
      let listAttempt = 0
      const counts = countingRoutes({
        [DIRECT_REGISTRIES_URL]: () => {
          listAttempt += 1
          if (listAttempt === 1) {
            throw new TypeError('Failed to fetch')
          }
          return registriesResponse()
        },
        [FALLBACK_URL]: () => jsonResponse({ registry: {} })
      })
      const { registryManager } = await loadRegistryManager()

      const first = await registryManager.lookupDid(DID)
      expect(first.matchingIssuers).toEqual([])

      const second = await registryManager.lookupDid(DID)
      expect(second.matchingIssuers).toEqual([LEGACY_MATCH])
      expect(listAttempt).toBe(2)
      expect(counts[LEGACY_URL]).toBe(1)
    })
  })

  it('__resetRegistryCacheForTests clears every cache', async () => {
    let listFetches = 0
    let legacyFetches = 0
    stubFetch({
      [DIRECT_REGISTRIES_URL]: () => {
        listFetches += 1
        return registriesResponse()
      },
      [LEGACY_URL]: () => {
        legacyFetches += 1
        return jsonResponse(LEGACY_BODY)
      }
    })

    const { registryManager, __resetRegistryCacheForTests } =
      await loadRegistryManager()

    await registryManager.lookupDid(DID)
    __resetRegistryCacheForTests()
    await registryManager.lookupDid(DID)

    // The list, the body cache, and the DID memo are all cleared.
    expect(listFetches).toBe(2)
    expect(legacyFetches).toBe(2)
  })
})
