import { afterEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'

const { httpGetMock } = vi.hoisted(() => ({
  httpGetMock: vi.fn(async () => ({
    data: { hello: 'world' },
    text: async () => ''
  }))
}))

vi.mock('@interop/http-client', () => ({
  httpClient: { get: httpGetMock }
}))

const TARGET_URL = 'https://issuer.example/credential.json'

async function loadCorsProxy(corsProxyUrl: string | undefined) {
  vi.resetModules()
  vi.doMock('@/app.config', () => ({ CORS_PROXY_URL: corsProxyUrl }))
  return import('@/lib/corsProxy')
}

describe('fetchFromURL', () => {
  afterEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
  })

  it('appends ?url= to the WAS proxy base without an extra slash', async () => {
    const { fetchFromURL } = await loadCorsProxy('https://was.example/api/cors')

    await fetchFromURL(TARGET_URL)

    expect(httpGetMock).toHaveBeenCalledWith(
      `https://was.example/api/cors?url=${encodeURIComponent(TARGET_URL)}`,
      expect.anything()
    )
  })

  it('tolerates a trailing slash on the configured proxy base', async () => {
    const { fetchFromURL } = await loadCorsProxy(
      'https://was.example/api/cors/'
    )

    await fetchFromURL(TARGET_URL)

    expect(httpGetMock).toHaveBeenCalledWith(
      `https://was.example/api/cors?url=${encodeURIComponent(TARGET_URL)}`,
      expect.anything()
    )
  })

  it('appends ?url= to an external corsproxy base', async () => {
    const { fetchFromURL } = await loadCorsProxy('https://corsproxy.io')

    await fetchFromURL(TARGET_URL)

    expect(httpGetMock).toHaveBeenCalledWith(
      `https://corsproxy.io?url=${encodeURIComponent(TARGET_URL)}`,
      expect.anything()
    )
  })

  it('fetches the URL directly when no proxy is configured', async () => {
    const { fetchFromURL } = await loadCorsProxy(undefined)

    await fetchFromURL(TARGET_URL)

    expect(httpGetMock).toHaveBeenCalledWith(TARGET_URL, expect.anything())
  })
})

describe('corsProxyFetch', () => {
  afterEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
  })

  it('fetches through the same proxy base fetchFromURL uses', async () => {
    const fetchMock = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', fetchMock)
    const { corsProxyFetch } = await loadCorsProxy(
      'https://was.example/api/cors'
    )

    await corsProxyFetch({ url: TARGET_URL })

    expect(fetchMock).toHaveBeenCalledWith(
      `https://was.example/api/cors?url=${encodeURIComponent(TARGET_URL)}`,
      { signal: undefined }
    )
  })

  it('fetches directly when no proxy is configured', async () => {
    const fetchMock = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', fetchMock)
    const { corsProxyFetch } = await loadCorsProxy(undefined)

    await corsProxyFetch({ url: TARGET_URL })

    expect(fetchMock).toHaveBeenCalledWith(TARGET_URL, { signal: undefined })
  })

  it('passes an abort signal through to fetch', async () => {
    const fetchMock = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', fetchMock)
    const { corsProxyFetch } = await loadCorsProxy(undefined)
    const controller = new AbortController()

    await corsProxyFetch({ url: TARGET_URL, signal: controller.signal })

    expect(fetchMock).toHaveBeenCalledWith(TARGET_URL, {
      signal: controller.signal
    })
  })
})

describe('proxyFallbackHttpGetService', () => {
  const PROXY_BASE = 'https://was.example/api/cors'
  const DID_DOC_URL = 'https://issuer.example/.well-known/did.json'
  const CONTEXT_URL = 'https://issuer.example/contexts/v1.json'
  const proxied = (url: string) =>
    `${PROXY_BASE}?url=${encodeURIComponent(url)}`
  const DOC = { id: 'did:web:issuer.example' }

  function jsonResponse(payload: unknown, status = 200) {
    return new Response(JSON.stringify(payload), {
      status,
      headers: { 'content-type': 'application/json' }
    })
  }

  /**
   * Stubs fetch: a direct request to the issuer host rejects the way a
   * browser's CORS block does, unless `direct` answers it; a proxied request
   * answers with the document.
   */
  function stubFetch({
    direct
  }: {
    direct?: () => Response | Promise<Response>
  } = {}) {
    const fetchMock = vi.fn(async (url: URL | RequestInfo) => {
      if (String(url).startsWith(PROXY_BASE)) {
        return jsonResponse(DOC)
      }
      if (direct) {
        return direct()
      }
      throw new TypeError('Failed to fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    return fetchMock
  }

  afterEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
  })

  it('returns a direct success without touching the proxy', async () => {
    const fetchMock = stubFetch({ direct: () => jsonResponse(DOC) })
    const { proxyFallbackHttpGetService } = await loadCorsProxy(PROXY_BASE)

    const result = await proxyFallbackHttpGetService().get(DID_DOC_URL)

    expect(result.status).toBe(200)
    expect(result.body).toEqual(DOC)
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      DID_DOC_URL
    ])
  })

  it('retries a rejected direct fetch once through the proxy', async () => {
    const fetchMock = stubFetch()
    const { proxyFallbackHttpGetService } = await loadCorsProxy(PROXY_BASE)

    const result = await proxyFallbackHttpGetService().get(DID_DOC_URL)

    expect(result.body).toEqual(DOC)
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      DID_DOC_URL,
      proxied(DID_DOC_URL)
    ])
  })

  it('does not retry an HTTP error status from the host', async () => {
    const fetchMock = stubFetch({
      direct: () => jsonResponse({ error: 'not found' }, 404)
    })
    const { proxyFallbackHttpGetService } = await loadCorsProxy(PROXY_BASE)

    const result = await proxyFallbackHttpGetService().get(DID_DOC_URL)

    expect(result.status).toBe(404)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('does not retry an abort', async () => {
    const fetchMock = stubFetch({
      direct: () => {
        throw new DOMException('Aborted', 'AbortError')
      }
    })
    const { proxyFallbackHttpGetService } = await loadCorsProxy(PROXY_BASE)

    await expect(
      proxyFallbackHttpGetService().get(DID_DOC_URL)
    ).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('sends later requests to a blocked origin straight to the proxy, warning once', async () => {
    const fetchMock = stubFetch()
    const { proxyFallbackHttpGetService, clearDirectFetchFailures } =
      await loadCorsProxy(PROXY_BASE)
    const service = proxyFallbackHttpGetService()
    const capture = captureSink()
    const removeSink = addSink(capture.sink)

    try {
      await service.get(DID_DOC_URL)
      await service.get(CONTEXT_URL)
    } finally {
      removeSink()
    }

    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      DID_DOC_URL,
      proxied(DID_DOC_URL),
      proxied(CONTEXT_URL)
    ])
    const warnings = capture.events.filter(
      event => event.ns === 'fw:cors-proxy' && event.level === 'warn'
    )
    expect(warnings).toHaveLength(1)

    // Cleared, the origin is tried direct again.
    clearDirectFetchFailures()
    fetchMock.mockClear()
    await service.get(CONTEXT_URL)
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      CONTEXT_URL,
      proxied(CONTEXT_URL)
    ])
  })

  it('tries a blocked origin direct again once the block expires', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    try {
      const fetchMock = stubFetch()
      const { proxyFallbackHttpGetService } = await loadCorsProxy(PROXY_BASE)
      const service = proxyFallbackHttpGetService()

      await service.get(DID_DOC_URL)
      vi.advanceTimersByTime(5 * 60 * 1000)
      fetchMock.mockClear()
      await service.get(CONTEXT_URL)

      expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
        CONTEXT_URL,
        proxied(CONTEXT_URL)
      ])
    } finally {
      vi.useRealTimers()
    }
  })

  it('falls back to direct when the proxy fails for a blocked origin', async () => {
    let directWorks = false
    const fetchMock = vi.fn(async (url: URL | RequestInfo) => {
      if (String(url).startsWith(PROXY_BASE)) {
        if (directWorks) {
          throw new TypeError('Failed to fetch')
        }
        return jsonResponse(DOC)
      }
      if (directWorks) {
        return jsonResponse(DOC)
      }
      throw new TypeError('Failed to fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    const { proxyFallbackHttpGetService } = await loadCorsProxy(PROXY_BASE)
    const service = proxyFallbackHttpGetService()

    await service.get(DID_DOC_URL)
    directWorks = true
    fetchMock.mockClear()
    const result = await service.get(CONTEXT_URL)
    await service.get(CONTEXT_URL)

    expect(result.body).toEqual(DOC)
    // The proxy failed, so the mark is dropped and later requests go direct.
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      proxied(CONTEXT_URL),
      CONTEXT_URL,
      CONTEXT_URL
    ])
  })

  it('does not retry when no proxy is configured', async () => {
    const fetchMock = stubFetch()
    const { proxyFallbackHttpGetService } = await loadCorsProxy(undefined)

    await expect(
      proxyFallbackHttpGetService().get(DID_DOC_URL)
    ).rejects.toThrow(TypeError)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
