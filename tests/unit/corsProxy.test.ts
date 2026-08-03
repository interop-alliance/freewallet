import { afterEach, describe, expect, it, vi } from 'vitest'

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
      `https://was.example/api/cors?url=${encodeURIComponent(TARGET_URL)}`
    )
  })

  it('fetches directly when no proxy is configured', async () => {
    const fetchMock = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', fetchMock)
    const { corsProxyFetch } = await loadCorsProxy(undefined)

    await corsProxyFetch({ url: TARGET_URL })

    expect(fetchMock).toHaveBeenCalledWith(TARGET_URL)
  })
})
