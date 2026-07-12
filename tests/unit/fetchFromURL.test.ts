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

async function loadFetchFromURL(corsProxyUrl: string | undefined) {
  vi.resetModules()
  vi.doMock('@/app.config', () => ({ CORS_PROXY_URL: corsProxyUrl }))
  return import('@/lib/fetchFromURL')
}

describe('fetchFromURL', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it('appends ?url= to the WAS proxy base without an extra slash', async () => {
    const { fetchFromURL } = await loadFetchFromURL(
      'https://was.example/api/cors'
    )

    await fetchFromURL(TARGET_URL)

    expect(httpGetMock).toHaveBeenCalledWith(
      `https://was.example/api/cors?url=${encodeURIComponent(TARGET_URL)}`,
      expect.anything()
    )
  })

  it('tolerates a trailing slash on the configured proxy base', async () => {
    const { fetchFromURL } = await loadFetchFromURL(
      'https://was.example/api/cors/'
    )

    await fetchFromURL(TARGET_URL)

    expect(httpGetMock).toHaveBeenCalledWith(
      `https://was.example/api/cors?url=${encodeURIComponent(TARGET_URL)}`,
      expect.anything()
    )
  })

  it('appends ?url= to an external corsproxy base', async () => {
    const { fetchFromURL } = await loadFetchFromURL('https://corsproxy.io')

    await fetchFromURL(TARGET_URL)

    expect(httpGetMock).toHaveBeenCalledWith(
      `https://corsproxy.io?url=${encodeURIComponent(TARGET_URL)}`,
      expect.anything()
    )
  })

  it('fetches the URL directly when no proxy is configured', async () => {
    const { fetchFromURL } = await loadFetchFromURL(undefined)

    await fetchFromURL(TARGET_URL)

    expect(httpGetMock).toHaveBeenCalledWith(TARGET_URL, expect.anything())
  })
})
