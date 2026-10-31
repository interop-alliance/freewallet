/**
 * Unit tests for the one service discovery: the memo that makes every
 * `PwsClient` this app builds share one read of the service description at
 * `{base}service`, the retry a failed discovery leaves open, the refusal
 * when no WAS server is configured, and the refusal of a description that
 * describes a server other than the configured base. The `app.config` canonicalization of the
 * configured base server URL is covered beside them, since the discovery
 * starts from it and every Space URL hangs off it.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

import { TEST_SERVICE_DESCRIPTION } from '../../tests/shared/wasServiceFixture'

// This file exercises the real module, so it opts out of the global mock
// registered in `tests/shared/setup.wasService.ts`.
vi.unmock('@/lib/wasService')

const readServiceDescription = vi.fn()
let baseServerUrl: string | undefined = 'http://localhost/'

vi.mock('@interop/pws-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/pws-client')>()),
  readServiceDescription: (options: { serviceUrl: string }) =>
    readServiceDescription(options)
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_BASE_SERVER_URL() {
    return baseServerUrl
  }
}))

/**
 * A fresh module instance, so each test starts with an empty memo.
 *
 * @returns {Promise<typeof import('./wasService')>}
 */
async function loadModule() {
  vi.resetModules()
  return await import('./wasService')
}

describe('wasServiceDescription', () => {
  beforeEach(() => {
    readServiceDescription.mockReset()
    baseServerUrl = 'http://localhost/'
  })

  it('reads {base}service once and memoizes the description', async () => {
    readServiceDescription.mockResolvedValue({
      description: TEST_SERVICE_DESCRIPTION,
      version: '0.5',
      features: []
    })
    const { wasServiceDescription } = await loadModule()

    const first = await wasServiceDescription()
    const second = await wasServiceDescription()

    expect(first).toBe(TEST_SERVICE_DESCRIPTION)
    expect(second).toBe(TEST_SERVICE_DESCRIPTION)
    expect(readServiceDescription).toHaveBeenCalledTimes(1)
    expect(readServiceDescription).toHaveBeenCalledWith({
      serviceUrl: 'http://localhost/service'
    })
  })

  it('does not memoize a failure, so the next call retries', async () => {
    readServiceDescription
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({
        description: TEST_SERVICE_DESCRIPTION,
        version: '0.5',
        features: []
      })
    const { wasServiceDescription } = await loadModule()

    await expect(wasServiceDescription()).rejects.toThrow('offline')
    await expect(wasServiceDescription()).resolves.toBe(
      TEST_SERVICE_DESCRIPTION
    )
    expect(readServiceDescription).toHaveBeenCalledTimes(2)
  })

  it('refuses a description whose url is not {base}service', async () => {
    readServiceDescription.mockResolvedValue({
      description: {
        ...TEST_SERVICE_DESCRIPTION,
        url: 'http://elsewhere/service'
      },
      version: '0.5',
      features: [],
      spacesUrl: 'http://localhost/spaces/'
    })
    const { wasServiceDescription } = await loadModule()

    await expect(wasServiceDescription()).rejects.toMatchObject({
      name: 'IncompatibleServerError'
    })
  })

  it('refuses a description whose Spaces Repository URL is not {base}spaces/', async () => {
    readServiceDescription.mockResolvedValue({
      description: TEST_SERVICE_DESCRIPTION,
      version: '0.5',
      features: [],
      spacesUrl: 'http://elsewhere/spaces/'
    })
    const { wasServiceDescription } = await loadModule()

    await expect(wasServiceDescription()).rejects.toMatchObject({
      name: 'IncompatibleServerError'
    })
    // Not memoized: the next call reads again.
    await expect(wasServiceDescription()).rejects.toMatchObject({
      name: 'IncompatibleServerError'
    })
    expect(readServiceDescription).toHaveBeenCalledTimes(2)
  })

  it('rejects when no WAS server is configured', async () => {
    baseServerUrl = undefined
    const { wasServiceDescription } = await loadModule()

    await expect(wasServiceDescription()).rejects.toThrow(
      'No WAS server is configured.'
    )
    expect(readServiceDescription).not.toHaveBeenCalled()
  })
})

describe('the WAS base server URL canonicalized in app.config', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
    vi.resetModules()
  })

  /**
   * Loads `app.config` with one `VITE_WAS_SERVER_URL` value in place.
   *
   * @param value {string}   the configured base server URL
   * @returns {Promise<string | undefined>}   the canonical base server URL
   */
  async function canonical(value: string) {
    vi.stubEnv('VITE_WAS_SERVER_URL', value)
    vi.resetModules()
    const config =
      await vi.importActual<typeof import('@/app.config')>('@/app.config')
    return config.WAS_BASE_SERVER_URL
  }

  it('supplies the trailing slash of a root-mounted base', async () => {
    expect(await canonical('https://host')).toBe('https://host/')
  })

  it('keeps a sub-path mount, with one trailing slash', async () => {
    expect(await canonical('https://host/was')).toBe('https://host/was/')
    expect(await canonical('https://host/was/')).toBe('https://host/was/')
  })

  it('refuses a scheme-less value by name at module evaluation', async () => {
    await expect(canonical('localhost:3002')).rejects.toThrow(
      'VITE_WAS_SERVER_URL "localhost:3002" is not a base server URL.'
    )
  })

  it('refuses a value carrying a query by name at module evaluation', async () => {
    await expect(canonical('https://host/?mount=was')).rejects.toThrow(
      'VITE_WAS_SERVER_URL "https://host/?mount=was" is not a base server URL.'
    )
  })
})
