/**
 * Unit tests for the one service discovery: the memo that makes every
 * `WasClient` this app builds share one `HEAD` of the Spaces Repository URL,
 * the retry a failed discovery leaves open, the refusal when no WAS server is
 * configured, and the refusal when the discovered Spaces URL is not the
 * configured one. The `app.config` derivation of the server base URL from
 * that Spaces URL is covered beside them, since the discovery starts from one
 * and every Space path hangs off the other.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

import { TEST_SERVICE_DESCRIPTION } from '../../tests/shared/wasServiceFixture'

// This file exercises the real module, so it opts out of the global mock
// registered in `tests/shared/setup.wasService.ts`.
vi.unmock('@/lib/wasService')

const discoverService = vi.fn()
let spacesUrl: string | undefined = 'http://localhost/spaces/'

vi.mock('@interop/was-client', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/was-client')>()),
  discoverService: (options: { url: string }) => discoverService(options)
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SPACES_URL() {
    return spacesUrl
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
    discoverService.mockReset()
    spacesUrl = 'http://localhost/spaces/'
  })

  it('discovers once and memoizes the description', async () => {
    discoverService.mockResolvedValue({
      description: TEST_SERVICE_DESCRIPTION,
      version: '0.5',
      features: [],
      spacesUrl: 'http://localhost/spaces/'
    })
    const { wasServiceDescription } = await loadModule()

    const first = await wasServiceDescription()
    const second = await wasServiceDescription()

    expect(first).toBe(TEST_SERVICE_DESCRIPTION)
    expect(second).toBe(TEST_SERVICE_DESCRIPTION)
    expect(discoverService).toHaveBeenCalledTimes(1)
    expect(discoverService).toHaveBeenCalledWith({
      url: 'http://localhost/spaces/'
    })
  })

  it('does not memoize a failure, so the next call retries', async () => {
    discoverService
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
    expect(discoverService).toHaveBeenCalledTimes(2)
  })

  it('rejects when no WAS server is configured', async () => {
    spacesUrl = undefined
    const { wasServiceDescription } = await loadModule()

    await expect(wasServiceDescription()).rejects.toThrow(
      'No WAS server is configured.'
    )
    expect(discoverService).not.toHaveBeenCalled()
  })

  it('refuses a description whose Spaces URL is not the configured one', async () => {
    discoverService.mockResolvedValue({
      description: {
        url: 'http://localhost/service',
        specs: {
          'https://w3id.org/pws': [
            { version: '0.5', spaces: 'http://elsewhere/spaces/' }
          ]
        }
      },
      version: '0.5',
      features: [],
      spacesUrl: 'http://elsewhere/spaces/'
    })
    const { wasServiceDescription } = await loadModule()

    await expect(wasServiceDescription()).rejects.toMatchObject({
      name: 'IncompatibleServerError'
    })
  })
})

describe('the WAS server base URL derived in app.config', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
    vi.resetModules()
  })

  /**
   * Loads `app.config` with one `VITE_WAS_SERVER_URL` value in place.
   *
   * @param value {string}   the configured Spaces Repository URL
   * @returns {Promise<{ spaces?: string, base?: string }>}
   */
  async function derive(value: string) {
    vi.stubEnv('VITE_WAS_SERVER_URL', value)
    vi.resetModules()
    const config =
      await vi.importActual<typeof import('@/app.config')>('@/app.config')
    return { spaces: config.WAS_SPACES_URL, base: config.WAS_SERVER_URL }
  }

  it('takes the parent of a root-mounted Spaces URL', async () => {
    expect(await derive('https://host/spaces/')).toEqual({
      spaces: 'https://host/spaces/',
      base: 'https://host'
    })
  })

  it('takes the parent of a sub-path-mounted Spaces URL', async () => {
    expect(await derive('https://host/was/spaces/')).toEqual({
      spaces: 'https://host/was/spaces/',
      base: 'https://host/was'
    })
  })

  it('canonicalizes a value written without the trailing slash', async () => {
    expect(await derive('https://host/was/spaces')).toEqual({
      spaces: 'https://host/was/spaces/',
      base: 'https://host/was'
    })
  })
})
