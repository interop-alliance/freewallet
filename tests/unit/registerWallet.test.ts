// @vitest-environment node
/**
 * Unit tests for CHAPI wallet registration (`src/lib/registerWallet.ts`):
 * the mediated registration URL passed to the polyfill, the handler install
 * wiring, and the swallow-on-failure contract (registration errors are logged
 * but never thrown out to the caller). The polyfill and handler module
 * boundaries are stubbed with `vi.mock`; `@/app.config` is stubbed so the
 * expected registration URL is deterministic.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('credential-handler-polyfill', () => ({
  loadOnce: vi.fn()
}))
vi.mock('web-credential-handler', () => ({
  installHandler: vi.fn()
}))
// The factory is hoisted above module-scope constants, so the stubbed config
// values are declared inline here and mirrored by the constants below.
vi.mock('@/app.config', () => ({
  DEPLOY_URL: 'https://wallet.example.test/path?with=query&and=chars',
  MEDIATOR_BASE: 'https://authn.io/mediator?origin='
}))

import { loadOnce } from 'credential-handler-polyfill'
import { installHandler } from 'web-credential-handler'
import { registerWallet } from '@/lib/registerWallet'

const DEPLOY_URL = 'https://wallet.example.test/path?with=query&and=chars'
const MEDIATOR_BASE = 'https://authn.io/mediator?origin='

const loadOnceMock = vi.mocked(loadOnce)
const installHandlerMock = vi.mocked(installHandler)

const expectedMediatedUrl = MEDIATOR_BASE + encodeURIComponent(DEPLOY_URL)

beforeEach(() => {
  loadOnceMock.mockReset().mockResolvedValue(undefined)
  installHandlerMock.mockReset().mockResolvedValue(undefined as never)
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('registerWallet', () => {
  it('loads the polyfill with the mediated deploy URL and installs the handler', async () => {
    await registerWallet()

    expect(loadOnceMock).toHaveBeenCalledTimes(1)
    expect(loadOnceMock).toHaveBeenCalledWith(expectedMediatedUrl)
    expect(installHandlerMock).toHaveBeenCalledTimes(1)
  })

  it('url-encodes the deploy URL exactly once into the mediator origin', async () => {
    await registerWallet()

    const passedUrl = loadOnceMock.mock.calls[0][0]
    expect(passedUrl.startsWith(MEDIATOR_BASE)).toBe(true)
    const origin = passedUrl.slice(MEDIATOR_BASE.length)
    // The origin segment is percent-encoded, and decoding it once recovers the
    // raw deploy URL (special characters like `?`, `&`, `=` are escaped).
    expect(origin).not.toBe(DEPLOY_URL)
    expect(decodeURIComponent(origin)).toBe(DEPLOY_URL)
  })

  it('installs the handler only after the polyfill has loaded', async () => {
    const order: string[] = []
    loadOnceMock.mockImplementation(async () => {
      order.push('load')
    })
    installHandlerMock.mockImplementation(async () => {
      order.push('install')
      return undefined as never
    })

    await registerWallet()

    expect(order).toEqual(['load', 'install'])
  })

  it('resolves without throwing when polyfill loading fails', async () => {
    loadOnceMock.mockRejectedValue(new Error('mediator unreachable'))

    await expect(registerWallet()).resolves.toBeUndefined()

    // A failed load short-circuits before the handler install.
    expect(installHandlerMock).not.toHaveBeenCalled()
    expect(console.error).toHaveBeenCalled()
  })

  it('resolves without throwing when handler install fails', async () => {
    installHandlerMock.mockRejectedValue(new Error('install blocked'))

    await expect(registerWallet()).resolves.toBeUndefined()

    expect(loadOnceMock).toHaveBeenCalledTimes(1)
    expect(console.error).toHaveBeenCalled()
  })

  it('re-runs the full registration on every call (idempotent, no memoization)', async () => {
    await registerWallet()
    await registerWallet()

    expect(loadOnceMock).toHaveBeenCalledTimes(2)
    expect(installHandlerMock).toHaveBeenCalledTimes(2)
    for (const call of loadOnceMock.mock.calls) {
      expect(call[0]).toBe(expectedMediatedUrl)
    }
  })
})
