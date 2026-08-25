// @vitest-environment node
/**
 * Unit tests for CHAPI wallet registration (`src/lib/registerWallet.ts`):
 * the mediated registration URL passed to the polyfill (always built from the
 * page's own origin, since handler registration is same-origin), the handler
 * install wiring, and the swallow-on-failure contract (registration errors
 * are logged but never thrown out to the caller). The polyfill and handler
 * module boundaries are stubbed with `vi.mock`; `window` is stubbed so the
 * expected registration URL is deterministic.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('credential-handler-polyfill', () => ({
  loadOnce: vi.fn()
}))
vi.mock('web-credential-handler', () => ({
  installHandler: vi.fn()
}))

import { loadOnce } from 'credential-handler-polyfill'
import { installHandler } from 'web-credential-handler'
import { registerWallet } from '@/lib/registerWallet'

const PAGE_ORIGIN = 'https://wallet.example.test'
const MEDIATOR_BASE = 'https://authn.io/mediator?origin='

const loadOnceMock = vi.mocked(loadOnce)
const installHandlerMock = vi.mocked(installHandler)

const expectedMediatedUrl = MEDIATOR_BASE + encodeURIComponent(PAGE_ORIGIN)

beforeEach(() => {
  loadOnceMock.mockReset().mockResolvedValue(undefined)
  installHandlerMock.mockReset().mockResolvedValue(undefined as never)
  vi.stubGlobal('window', { location: { origin: PAGE_ORIGIN } })
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('registerWallet', () => {
  it('loads the polyfill with the mediated page origin and installs the handler', async () => {
    await registerWallet()

    expect(loadOnceMock).toHaveBeenCalledTimes(1)
    expect(loadOnceMock).toHaveBeenCalledWith(expectedMediatedUrl)
    expect(installHandlerMock).toHaveBeenCalledTimes(1)
  })

  it('url-encodes the page origin exactly once into the mediator origin', async () => {
    await registerWallet()

    const passedUrl = loadOnceMock.mock.calls[0][0]
    expect(passedUrl.startsWith(MEDIATOR_BASE)).toBe(true)
    const origin = passedUrl.slice(MEDIATOR_BASE.length)
    // Decoding the origin segment once recovers the raw page origin (special
    // characters like `:` and `/` are escaped).
    expect(origin).not.toBe(PAGE_ORIGIN)
    expect(decodeURIComponent(origin)).toBe(PAGE_ORIGIN)
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
