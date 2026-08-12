import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  createOnboardingExchange,
  OnboardingExchangeGoneError,
  ONBOARDING_INVITE_TTL_MS,
  ONBOARDING_POLL_INTERVAL_MS,
  pollOnboardingExchange
} from '@/lib/onboardingInvite'

const SERVER_URL = 'https://was.example'
const EXCHANGE_URL = 'https://was.example/workflows/ephemeral/exchanges/abc123'
const REQUEST = { query: [{ type: 'WalletOnboardingQuery' }] }

/**
 * A minimal `Response` stand-in: only the members the module reads.
 */
function fakeResponse({
  status = 200,
  headers = {},
  body
}: {
  status?: number
  headers?: Record<string, string>
  body?: unknown
} = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (name: string) => headers[name.toLowerCase()] ?? null
    },
    json: async () => {
      if (body === undefined) {
        throw new Error('No JSON body.')
      }
      return body
    }
  } as unknown as Response
}

describe('createOnboardingExchange', () => {
  it('posts the request and reads the Location header', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ status: 201, headers: { location: EXCHANGE_URL } })
    )

    const created = await createOnboardingExchange({
      serverUrl: SERVER_URL,
      request: REQUEST,
      fetch: fetchMock
    })

    expect(fetchMock).toHaveBeenCalledWith(
      'https://was.example/workflows/ephemeral/exchanges',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ request: REQUEST })
      }
    )
    expect(created.exchangeUrl).toBe(EXCHANGE_URL)
    expect(created.interactionUrl).toBe(`${EXCHANGE_URL}/protocols?iuv=1`)
  })

  it('falls back to the body location when no header is set', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ status: 201, body: { location: EXCHANGE_URL } })
    )

    const created = await createOnboardingExchange({
      serverUrl: SERVER_URL,
      request: REQUEST,
      fetch: fetchMock
    })

    expect(created.exchangeUrl).toBe(EXCHANGE_URL)
  })

  it('tolerates a trailing slash on the server URL', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ status: 201, headers: { location: EXCHANGE_URL } })
    )

    await createOnboardingExchange({
      serverUrl: 'https://was.example/',
      request: REQUEST,
      fetch: fetchMock
    })

    expect(fetchMock).toHaveBeenCalledWith(
      'https://was.example/workflows/ephemeral/exchanges',
      expect.anything()
    )
  })

  it('throws when the server refuses the create', async () => {
    const fetchMock = vi.fn(async () => fakeResponse({ status: 429 }))

    await expect(
      createOnboardingExchange({
        serverUrl: SERVER_URL,
        request: REQUEST,
        fetch: fetchMock
      })
    ).rejects.toThrow(/429/)
  })

  it('throws when the created exchange has no location', async () => {
    const fetchMock = vi.fn(async () => fakeResponse({ status: 201, body: {} }))

    await expect(
      createOnboardingExchange({
        serverUrl: SERVER_URL,
        request: REQUEST,
        fetch: fetchMock
      })
    ).rejects.toThrow(/no location/)
  })
})

describe('pollOnboardingExchange', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('resolves with the response once the exchange completes', async () => {
    const fetchMock = vi
      .fn<() => Promise<Response>>()
      .mockResolvedValueOnce(
        fakeResponse({ body: { id: 'abc123', sequence: 0, state: 'pending' } })
      )
      .mockResolvedValueOnce(
        fakeResponse({
          body: {
            id: 'abc123',
            sequence: 1,
            state: 'complete',
            response: { verifiablePresentation: { hello: 'world' } }
          }
        })
      )

    const polling = pollOnboardingExchange({
      exchangeUrl: EXCHANGE_URL,
      fetch: fetchMock
    })

    await vi.advanceTimersByTimeAsync(ONBOARDING_POLL_INTERVAL_MS * 2)

    await expect(polling).resolves.toEqual({
      verifiablePresentation: { hello: 'world' }
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('rejects with the gone error on a 404', async () => {
    const fetchMock = vi.fn(async () => fakeResponse({ status: 404 }))

    const polling = pollOnboardingExchange({
      exchangeUrl: EXCHANGE_URL,
      fetch: fetchMock
    })

    await expect(polling).rejects.toBeInstanceOf(OnboardingExchangeGoneError)
  })

  it('retries a transient network failure', async () => {
    const fetchMock = vi
      .fn<() => Promise<Response>>()
      .mockRejectedValueOnce(new Error('network down'))
      .mockResolvedValueOnce(
        fakeResponse({ body: { state: 'complete', response: { ok: true } } })
      )

    const polling = pollOnboardingExchange({
      exchangeUrl: EXCHANGE_URL,
      fetch: fetchMock
    })

    await vi.advanceTimersByTimeAsync(ONBOARDING_POLL_INTERVAL_MS * 2)

    await expect(polling).resolves.toEqual({ ok: true })
  })

  it('stops polling and rejects when the signal aborts', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ body: { state: 'pending' } })
    )
    const controller = new AbortController()

    const polling = pollOnboardingExchange({
      exchangeUrl: EXCHANGE_URL,
      signal: controller.signal,
      fetch: fetchMock
    })
    const settled = polling.catch((err: unknown) => err)

    await vi.advanceTimersByTimeAsync(ONBOARDING_POLL_INTERVAL_MS)
    const callsBeforeAbort = fetchMock.mock.calls.length
    controller.abort(new Error('cancelled'))

    await expect(settled).resolves.toEqual(new Error('cancelled'))

    await vi.advanceTimersByTimeAsync(ONBOARDING_POLL_INTERVAL_MS * 3)
    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeAbort)
  })

  it('passes the signal to fetch so an in-flight request is cancelled', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ body: { state: 'complete', response: null } })
    )
    const controller = new AbortController()

    await pollOnboardingExchange({
      exchangeUrl: EXCHANGE_URL,
      signal: controller.signal,
      fetch: fetchMock
    })

    expect(fetchMock).toHaveBeenCalledWith(EXCHANGE_URL, {
      signal: controller.signal
    })
  })
})

describe('invite constants', () => {
  it('expires the invite inside the server exchange TTL', () => {
    expect(ONBOARDING_INVITE_TTL_MS).toBeLessThan(10 * 60 * 1000)
    expect(ONBOARDING_POLL_INTERVAL_MS).toBeGreaterThan(0)
  })
})
