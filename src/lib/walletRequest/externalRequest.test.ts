// @vitest-environment node
/**
 * Unit tests for the non-CHAPI request entry point's pure half
 * (`src/lib/walletRequest/externalRequest.ts`): the deep-link parser, the
 * exchange-opening error mapping, and the pre-consent refusal matrix (DID
 * Auth, `domain`, `AppConnectQuery`, a foreign delivery endpoint, the grant
 * class allowlist).
 */
import { describe, expect, it, vi } from 'vitest'
import { EphemeralExchangeGoneError } from '@interop/wallet-core/request'
import {
  barredGrants,
  EXTERNAL_REQUEST_ORIGIN,
  ExternalRequestRefusedError,
  externalRequestPath,
  interactionUrlFromSearch,
  openExternalRequest,
  precheckExternalRequest
} from './externalRequest'
import type { ResolvedGrant } from './processZcaps'
import type { IVPRDetails } from './types'

const INTERACTION_URL =
  'https://was.example/workflows/ephemeral/exchanges/abc/protocols?iuv=1'
const EXCHANGE_URL = 'https://was.example/workflows/ephemeral/exchanges/abc'

const ZCAP_QUERY = {
  type: 'AuthorizationCapabilityQuery',
  capabilityQuery: [
    {
      referenceId: 'web',
      reason: 'publish a page',
      allowedAction: ['GET', 'PUT'],
      controller: 'did:key:z6MkAgent',
      invocationTarget: {
        type: 'https://w3id.org/byoe#public-collection',
        name: 'web'
      }
    }
  ]
}

function zcapOnlyRequest(extra: Partial<IVPRDetails> = {}): IVPRDetails {
  return { query: [ZCAP_QUERY], ...extra } as unknown as IVPRDetails
}

function refusalOf(run: () => unknown): string | undefined {
  try {
    run()
    return undefined
  } catch (err) {
    return err instanceof ExternalRequestRefusedError ? err.refusal : 'other'
  }
}

describe('externalRequestPath', () => {
  it('builds the deep link the CLI prints, with the URL percent-encoded', () => {
    const path = externalRequestPath({ url: INTERACTION_URL })
    expect(path.startsWith('/external/request?url=')).toBe(true)
    expect(interactionUrlFromSearch(path.slice(path.indexOf('?')))).toBe(
      INTERACTION_URL
    )
  })
})

describe('interactionUrlFromSearch', () => {
  it('accepts an http(s) interaction URL and the interaction: scheme', () => {
    expect(
      interactionUrlFromSearch(`?url=${encodeURIComponent(INTERACTION_URL)}`)
    ).toBe(INTERACTION_URL)
    const schemed = `interaction:${INTERACTION_URL}`
    expect(
      interactionUrlFromSearch(`?url=${encodeURIComponent(schemed)}`)
    ).toBe(schemed)
  })

  it('refuses a missing parameter, a bare exchange URL, and other schemes', () => {
    expect(interactionUrlFromSearch('')).toBeNull()
    expect(interactionUrlFromSearch('?url=')).toBeNull()
    expect(
      interactionUrlFromSearch(`?url=${encodeURIComponent(EXCHANGE_URL)}`)
    ).toBeNull()
    expect(
      interactionUrlFromSearch(
        `?url=${encodeURIComponent('ftp://was.example/x?iuv=1')}`
      )
    ).toBeNull()
    expect(
      interactionUrlFromSearch(
        `?url=${encodeURIComponent('javascript:alert(1)?iuv=1')}`
      )
    ).toBeNull()
    expect(interactionUrlFromSearch('?url=%2Frelative%3Fiuv%3D1')).toBeNull()
  })
})

describe('openExternalRequest', () => {
  it('opens the exchange behind the interaction URL', async () => {
    const fetch = vi.fn(async (url: string, init?: { method?: string }) => {
      if (url === INTERACTION_URL) {
        return new Response(
          JSON.stringify({ protocols: { vcapi: EXCHANGE_URL } })
        )
      }
      expect(url).toBe(EXCHANGE_URL)
      expect(init?.method).toBe('POST')
      return new Response(
        JSON.stringify({ verifiablePresentationRequest: zcapOnlyRequest() })
      )
    })
    const opened = await openExternalRequest({
      url: INTERACTION_URL,
      fetch: fetch as unknown as typeof globalThis.fetch
    })
    expect(opened.exchangeUrl).toBe(EXCHANGE_URL)
    expect(opened.request.query).toEqual([ZCAP_QUERY])
  })

  it('maps a 404 on the protocols fetch to the gone refusal', async () => {
    const fetch = vi.fn(async () => new Response('', { status: 404 }))
    const thrown = await openExternalRequest({
      url: INTERACTION_URL,
      fetch: fetch as unknown as typeof globalThis.fetch
    }).catch((err: unknown) => err)
    expect(thrown).toBeInstanceOf(ExternalRequestRefusedError)
    expect((thrown as ExternalRequestRefusedError).refusal).toBe('gone')
    expect((thrown as Error).cause).toBeInstanceOf(EphemeralExchangeGoneError)
  })

  it('maps a network failure to unreachable and a bad body to malformed', async () => {
    const down = vi.fn(async () => {
      throw new TypeError('fetch failed')
    })
    await expect(
      openExternalRequest({
        url: INTERACTION_URL,
        fetch: down as unknown as typeof globalThis.fetch
      })
    ).rejects.toMatchObject({ refusal: 'unreachable' })

    const noProtocols = vi.fn(async () => new Response(JSON.stringify({})))
    await expect(
      openExternalRequest({
        url: INTERACTION_URL,
        fetch: noProtocols as unknown as typeof globalThis.fetch
      })
    ).rejects.toMatchObject({ refusal: 'malformedRequest' })
  })

  it('refuses a URL that is not an interaction URL as malformed', async () => {
    await expect(
      openExternalRequest({ url: EXCHANGE_URL })
    ).rejects.toMatchObject({ refusal: 'malformedRequest' })
  })
})

describe('precheckExternalRequest', () => {
  it('passes a zcap-only request through, naming the exchange host for delivery', () => {
    const { profile, deliveryHost } = precheckExternalRequest({
      request: zcapOnlyRequest(),
      exchangeUrl: EXCHANGE_URL
    })
    expect(profile.didAuth).toBe(false)
    expect(profile.appConnect).toBeNull()
    expect(profile.zcapRequests).toHaveLength(1)
    expect(deliveryHost).toBe('was.example')
  })

  it('refuses an empty query set as malformed', () => {
    expect(
      refusalOf(() =>
        precheckExternalRequest({
          request: { query: [] } as unknown as IVPRDetails,
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('malformedRequest')
  })

  it('refuses an AppConnectQuery with its own reason, ahead of classification', () => {
    const request = {
      query: [
        { type: 'DIDAuthentication' },
        {
          type: 'AppConnectQuery',
          app: { name: 'Editor', appUrl: 'https://app.example/' },
          capabilityQuery: []
        }
      ]
    } as unknown as IVPRDetails
    expect(
      refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('appConnect')
  })

  it('refuses DID Authentication in either spelling', () => {
    const withDomain = {
      query: [{ type: 'DIDAuthentication' }, ZCAP_QUERY],
      challenge: 'abc',
      domain: 'verifier.example'
    } as unknown as IVPRDetails
    const withoutDomain = {
      query: [{ type: 'DIDAuthentication' }, ZCAP_QUERY],
      challenge: 'abc'
    } as unknown as IVPRDetails
    for (const request of [withDomain, withoutDomain]) {
      expect(
        refusalOf(() =>
          precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
        )
      ).toBe('didAuth')
    }
  })

  it('refuses a request with no capability query as nothing requested', () => {
    const request = {
      query: [{ type: 'QueryByExample', credentialQuery: [{ example: {} }] }]
    } as unknown as IVPRDetails
    expect(
      refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('nothingRequested')
  })

  it('maps a null reply body to malformed, not unreachable', async () => {
    const nullBody = vi.fn(async () => new Response('null'))
    await expect(
      openExternalRequest({
        url: INTERACTION_URL,
        fetch: nullBody as unknown as typeof globalThis.fetch
      })
    ).rejects.toMatchObject({ refusal: 'malformedRequest' })
  })

  it('refuses a domain on any request', () => {
    expect(
      refusalOf(() =>
        precheckExternalRequest({
          request: zcapOnlyRequest({ domain: 'verifier.example' }),
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('domain')
  })

  it('refuses a presentation endpoint on another origin, allows a same-origin one', () => {
    const foreign = zcapOnlyRequest({
      interact: {
        service: [
          {
            type: 'UnmediatedHttpPresentationService2021',
            serviceEndpoint: 'https://attacker.example/collect'
          }
        ]
      }
    } as Partial<IVPRDetails>)
    expect(
      refusalOf(() =>
        precheckExternalRequest({ request: foreign, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('foreignDelivery')

    const sameOrigin = zcapOnlyRequest({
      interact: {
        service: [
          {
            type: 'UnmediatedHttpPresentationService2021',
            serviceEndpoint: 'https://was.example/other/endpoint'
          }
        ]
      }
    } as Partial<IVPRDetails>)
    expect(
      precheckExternalRequest({
        request: sameOrigin,
        exchangeUrl: EXCHANGE_URL
      }).deliveryHost
    ).toBe('was.example')
  })
})

describe('barredGrants', () => {
  function grant(
    targetClass: string | undefined,
    satisfiable = true
  ): ResolvedGrant {
    return {
      descriptor: { referenceId: targetClass ?? 'none' },
      target: { satisfiable, targetClass },
      allowedActions: ['GET'],
      write: false
    } as unknown as ResolvedGrant
  }

  it('lets public and private collection grants through', () => {
    expect(
      barredGrants([grant('public-collection'), grant('collection')])
    ).toEqual([])
  })

  it('bars shares, whole-Space, and protected-collection targets', () => {
    const barred = barredGrants([
      grant('public-collection'),
      grant('share'),
      grant('space'),
      grant('protected-collection')
    ])
    expect(barred.map(({ target }) => target.targetClass)).toEqual([
      'share',
      'space',
      'protected-collection'
    ])
  })

  it('ignores unsatisfiable grants, which delegate nothing', () => {
    expect(
      barredGrants([grant(undefined, false), grant('share', false)])
    ).toEqual([])
  })
})

describe('EXTERNAL_REQUEST_ORIGIN', () => {
  it('is the fixed marker the Login activity records', () => {
    expect(EXTERNAL_REQUEST_ORIGIN).toBe('n/a (API request)')
  })
})
