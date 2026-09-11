// @vitest-environment node
/**
 * Unit tests for the CHAPI store popup's pre-login check over an issuance
 * exchange's DID-Auth step (`src/lib/walletRequest/storeRequest.ts`): the
 * accepted shape, and each of the four refusals.
 */
import { describe, expect, it } from 'vitest'
import {
  checkStoreDIDAuthRequest,
  StoreRequestRefusedError
} from './storeRequest'
import type { IVPRDetails } from './types'

const EXCHANGE_URL = 'https://issuer.example/workflows/w1/exchanges/abc'
const ORIGIN = 'https://issuer.example'

const DID_AUTH_QUERY = { type: 'DIDAuthentication' }

function didAuthRequest(extra: Partial<IVPRDetails> = {}): IVPRDetails {
  return {
    query: [DID_AUTH_QUERY],
    challenge: 'c-123',
    domain: ORIGIN,
    ...extra
  } as unknown as IVPRDetails
}

function refusalOf(run: () => unknown): string | undefined {
  try {
    run()
    return undefined
  } catch (err) {
    return err instanceof StoreRequestRefusedError ? err.refusal : 'other'
  }
}

describe('checkStoreDIDAuthRequest', () => {
  it('accepts a plain DID-Auth request whose domain matches the origin', () => {
    const { exchangeHost } = checkStoreDIDAuthRequest({
      request: didAuthRequest(),
      exchangeUrl: EXCHANGE_URL,
      origin: ORIGIN
    })
    expect(exchangeHost).toBe('issuer.example')
  })

  it('refuses a request that is not DID Auth, or carries other queries', () => {
    expect(
      refusalOf(() =>
        checkStoreDIDAuthRequest({
          request: didAuthRequest({
            query: [{ type: 'QueryByExample', credentialQuery: {} }]
          } as unknown as Partial<IVPRDetails>),
          exchangeUrl: EXCHANGE_URL,
          origin: ORIGIN
        })
      )
    ).toBe('unsupportedRequest')
    expect(
      refusalOf(() =>
        checkStoreDIDAuthRequest({
          request: didAuthRequest({
            query: [
              DID_AUTH_QUERY,
              { type: 'QueryByExample', credentialQuery: {} }
            ]
          } as unknown as Partial<IVPRDetails>),
          exchangeUrl: EXCHANGE_URL,
          origin: ORIGIN
        })
      )
    ).toBe('unsupportedRequest')
  })

  it('refuses a DID-Auth request that states no domain', () => {
    expect(
      refusalOf(() =>
        checkStoreDIDAuthRequest({
          request: didAuthRequest({ domain: undefined }),
          exchangeUrl: EXCHANGE_URL,
          origin: ORIGIN
        })
      )
    ).toBe('noDomain')
  })

  it('refuses a domain naming another host than the requesting origin', () => {
    expect(
      refusalOf(() =>
        checkStoreDIDAuthRequest({
          request: didAuthRequest({ domain: 'https://relay.example' }),
          exchangeUrl: EXCHANGE_URL,
          origin: ORIGIN
        })
      )
    ).toBe('domainMismatch')
  })

  it('refuses when there is no requesting origin at all', () => {
    expect(
      refusalOf(() =>
        checkStoreDIDAuthRequest({
          request: didAuthRequest(),
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('domainMismatch')
  })

  it('matches a domain on host alone, across scheme and port', () => {
    expect(
      checkStoreDIDAuthRequest({
        request: didAuthRequest({ domain: 'http://issuer.example' }),
        exchangeUrl: EXCHANGE_URL,
        origin: ORIGIN
      }).exchangeHost
    ).toBe('issuer.example')
    expect(
      refusalOf(() =>
        checkStoreDIDAuthRequest({
          request: didAuthRequest({ domain: 'https://issuer.example:8443' }),
          exchangeUrl: EXCHANGE_URL,
          origin: ORIGIN
        })
      )
    ).toBe('domainMismatch')
  })

  it('accepts an interact service endpoint on the exchange origin', () => {
    const request = didAuthRequest({
      interact: {
        service: [
          {
            type: 'UnmediatedHttpPresentationService2021',
            serviceEndpoint: `${EXCHANGE_URL}/response`
          }
        ]
      }
    } as unknown as Partial<IVPRDetails>)
    expect(
      checkStoreDIDAuthRequest({
        request,
        exchangeUrl: EXCHANGE_URL,
        origin: ORIGIN
      }).exchangeHost
    ).toBe('issuer.example')
  })

  it('refuses a service endpoint on another origin than the exchange', () => {
    const request = didAuthRequest({
      interact: {
        service: [
          {
            type: 'UnmediatedHttpPresentationService2021',
            serviceEndpoint: 'https://collector.example/response'
          }
        ]
      }
    } as unknown as Partial<IVPRDetails>)
    expect(
      refusalOf(() =>
        checkStoreDIDAuthRequest({
          request,
          exchangeUrl: EXCHANGE_URL,
          origin: ORIGIN
        })
      )
    ).toBe('foreignDelivery')
  })
})
