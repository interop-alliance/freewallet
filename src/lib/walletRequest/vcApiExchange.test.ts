import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  beginExchange,
  collectIssuedPresentation,
  presentationEndpointFor,
  startExchange,
  submitPresentation,
  vcApiExchangeUrl
} from './vcApiExchange'
import type { IVerifiablePresentation, IVPRDetails } from './types'

const EXCHANGE_URL =
  'https://sandbox.platform.veres.dev/workflows/z19szo/exchanges/z1A7B6'

/**
 * The VPR vcplayground.org's "Any VC" request actually yields, verbatim from
 * the exchange: an array-valued `credentialQuery`, bare-string
 * `acceptedCryptosuites`, a DIDAuthentication query alongside the
 * QueryByExample, and a `domain` naming the verifier rather than the (distinct)
 * host the exchange runs on.
 */
const VPR: IVPRDetails = {
  query: [
    {
      type: 'QueryByExample',
      credentialQuery: [
        {
          reason: 'Please present any Verifiable Credential(s).',
          example: {
            '@context': ['https://www.w3.org/ns/credentials/v2'],
            type: ['VerifiableCredential']
          },
          acceptedCryptosuites: ['Ed25519Signature2020', 'eddsa-rdfc-2022']
        }
      ]
    },
    { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] }
  ],
  domain: 'vcplayground.org',
  challenge: 'z1A7B6PGddB5yHepS1zvKmnZp'
}

const PRESENTATION = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiablePresentation']
} as IVerifiablePresentation

function mockFetch(response: { status?: number; body?: string }) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: (response.status ?? 200) < 400,
    status: response.status ?? 200,
    statusText: 'Error',
    text: async () => response.body ?? ''
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

beforeEach(() => {
  vi.restoreAllMocks()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('vcApiExchangeUrl', () => {
  const INTERACT_URL =
    'https://coordinator.example/interactions/z1A2b3C4d5E6f7G8h9'

  it('returns the vcapi exchange URL when the verifier names one', () => {
    expect(vcApiExchangeUrl({ protocols: { vcapi: EXCHANGE_URL } })).toBe(
      EXCHANGE_URL
    )
  })

  it('returns the interact URL of the chapi.interact() API', () => {
    expect(vcApiExchangeUrl({ protocols: { interact: INTERACT_URL } })).toBe(
      INTERACT_URL
    )
  })

  it('prefers the interact URL over vcapi when both are present', () => {
    expect(
      vcApiExchangeUrl({
        protocols: { interact: INTERACT_URL, vcapi: EXCHANGE_URL }
      })
    ).toBe(INTERACT_URL)
  })

  it('returns undefined when no protocols are offered', () => {
    expect(vcApiExchangeUrl({})).toBeUndefined()
    expect(vcApiExchangeUrl({ protocols: {} })).toBeUndefined()
    expect(
      vcApiExchangeUrl({ protocols: { OID4VP: 'openid4vp://' } })
    ).toBeUndefined()
  })

  it('ignores an empty interact value and falls back to vcapi', () => {
    expect(
      vcApiExchangeUrl({ protocols: { interact: '', vcapi: EXCHANGE_URL } })
    ).toBe(EXCHANGE_URL)
  })
})

describe('startExchange', () => {
  it('POSTs an empty body and returns the VPR', async () => {
    const fetchMock = mockFetch({
      body: JSON.stringify({ verifiablePresentationRequest: VPR })
    })
    const request = await startExchange({ exchangeUrl: EXCHANGE_URL })

    expect(request).toEqual(VPR)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(EXCHANGE_URL)
    expect(init.method).toBe('POST')
    expect(init.body).toBe('{}')
  })

  it('throws when the exchange returns no presentation request', async () => {
    mockFetch({ body: JSON.stringify({ redirectUrl: 'https://elsewhere' }) })
    await expect(startExchange({ exchangeUrl: EXCHANGE_URL })).rejects.toThrow(
      /did not return a verifiablePresentationRequest/
    )
  })

  it('throws on a non-2xx response', async () => {
    mockFetch({ status: 404 })
    await expect(startExchange({ exchangeUrl: EXCHANGE_URL })).rejects.toThrow(
      /responded 404/
    )
  })
})

describe('beginExchange', () => {
  it('returns the presentation an issuance exchange offers outright', async () => {
    const fetchMock = mockFetch({
      body: JSON.stringify({ verifiablePresentation: PRESENTATION })
    })
    const opening = await beginExchange({ exchangeUrl: EXCHANGE_URL })

    expect(opening.verifiablePresentation).toEqual(PRESENTATION)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(EXCHANGE_URL)
    expect(init.body).toBe('{}')
  })

  it('returns the VPR of an exchange that asks for holder binding', async () => {
    mockFetch({ body: JSON.stringify({ verifiablePresentationRequest: VPR }) })
    const opening = await beginExchange({ exchangeUrl: EXCHANGE_URL })

    expect(opening.verifiablePresentationRequest).toEqual(VPR)
    expect(opening.verifiablePresentation).toBeUndefined()
  })
})

describe('collectIssuedPresentation', () => {
  it('trades the DID-Auth presentation for the offered credentials', async () => {
    const offered = {
      ...PRESENTATION,
      verifiableCredential: []
    } as IVerifiablePresentation
    const fetchMock = mockFetch({
      body: JSON.stringify({ verifiablePresentation: offered })
    })
    const result = await collectIssuedPresentation({
      request: VPR,
      exchangeUrl: EXCHANGE_URL,
      verifiablePresentation: PRESENTATION
    })

    expect(result).toEqual(offered)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(EXCHANGE_URL)
    expect(JSON.parse(init.body)).toEqual({
      verifiablePresentation: PRESENTATION
    })
  })

  it('rejects an exchange that asks for a further presentation', async () => {
    mockFetch({ body: JSON.stringify({ verifiablePresentationRequest: VPR }) })
    await expect(
      collectIssuedPresentation({
        request: VPR,
        exchangeUrl: EXCHANGE_URL,
        verifiablePresentation: PRESENTATION
      })
    ).rejects.toThrow(/asked for a further presentation/)
  })

  it('rejects an exchange that offers nothing back', async () => {
    mockFetch({ body: '' })
    await expect(
      collectIssuedPresentation({
        request: VPR,
        exchangeUrl: EXCHANGE_URL,
        verifiablePresentation: PRESENTATION
      })
    ).rejects.toThrow(/offered no verifiablePresentation/)
  })
})

describe('presentationEndpointFor', () => {
  it('falls back to the exchange URL when the VPR names no service', () => {
    expect(
      presentationEndpointFor({ request: VPR, exchangeUrl: EXCHANGE_URL })
    ).toBe(EXCHANGE_URL)
  })

  it('prefers an unmediated HTTP presentation service endpoint', () => {
    const serviceEndpoint = 'https://example.com/present'
    const request = {
      ...VPR,
      interact: {
        service: [
          { type: 'MediatedHttpPresentationService2021', serviceEndpoint: 'x' },
          { type: 'UnmediatedHttpPresentationService2021', serviceEndpoint }
        ]
      }
    }
    expect(
      presentationEndpointFor({ request, exchangeUrl: EXCHANGE_URL })
    ).toBe(serviceEndpoint)
  })
})

describe('submitPresentation', () => {
  it('POSTs the presentation to the exchange', async () => {
    const fetchMock = mockFetch({ body: '' })
    const result = await submitPresentation({
      request: VPR,
      exchangeUrl: EXCHANGE_URL,
      verifiablePresentation: PRESENTATION
    })

    // A completed exchange answers with an empty body.
    expect(result).toEqual({})
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(EXCHANGE_URL)
    expect(JSON.parse(init.body)).toEqual({
      verifiablePresentation: PRESENTATION
    })
  })

  it('throws when the exchange rejects the presentation', async () => {
    mockFetch({ status: 400 })
    await expect(
      submitPresentation({
        request: VPR,
        exchangeUrl: EXCHANGE_URL,
        verifiablePresentation: PRESENTATION
      })
    ).rejects.toThrow(/responded 400/)
  })
})
