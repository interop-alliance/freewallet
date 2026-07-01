import { describe, it, expect } from 'vitest'
import {
  classifyCHAPIGetEvent,
  classifyCHAPIStoreEvent,
  isVPOffer,
  isVPRequest,
  isDIDAuthRequested,
  isDIDAuthOnlyRequest,
  requestKindOf,
  didAuthMethodSupported,
  type CHAPIGetEvent,
  type CHAPIStoreEvent,
  type IVPRQuery
} from '@/lib/walletRequest'

const noop = () => {}

const queryByExample: IVPRQuery = {
  type: 'QueryByExample',
  credentialQuery: { reason: 'Please share your ID.', example: {} }
}

const didAuthQuery: IVPRQuery = {
  type: 'DIDAuthentication',
  acceptedMethods: [{ method: 'key' }]
}

function getEvent(query: unknown): CHAPIGetEvent {
  return {
    credentialRequestOrigin: 'https://verifier.example',
    credentialRequestOptions: {
      web: {
        VerifiablePresentation: {
          query,
          challenge: 'abc-123',
          domain: 'verifier.example'
        }
      }
    } as CHAPIGetEvent['credentialRequestOptions'],
    respondWith: noop
  }
}

describe('classifyCHAPIGetEvent', () => {
  it('wraps the VerifiablePresentation body as an IVpRequest', () => {
    const request = classifyCHAPIGetEvent(getEvent([queryByExample]))

    expect(isVPRequest(request)).toBe(true)
    expect(request.credentialRequestOrigin).toBe('https://verifier.example')
    expect(request.verifiablePresentationRequest.challenge).toBe('abc-123')
    expect(request.verifiablePresentationRequest.domain).toBe(
      'verifier.example'
    )
    expect(request.verifiablePresentationRequest.query).toEqual([
      queryByExample
    ])
  })

  it('throws when the event carries no VerifiablePresentation request', () => {
    const event = {
      credentialRequestOrigin: 'https://verifier.example',
      credentialRequestOptions: { web: {} },
      respondWith: noop
    } as CHAPIGetEvent

    expect(() => classifyCHAPIGetEvent(event)).toThrow(
      /missing a VerifiablePresentation request/
    )
  })
})

describe('classifyCHAPIStoreEvent', () => {
  it('wraps credential.data as an IVpOffer', () => {
    const vp = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: 'VerifiablePresentation',
      verifiableCredential: { id: 'urn:vc:1' }
    }
    const event = {
      credentialRequestOrigin: 'https://issuer.example',
      credential: { data: vp },
      respondWith: noop
    } as unknown as CHAPIStoreEvent

    const offer = classifyCHAPIStoreEvent(event)

    expect(isVPOffer(offer)).toBe(true)
    expect(isVPRequest(offer)).toBe(false)
    expect(offer.credentialRequestOrigin).toBe('https://issuer.example')
    expect(offer.verifiablePresentation).toBe(vp)
  })
})

describe('isDidAuthRequested', () => {
  it('is false when no DIDAuthentication query is present', () => {
    expect(isDIDAuthRequested({ queries: [queryByExample] })).toBe(false)
  })

  it('is true when exactly one DIDAuthentication query is present', () => {
    expect(
      isDIDAuthRequested({ queries: [queryByExample, didAuthQuery] })
    ).toBe(true)
  })

  it('throws when more than one DIDAuthentication query is present', () => {
    expect(() =>
      isDIDAuthRequested({ queries: [didAuthQuery, didAuthQuery] })
    ).toThrow(/More than one DIDAuthentication/)
  })
})

describe('isDIDAuthOnlyRequest', () => {
  it('is true when every query is DIDAuthentication', () => {
    const request = classifyCHAPIGetEvent(getEvent([didAuthQuery]))
    expect(isDIDAuthOnlyRequest(request)).toBe(true)
  })

  it('handles a single (non-array) query object', () => {
    const request = classifyCHAPIGetEvent(getEvent(didAuthQuery))
    expect(isDIDAuthOnlyRequest(request)).toBe(true)
  })

  it('is false for a combined VC + DIDAuthentication request', () => {
    const request = classifyCHAPIGetEvent(
      getEvent([queryByExample, didAuthQuery])
    )
    expect(isDIDAuthOnlyRequest(request)).toBe(false)
  })

  it('is false for a plain VC request', () => {
    const request = classifyCHAPIGetEvent(getEvent([queryByExample]))
    expect(isDIDAuthOnlyRequest(request)).toBe(false)
  })

  it('is false for an offer', () => {
    const offer = classifyCHAPIStoreEvent({
      credentialRequestOrigin: 'https://issuer.example',
      credential: {
        data: {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          type: 'VerifiablePresentation'
        }
      },
      respondWith: noop
    } as unknown as CHAPIStoreEvent)
    expect(isDIDAuthOnlyRequest(offer)).toBe(false)
  })
})

describe('requestKindOf', () => {
  it('is "vc" for a QueryByExample-only request', () => {
    expect(
      requestKindOf(classifyCHAPIGetEvent(getEvent([queryByExample])))
    ).toBe('vc')
  })

  it('is "didauth" for a DIDAuthentication-only request', () => {
    expect(requestKindOf(classifyCHAPIGetEvent(getEvent([didAuthQuery])))).toBe(
      'didauth'
    )
  })

  it('is "vc+didauth" for a combined request', () => {
    expect(
      requestKindOf(
        classifyCHAPIGetEvent(getEvent([queryByExample, didAuthQuery]))
      )
    ).toBe('vc+didauth')
  })
})

describe('didAuthMethodSupported', () => {
  it('is true when acceptedMethods includes key', () => {
    expect(didAuthMethodSupported([didAuthQuery])).toBe(true)
  })

  it('is true when acceptedMethods is absent', () => {
    expect(didAuthMethodSupported([{ type: 'DIDAuthentication' }])).toBe(true)
  })

  it('is false when acceptedMethods excludes key', () => {
    expect(
      didAuthMethodSupported([
        { type: 'DIDAuthentication', acceptedMethods: [{ method: 'web' }] }
      ])
    ).toBe(false)
  })
})
