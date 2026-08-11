import { describe, it, expect } from 'vitest'
import {
  classifyCHAPIGetEvent,
  classifyCHAPIStoreEvent,
  classifyRequest,
  isDIDAuthRequested,
  zcapQueriesOf,
  didAuthMethodSupported,
  type CHAPIGetEvent,
  type CHAPIStoreEvent,
  type ICapabilityQueryDetail,
  type IVPRDetails
} from '@/lib/walletRequest'
// The spec query union (no App Connect member): these fixtures feed the shared
// classify helpers, which take the spec union.
import type { IVPRQuery } from '@interop/wallet-core/request'

const noop = () => {}

const queryByExample: IVPRQuery = {
  type: 'QueryByExample',
  credentialQuery: { reason: 'Please share your ID.', example: {} }
}

const didAuthQuery: IVPRQuery = {
  type: 'DIDAuthentication',
  acceptedMethods: [{ method: 'key' }]
}

const capabilityDetail: ICapabilityQueryDetail = {
  referenceId: 'example-app-data',
  reason: 'Example App stores your documents in your wallet storage.',
  allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
  controller: 'did:key:z6MkrRP',
  invocationTarget: {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'example-app-data'
  }
}

// Canonical VCALM shape: an array-valued capabilityQuery.
const authorizationCapabilityQuery: IVPRQuery = {
  type: 'AuthorizationCapabilityQuery',
  capabilityQuery: [capabilityDetail]
}

// Legacy demo shape: the ZcapQuery alias with a single-object capabilityQuery.
const legacyZcapQuery: IVPRQuery = {
  type: 'ZcapQuery',
  capabilityQuery: capabilityDetail
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

function details(query: IVPRQuery | IVPRQuery[]): IVPRDetails {
  return { query }
}

describe('classifyCHAPIGetEvent', () => {
  it('wraps the VerifiablePresentation body as an IVpRequest', () => {
    const request = classifyCHAPIGetEvent(getEvent([queryByExample]))

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

describe('zcapQueriesOf', () => {
  it('collects an array-valued AuthorizationCapabilityQuery', () => {
    expect(zcapQueriesOf([authorizationCapabilityQuery])).toEqual([
      capabilityDetail
    ])
  })

  it('normalizes a single-object ZcapQuery (legacy demo shape)', () => {
    expect(zcapQueriesOf([legacyZcapQuery])).toEqual([capabilityDetail])
  })

  it('flattens across multiple zcap queries and ignores other types', () => {
    expect(
      zcapQueriesOf([
        queryByExample,
        authorizationCapabilityQuery,
        legacyZcapQuery,
        didAuthQuery
      ])
    ).toEqual([capabilityDetail, capabilityDetail])
  })

  it('is empty when no zcap query is present', () => {
    expect(zcapQueriesOf([queryByExample, didAuthQuery])).toEqual([])
  })

  it('throws when a zcap query has no capabilityQuery', () => {
    expect(() => zcapQueriesOf([{ type: 'ZcapQuery' } as IVPRQuery])).toThrow(
      /missing its capabilityQuery detail/
    )
  })

  it('throws when an array capabilityQuery holds a non-object entry', () => {
    expect(() =>
      zcapQueriesOf([
        {
          type: 'AuthorizationCapabilityQuery',
          capabilityQuery: [capabilityDetail, null]
        } as unknown as IVPRQuery
      ])
    ).toThrow(/missing its capabilityQuery detail/)
  })
})

describe('classifyRequest', () => {
  it('classifies a DID-Auth-only request', () => {
    const profile = classifyRequest({ request: details([didAuthQuery]) })
    expect(profile).toEqual({
      didAuth: true,
      vcQueries: [],
      zcapRequests: [],
      appConnect: null
    })
  })

  it('classifies a VC-only request', () => {
    const profile = classifyRequest({ request: details([queryByExample]) })
    expect(profile.didAuth).toBe(false)
    expect(profile.vcQueries).toEqual([queryByExample])
    expect(profile.zcapRequests).toEqual([])
  })

  it('classifies a zcap-only request', () => {
    const profile = classifyRequest({
      request: details([authorizationCapabilityQuery])
    })
    expect(profile.didAuth).toBe(false)
    expect(profile.vcQueries).toEqual([])
    expect(profile.zcapRequests).toEqual([capabilityDetail])
  })

  it('classifies a combined DIDAuth + VC + zcap request', () => {
    const profile = classifyRequest({
      request: details([
        didAuthQuery,
        queryByExample,
        authorizationCapabilityQuery
      ])
    })
    expect(profile.didAuth).toBe(true)
    expect(profile.vcQueries).toEqual([queryByExample])
    expect(profile.zcapRequests).toEqual([capabilityDetail])
  })

  it('handles a single (non-array) query object', () => {
    const profile = classifyRequest({ request: details(didAuthQuery) })
    expect(profile.didAuth).toBe(true)
  })

  it('round-trips the legacy demo request (ZcapQuery + DIDAuthentication)', () => {
    const profile = classifyRequest({
      request: details([didAuthQuery, legacyZcapQuery])
    })
    expect(profile.didAuth).toBe(true)
    expect(profile.zcapRequests).toEqual([capabilityDetail])
  })

  it('throws on a capabilityQuery-less zcap query (malformed request)', () => {
    expect(() =>
      classifyRequest({
        request: details([{ type: 'ZcapQuery' } as IVPRQuery])
      })
    ).toThrow(/missing its capabilityQuery detail/)
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
