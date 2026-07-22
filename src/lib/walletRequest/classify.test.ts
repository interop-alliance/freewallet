import { describe, it, expect } from 'vitest'
import {
  classifyCHAPIStoreEvent,
  classifyRequest,
  credentialQueriesOf,
  credentialsOf,
  queriesOf
} from './classify'
import type { CHAPIStoreEvent, IQueryByExample } from './types'

const BARE_VC = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'https://issuer.example.com/issuers/14',
  validFrom: '2018-02-24T05:28:04Z',
  credentialSubject: {
    id: 'did:example:abcdef1234567',
    name: 'Jane Doe'
  }
}

function storeEvent(
  credential: CHAPIStoreEvent['credential']
): CHAPIStoreEvent {
  return { credential, respondWith: () => {} }
}

describe('classifyCHAPIStoreEvent', () => {
  it('wraps a bare offered credential in a presentation', () => {
    const offer = classifyCHAPIStoreEvent(
      storeEvent({ dataType: 'VerifiableCredential', data: BARE_VC })
    )
    const presentation = offer.verifiablePresentation
    expect(presentation.type).toEqual(['VerifiablePresentation'])
    expect(presentation['@context']).toEqual([
      'https://www.w3.org/ns/credentials/v2'
    ])
    expect(credentialsOf(presentation)).toEqual([BARE_VC])
  })

  it('wraps a bare credential even when dataType is absent', () => {
    const offer = classifyCHAPIStoreEvent(storeEvent({ data: BARE_VC }))
    expect(credentialsOf(offer.verifiablePresentation)).toEqual([BARE_VC])
  })

  it('uses the VC 1.0 context when wrapping a VC 1.0 credential', () => {
    const v1 = {
      ...BARE_VC,
      '@context': ['https://www.w3.org/2018/credentials/v1']
    }
    const offer = classifyCHAPIStoreEvent(
      storeEvent({ dataType: 'VerifiableCredential', data: v1 })
    )
    expect(offer.verifiablePresentation['@context']).toEqual([
      'https://www.w3.org/2018/credentials/v1'
    ])
  })

  it('passes an offered presentation through unchanged', () => {
    const presentation = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      verifiableCredential: [BARE_VC]
    }
    const offer = classifyCHAPIStoreEvent(
      storeEvent({ dataType: 'VerifiablePresentation', data: presentation })
    )
    expect(offer.verifiablePresentation).toBe(presentation)
    expect(credentialsOf(offer.verifiablePresentation)).toEqual([BARE_VC])
  })

  it('normalizes a single (non-array) verifiableCredential', () => {
    const presentation = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      verifiableCredential: BARE_VC
    }
    expect(credentialsOf(presentation as never)).toEqual([BARE_VC])
  })

  it('throws on an unrecognized payload', () => {
    expect(() =>
      classifyCHAPIStoreEvent(
        storeEvent({
          dataType: 'Whatever',
          data: { type: ['Whatever'] } as never
        })
      )
    ).toThrow(/unrecognized payload/)
  })
})

describe('queriesOf', () => {
  it('normalizes a single query to an array', () => {
    const query = { type: 'DIDAuthentication' } as const
    expect(queriesOf({ query })).toEqual([query])
  })

  it('returns an empty array for an empty VPR body', () => {
    // What a CHAPI request carrying a `protocols` entry sends: the real
    // request lives behind the exchange, not in the VPR body.
    expect(queriesOf({})).toEqual([])
  })

  it('drops entries that are not typed query objects', () => {
    const query = { type: 'QueryByExample' } as never
    expect(
      queriesOf({ query: [undefined, null, 'nope', query] as never })
    ).toEqual([query])
  })

  it('classifies an empty VPR body without throwing', () => {
    expect(classifyRequest({})).toEqual({
      didAuth: false,
      vcQueries: [],
      zcapRequests: [],
      appConnect: null
    })
  })
})

describe('appConnectRequestOf (via classifyRequest)', () => {
  const app = {
    name: 'Text Editor',
    credentialType: 'TextEditorAppKey',
    vocabBase: 'urn:text-editor:vocab#'
  }
  const capabilityQuery = {
    referenceId: 'text-editor-document',
    allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
    invocationTarget: {
      type: 'urn:was:collection',
      name: 'text-editor-document'
    }
  }

  it('classifies an App Connect request with DID Auth', () => {
    const profile = classifyRequest({
      query: [
        { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] },
        { type: 'AppConnectQuery', app, capabilityQuery: [capabilityQuery] }
      ]
    })
    expect(profile.didAuth).toBe(true)
    expect(profile.appConnect).toEqual({
      app,
      capabilityQueries: [capabilityQuery]
    })
    expect(profile.vcQueries).toEqual([])
    expect(profile.zcapRequests).toEqual([])
  })

  it('normalizes a single (non-array) capabilityQuery', () => {
    const profile = classifyRequest({
      query: [{ type: 'AppConnectQuery', app, capabilityQuery }]
    })
    expect(profile.appConnect?.capabilityQueries).toEqual([capabilityQuery])
  })

  it('classifies an absent capabilityQuery as no grants requested', () => {
    const profile = classifyRequest({
      query: [{ type: 'AppConnectQuery', app }]
    })
    expect(profile.appConnect?.capabilityQueries).toEqual([])
  })

  it('rejects mixing with QueryByExample', () => {
    expect(() =>
      classifyRequest({
        query: [
          { type: 'AppConnectQuery', app },
          { type: 'QueryByExample', credentialQuery: { example: {} } }
        ]
      })
    ).toThrow(/cannot be combined/)
  })

  it('rejects mixing with a standalone capability query', () => {
    expect(() =>
      classifyRequest({
        query: [
          { type: 'AppConnectQuery', app },
          {
            type: 'AuthorizationCapabilityQuery',
            capabilityQuery: {
              controller: 'did:key:z6Mk...',
              ...capabilityQuery
            }
          }
        ]
      })
    ).toThrow(/cannot be combined/)
  })

  it('rejects more than one AppConnectQuery', () => {
    expect(() =>
      classifyRequest({
        query: [
          { type: 'AppConnectQuery', app },
          { type: 'AppConnectQuery', app }
        ]
      })
    ).toThrow(/More than one AppConnectQuery/)
  })

  it('rejects a missing app block', () => {
    expect(() =>
      classifyRequest({ query: [{ type: 'AppConnectQuery' } as never] })
    ).toThrow(/missing its app name/)
  })

  it('rejects a malformed capabilityQuery entry', () => {
    expect(() =>
      classifyRequest({
        query: [
          { type: 'AppConnectQuery', app, capabilityQuery: ['nope'] as never }
        ]
      })
    ).toThrow(/malformed capabilityQuery/)
  })
})

describe('credentialQueriesOf', () => {
  const detail = { reason: 'Please present any VC.', example: {} }

  it('normalizes a single credentialQuery to an array', () => {
    const query: IQueryByExample = {
      type: 'QueryByExample',
      credentialQuery: detail
    }
    expect(credentialQueriesOf(query)).toEqual([detail])
  })

  it('passes an array of credentialQuery details through', () => {
    // The array form is what vcplayground.org sends.
    const query: IQueryByExample = {
      type: 'QueryByExample',
      credentialQuery: [detail, detail]
    }
    expect(credentialQueriesOf(query)).toEqual([detail, detail])
  })

  it('returns an empty array when credentialQuery is absent', () => {
    const query = { type: 'QueryByExample' } as never
    expect(credentialQueriesOf(query)).toEqual([])
  })
})
