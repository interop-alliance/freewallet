// @vitest-environment node
/**
 * Unit tests for the CHAPI get popup's pre-consent refusal matrix
 * (`src/lib/walletRequest/getRequest.ts`): the accepted shapes, the order the
 * cells are read in, and each refusal -- the unattributable requesting origin
 * included, which used to reach the consent screen as a blank requester label.
 */
import { describe, expect, it } from 'vitest'
import en from '@/i18n/locales/en.json'
import es from '@/i18n/locales/es.json'
import {
  attestedRequestOrigin,
  GetRequestRefusedError,
  precheckGetRequest
} from './getRequest'
import type { IVPRDetails } from './types'

const ORIGIN = 'https://verifier.example'
const DID_METHODS = ['webvh', 'web', 'key'] as const

const QUERY_BY_EXAMPLE = {
  type: 'QueryByExample',
  credentialQuery: { example: { type: 'DriversLicense' } }
}

function request(extra: Partial<IVPRDetails> = {}): IVPRDetails {
  return {
    query: [QUERY_BY_EXAMPLE],
    challenge: 'c-123',
    ...extra
  } as unknown as IVPRDetails
}

function refusalOf(run: () => unknown): string | undefined {
  try {
    run()
    return undefined
  } catch (err) {
    return err instanceof GetRequestRefusedError ? err.refusal : 'other'
  }
}

function precheck({
  request: body = request(),
  credentialRequestOrigin = ORIGIN
}: {
  request?: IVPRDetails
  credentialRequestOrigin?: string
} = {}) {
  return precheckGetRequest({
    request: body,
    credentialRequestOrigin,
    didMethods: DID_METHODS
  })
}

describe('attestedRequestOrigin', () => {
  it('canonicalizes the attested value', () => {
    expect(attestedRequestOrigin('https://verifier.example/some/path')).toBe(
      ORIGIN
    )
    expect(attestedRequestOrigin('https://verifier.example:443')).toBe(ORIGIN)
  })

  it('refuses an absent, empty, or unparseable origin', () => {
    for (const value of [
      undefined,
      '',
      '   ',
      'verifier.example',
      'https://'
    ]) {
      expect(refusalOf(() => attestedRequestOrigin(value))).toBe(
        'unattributedOrigin'
      )
    }
  })

  it('refuses a scheme whose origin is opaque', () => {
    // `new URL()` accepts these and serializes their origin as the string
    // "null", which attributes the request to nobody.
    for (const value of [
      'mailto:someone@verifier.example',
      'data:text/plain,hello',
      'file:///tmp/page.html'
    ]) {
      expect(refusalOf(() => attestedRequestOrigin(value))).toBe(
        'unattributedOrigin'
      )
    }
  })
})

describe('precheckGetRequest', () => {
  it('accepts a credential request from an attested origin', () => {
    const { profile, queries, origin } = precheck()
    expect(origin).toBe(ORIGIN)
    expect(queries).toHaveLength(1)
    expect(profile.vcQueries).toHaveLength(1)
    expect(profile.didAuth).toBe(false)
    expect(profile.appConnect).toBeNull()
  })

  it('refuses a request this wallet cannot attribute to a website', () => {
    expect(
      refusalOf(() => precheck({ credentialRequestOrigin: 'not a url' }))
    ).toBe('unattributedOrigin')
  })

  it('reads the origin cell before anything in the request body', () => {
    // Both cells would refuse; the origin is the one the user is told about,
    // since a body from nobody is not a body worth reporting on.
    expect(
      refusalOf(() =>
        precheck({
          request: request({ query: [] } as unknown as Partial<IVPRDetails>),
          credentialRequestOrigin: 'not a url'
        })
      )
    ).toBe('unattributedOrigin')
  })

  it('refuses a body carrying no readable query', () => {
    expect(
      refusalOf(() =>
        precheck({
          request: request({ query: [] } as unknown as Partial<IVPRDetails>)
        })
      )
    ).toBe('malformedRequest')
  })

  it('refuses a body the classifier rejects', () => {
    expect(
      refusalOf(() =>
        precheck({
          request: request({
            query: [{ type: 'AppConnectQuery' }]
          } as unknown as Partial<IVPRDetails>)
        })
      )
    ).toBe('malformedRequest')
  })

  it('classifies an App Connect request against the attested origin', () => {
    const { profile } = precheck({
      request: request({
        query: [
          {
            type: 'AppConnectQuery',
            app: { name: 'Notes', appUrl: 'https://verifier.example/notes' }
          }
        ]
      } as unknown as Partial<IVPRDetails>)
    })
    expect(profile.appConnect?.app).toEqual({
      name: 'Notes',
      appUrl: 'https://verifier.example/notes'
    })
  })

  it('refuses DID Auth constrained to methods the deployment cannot present', () => {
    const didAuth = (acceptedMethods: Array<{ method: string }>) =>
      request({
        query: [{ type: 'DIDAuthentication', acceptedMethods }]
      } as unknown as Partial<IVPRDetails>)
    expect(
      refusalOf(() => precheck({ request: didAuth([{ method: 'ion' }]) }))
    ).toBe('unsupported')
    expect(
      precheck({ request: didAuth([{ method: 'key' }]) }).profile.didAuth
    ).toBe(true)
  })

  it('refuses a domain naming another site than the attested origin', () => {
    expect(
      refusalOf(() =>
        precheck({ request: request({ domain: 'evil.example' }) })
      )
    ).toBe('domainMismatch')
    expect(
      precheck({ request: request({ domain: 'verifier.example' }) }).origin
    ).toBe(ORIGIN)
  })
})

describe('the refusal copy', () => {
  it('has an en and an es cell for the unattributable origin', () => {
    expect(en.chapi.get.unattributedOrigin).toBeTruthy()
    expect(es.chapi.get.unattributedOrigin).toBeTruthy()
  })
})
