import { describe, it, expect } from 'vitest'
import { vcMatchesFor, hasTypedExample } from '@/lib/walletRequest'
import type { ICredentialQuery, IQueryByExample } from '@/lib/walletRequest'
import type { StoredCredential } from '@/types/credential'
import type { IVerifiableCredential } from '@interop/data-integrity-core'

function stored(
  cid: string,
  type: string | string[],
  issuer: string
): StoredCredential {
  return {
    cid,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type,
      issuer,
      credentialSubject: { id: 'did:example:subject' }
    } as unknown as IVerifiableCredential
  }
}

const loginVc = stored(
  'login',
  ['VerifiableCredential', 'LoginCredential'],
  'did:key:zUser'
)
const idVc = stored(
  'id',
  ['VerifiableCredential', 'IdentityCredential'],
  'did:key:zIssuer'
)

function qbe(example: ICredentialQuery['example']): IQueryByExample {
  return { type: 'QueryByExample', credentialQuery: { example } }
}

describe('vcMatchesFor', () => {
  it('matches by a single example type', () => {
    const matches = vcMatchesFor({
      credentials: [loginVc, idVc],
      queries: [qbe({ type: 'LoginCredential' })]
    })
    expect(matches.map(({ cid }) => cid)).toEqual(['login'])
  })

  it('requires every type in an array example to be present', () => {
    const matches = vcMatchesFor({
      credentials: [loginVc, idVc],
      queries: [qbe({ type: ['VerifiableCredential', 'IdentityCredential'] })]
    })
    expect(matches.map(({ cid }) => cid)).toEqual(['id'])
  })

  it('also matches on example.issuer when present', () => {
    const noMatch = vcMatchesFor({
      credentials: [loginVc],
      queries: [qbe({ type: 'LoginCredential', issuer: 'did:key:zOther' })]
    })
    expect(noMatch).toEqual([])

    const match = vcMatchesFor({
      credentials: [loginVc],
      queries: [qbe({ type: 'LoginCredential', issuer: 'did:key:zUser' })]
    })
    expect(match.map(({ cid }) => cid)).toEqual(['login'])
  })

  it('matches through an array-shaped credentialQuery', () => {
    // The form vcplayground.org sends.
    const query: IQueryByExample = {
      type: 'QueryByExample',
      credentialQuery: [
        { example: { type: 'LoginCredential' } },
        { example: { type: 'IdentityCredential' } }
      ]
    }
    const matches = vcMatchesFor({
      credentials: [loginVc, idVc],
      queries: [query]
    })
    expect(matches.map(({ cid }) => cid)).toEqual(['login', 'id'])
    expect(hasTypedExample([query])).toBe(true)
  })

  it('returns nothing when no query specifies an example type', () => {
    expect(
      vcMatchesFor({
        credentials: [loginVc, idVc],
        queries: [qbe({})]
      })
    ).toEqual([])
  })

  it('unions matches across multiple typed queries', () => {
    const matches = vcMatchesFor({
      credentials: [loginVc, idVc],
      queries: [
        qbe({ type: 'LoginCredential' }),
        qbe({ type: 'IdentityCredential' })
      ]
    })
    expect(matches.map(({ cid }) => cid).sort()).toEqual(['id', 'login'])
  })
})

describe('hasTypedExample', () => {
  it('is true when a query pins an example type', () => {
    expect(hasTypedExample([qbe({ type: 'LoginCredential' })])).toBe(true)
  })

  it('is false when no query pins an example type', () => {
    expect(hasTypedExample([qbe({})])).toBe(false)
  })
})
