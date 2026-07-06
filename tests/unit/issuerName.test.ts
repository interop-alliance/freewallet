import { describe, expect, it } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { issuerName, getIssuerDetails } from '@/lib/viewMappers/issuerName'

describe('issuerName', () => {
  it('returns the issuer string directly when it is a DID string', () => {
    const vc = {
      issuer: 'did:web:example.edu'
    } as unknown as IVerifiableCredential
    expect(issuerName(vc)).toBe('did:web:example.edu')
  })

  it('prefers the issuer name for an object issuer', () => {
    const vc = {
      issuer: { id: 'did:web:example.edu', name: 'Example University' }
    } as unknown as IVerifiableCredential
    expect(issuerName(vc)).toBe('Example University')
  })

  it('falls back to the issuer id when the object has no name', () => {
    const vc = {
      issuer: { id: 'did:web:example.edu' }
    } as unknown as IVerifiableCredential
    expect(issuerName(vc)).toBe('did:web:example.edu')
  })

  it('returns Unknown Issuer when the object has neither name nor id', () => {
    const vc = { issuer: {} } as unknown as IVerifiableCredential
    expect(issuerName(vc)).toBe('Unknown Issuer')
  })
})

describe('getIssuerDetails', () => {
  it('maps a string issuer to an id-only detail record', () => {
    expect(getIssuerDetails('did:web:example.edu')).toEqual({
      id: 'did:web:example.edu',
      name: '',
      url: '',
      image: ''
    })
  })

  it('maps a full object issuer with a string image', () => {
    expect(
      getIssuerDetails({
        id: 'did:web:example.edu',
        name: 'Example University',
        url: 'https://example.edu',
        image: 'https://example.edu/logo.png'
      })
    ).toEqual({
      id: 'did:web:example.edu',
      name: 'Example University',
      url: 'https://example.edu',
      image: 'https://example.edu/logo.png'
    })
  })

  it('extracts the image id from an object image', () => {
    const details = getIssuerDetails({
      id: 'did:web:example.edu',
      image: { id: 'https://example.edu/logo.png' }
    } as unknown as IVerifiableCredential['issuer'])
    expect(details.image).toBe('https://example.edu/logo.png')
  })

  it('defaults missing fields to empty strings', () => {
    expect(getIssuerDetails({ id: 'did:web:example.edu' })).toEqual({
      id: 'did:web:example.edu',
      name: '',
      url: '',
      image: ''
    })
  })
})
