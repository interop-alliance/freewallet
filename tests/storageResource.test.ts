import { describe, it, expect } from 'vitest'
import {
  isJsonLikeContentType,
  isTextLikeContentType,
  isVerifiableCredentialData
} from '../src/lib/storageResource'

describe('storageResource', () => {
  it('isJsonLikeContentType detects JSON media types', () => {
    expect(isJsonLikeContentType('application/json')).toBe(true)
    expect(isJsonLikeContentType('application/ld+json')).toBe(true)
    expect(isJsonLikeContentType('text/html')).toBe(false)
  })

  it('isTextLikeContentType detects text/*', () => {
    expect(isTextLikeContentType('text/plain')).toBe(true)
    expect(isTextLikeContentType('application/json')).toBe(false)
    expect(isTextLikeContentType(undefined)).toBe(false)
  })

  it('isVerifiableCredentialData detects VC type', () => {
    expect(
      isVerifiableCredentialData({
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: 'VerifiableCredential',
        issuer: 'did:key:abc'
      })
    ).toBe(true)
    expect(
      isVerifiableCredentialData({
        type: ['VerifiableCredential', 'OpenBadgeCredential']
      })
    ).toBe(true)
    expect(isVerifiableCredentialData({ type: 'OpenBadgeCredential' })).toBe(
      false
    )
    expect(isVerifiableCredentialData(null)).toBe(false)
  })
})
