import { describe, it, expect } from 'vitest'
import {
  isJsonLikeContentType,
  isTextLikeContentType
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
})
