/**
 * Unit tests for the did:web projection id: the string a promoted account's
 * `id/did.json` resolves under. The wallet publishes no did:web document of
 * its own, so there is nothing else in this module to test.
 */
import { describe, it, expect } from 'vitest'
import { didWebOfAccount, didWebOfSpace } from './didWeb'

const SCID = 'QmZQHqm2a11FAhwmsVY5Sa9ZByNLWN1HQH68ze5WmtJqY7'

describe('didWebOfAccount', () => {
  it('drops the method and SCID of a plain-host did:webvh', () => {
    expect(
      didWebOfAccount({
        did: `did:webvh:${SCID}:example.com:space:space-abc:id`
      })
    ).toBe('did:web:example.com:space:space-abc:id')
  })

  it('keeps the percent-encoded port of a dev host', () => {
    expect(
      didWebOfAccount({
        did: `did:webvh:${SCID}:localhost%3A8080:space:space-abc:id`
      })
    ).toBe('did:web:localhost%3A8080:space:space-abc:id')
  })

  it('keeps the prefix segments of a sub-path mount', () => {
    expect(
      didWebOfAccount({
        did: `did:webvh:${SCID}:example.com:was:space:space-abc:id`
      })
    ).toBe('did:web:example.com:was:space:space-abc:id')
  })

  it('refuses a did that is not a did:webvh', () => {
    expect(() =>
      didWebOfAccount({
        did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
      })
    ).toThrow()
  })
})

describe('didWebOfSpace', () => {
  it('names the id the published did:webvh will project to', () => {
    expect(
      didWebOfSpace({
        baseServerUrl: 'http://localhost:8080/',
        spaceId: 'space-abc'
      })
    ).toBe('did:web:localhost%3A8080:space:space-abc:id')
  })

  it('carries a sub-path mount as prefix segments', () => {
    expect(
      didWebOfSpace({
        baseServerUrl: 'https://example.com/was/',
        spaceId: 'space-abc'
      })
    ).toBe(
      didWebOfAccount({
        did: 'did:webvh:QmZQHqm2a11FAhwmsVY5Sa9ZByNLWN1HQH68ze5WmtJqY7:example.com:was:space:space-abc:id'
      })
    )
  })
})
