/**
 * Unit tests for the did:web projection id: the string a promoted account's
 * `id/did.json` resolves under. The wallet publishes no did:web document of
 * its own, so there is nothing else in this module to test.
 */
import { describe, it, expect } from 'vitest'
import { didWebFromSpace } from './didWeb'

const SPACE_ID = 'space-abc'

describe('didWebFromSpace', () => {
  it('builds a did:web from a plain host', () => {
    expect(
      didWebFromSpace({
        wasServerUrl: 'https://example.com',
        spaceId: SPACE_ID
      })
    ).toBe('did:web:example.com:space:space-abc:id')
  })

  it('percent-encodes a host with a port (dev)', () => {
    expect(
      didWebFromSpace({
        wasServerUrl: 'http://localhost:8080',
        spaceId: SPACE_ID
      })
    ).toBe('did:web:localhost%3A8080:space:space-abc:id')
  })

  it('drops a default port', () => {
    expect(
      didWebFromSpace({
        wasServerUrl: 'https://example.com:443/kms',
        spaceId: SPACE_ID
      })
    ).toBe('did:web:example.com:space:space-abc:id')
  })
})
