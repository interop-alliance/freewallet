import { describe, it, expect } from 'vitest'
import { requestsCredentialType } from './vcMatches'
import type { ICredentialQuery, IQueryByExample } from './types'

function queryByExample(
  example: ICredentialQuery['example']
): IQueryByExample {
  return {
    type: 'QueryByExample',
    credentialQuery: { reason: 'Please present a VC.', example }
  }
}

describe('requestsCredentialType', () => {
  it('is true when an example type (string) matches', () => {
    const queries = [queryByExample({ type: 'LoginCredential' })]
    expect(
      requestsCredentialType({ queries, type: 'LoginCredential' })
    ).toBe(true)
  })

  it('is true when an example type (array) includes the type', () => {
    const queries = [
      queryByExample({ type: ['VerifiableCredential', 'LoginCredential'] })
    ]
    expect(
      requestsCredentialType({ queries, type: 'LoginCredential' })
    ).toBe(true)
  })

  it('is false for an untyped example', () => {
    const queries = [queryByExample({})]
    expect(
      requestsCredentialType({ queries, type: 'LoginCredential' })
    ).toBe(false)
  })

  it('is false when only other types are requested', () => {
    const queries = [queryByExample({ type: 'AlumniCredential' })]
    expect(
      requestsCredentialType({ queries, type: 'LoginCredential' })
    ).toBe(false)
  })

  it('is false for an empty query list', () => {
    expect(
      requestsCredentialType({ queries: [], type: 'LoginCredential' })
    ).toBe(false)
  })
})
