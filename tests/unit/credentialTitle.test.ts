import { describe, expect, it } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { credentialTitle } from '@/lib/viewMappers/credentialTitle'
import { welcomeCredential } from '@/fixtures/welcomeCredential'

describe('credentialTitle', () => {
  it('returns the top-level credential name', () => {
    expect(credentialTitle(welcomeCredential)).toBe('Your First Credential')
  })

  it('derives the name from a single achievement when there is no top-level name', () => {
    const vc = {
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      credentialSubject: {
        achievement: { name: 'Team Player Badge' }
      }
    } as unknown as IVerifiableCredential
    expect(credentialTitle(vc)).toBe('Team Player Badge')
  })

  it('falls back to a generic title when nothing names the credential', () => {
    const vc = {
      type: ['VerifiableCredential'],
      credentialSubject: { id: 'did:example:123' }
    } as unknown as IVerifiableCredential
    expect(credentialTitle(vc)).toBe('Verifiable Credential')
  })
})
