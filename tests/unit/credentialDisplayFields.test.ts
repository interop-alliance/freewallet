import { describe, expect, it } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { getDisplayFields } from '@/lib/viewMappers/credentialDisplayFields'
import { welcomeCredential } from '@/fixtures/welcomeCredential'

describe('getDisplayFields', () => {
  it('maps a simple credential using its top-level name and subject description', () => {
    const fields = getDisplayFields(welcomeCredential)
    expect(fields.credentialName).toBe('Your First Credential')
    expect(fields.credentialDescription).toBe(
      'You have successfully set up your credentials wallet!'
    )
    expect(fields.criteria).toBe('')
    expect(fields.achievementImage).toBe('')
    expect(fields.alignments).toEqual([])
  })

  it('maps an open-badge achievement into name, description, criteria, and image', () => {
    const vc = {
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      credentialSubject: {
        achievement: {
          name: 'Team Player',
          description: 'Works well with others',
          achievementType: 'Badge',
          image: { id: 'https://img/badge.png' },
          criteria: { narrative: 'Collaborate on a project' },
          alignment: [
            {
              targetName: 'Collaboration',
              targetUrl: 'https://skills/collab'
            }
          ]
        }
      }
    } as unknown as IVerifiableCredential

    const fields = getDisplayFields(vc)
    expect(fields.credentialName).toBe('Team Player')
    expect(fields.credentialDescription).toBe('Works well with others')
    expect(fields.criteria).toBe('Collaborate on a project')
    expect(fields.achievementType).toBe('Badge')
    expect(fields.achievementImage).toBe('https://img/badge.png')
    expect(fields.alignments).toEqual([
      {
        targetName: 'Collaboration',
        targetUrl: 'https://skills/collab',
        targetDescription: ''
      }
    ])
  })

  it('returns safe defaults when the subject is not an object', () => {
    const vc = {
      name: 'Bare Credential',
      type: ['VerifiableCredential'],
      credentialSubject: 'did:example:123'
    } as unknown as IVerifiableCredential

    const fields = getDisplayFields(vc)
    expect(fields.credentialName).toBe('Bare Credential')
    expect(fields.credentialDescription).toBe('')
    expect(fields.criteria).toBe('')
    expect(fields.achievementImage).toBe('')
    expect(fields.achievementType).toBe('')
    expect(fields.alignments).toEqual([])
  })

  it('carries expiration and recipient onto the common fields', () => {
    const vc = {
      name: 'Course Certificate',
      validUntil: '2030-01-01T00:00:00Z',
      credentialSubject: {
        person: { contact: { fullName: 'Ada Lovelace' } }
      }
    } as unknown as IVerifiableCredential

    const fields = getDisplayFields(vc)
    expect(fields.expirationDate).toBe('2030-01-01T00:00:00Z')
    expect(fields.issuedTo).toBe('Ada Lovelace')
  })
})
