// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import type { Session } from '@/types/auth'
import {
  processRequest,
  domainMatchesOrigin,
  type IVPRDetails
} from '@/lib/walletRequest'

const CHALLENGE = '99612b24-63d9-11ea-b99f-4f66f3e4f81a'

let session: Session

beforeAll(async () => {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret: 'correct horse battery staple',
    handle: 'test',
    keyName: 'test-key'
  })
  session = {
    user: { id: keyAgent.id },
    profile: { keyAgent }
  } as unknown as Session
})

describe('domainMatchesOrigin', () => {
  it('matches a bare host against a full origin URL', () => {
    expect(
      domainMatchesOrigin({
        domain: 'verifier.example',
        origin: 'https://verifier.example'
      })
    ).toBe(true)
  })

  it('does not match a different host', () => {
    expect(
      domainMatchesOrigin({
        domain: 'attacker.example',
        origin: 'https://verifier.example'
      })
    ).toBe(false)
  })

  it('is false when origin is missing', () => {
    expect(domainMatchesOrigin({ domain: 'verifier.example' })).toBe(false)
  })
})

describe('processRequest', () => {
  it('returns {} when neither VCs nor DID Auth are requested', async () => {
    const request: IVPRDetails = {
      query: [{ type: 'QueryByExample', credentialQuery: { example: {} } }]
    }
    const response = await processRequest({
      request,
      session,
      credentialRequestOrigin: 'https://verifier.example',
      selectedVCs: []
    })
    expect(response).toEqual({})
  })

  it('signs a DID-Auth-only VP when the domain matches the origin', async () => {
    const request: IVPRDetails = {
      query: [
        { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] }
      ],
      challenge: CHALLENGE,
      domain: 'verifier.example'
    }
    const { verifiablePresentation } = await processRequest({
      request,
      session,
      credentialRequestOrigin: 'https://verifier.example'
    })
    const proof = verifiablePresentation?.proof as Record<string, unknown>
    expect(proof?.proofPurpose).toBe('authentication')
    expect(proof?.challenge).toBe(CHALLENGE)
    expect(verifiablePresentation?.holder).toBe(session.user.id)
  })

  it('refuses to sign when the domain does not match the origin', async () => {
    const request: IVPRDetails = {
      query: [{ type: 'DIDAuthentication' }],
      challenge: CHALLENGE,
      domain: 'attacker.example'
    }
    await expect(
      processRequest({
        request,
        session,
        credentialRequestOrigin: 'https://verifier.example'
      })
    ).rejects.toThrow(/does not match request origin/)
  })
})
