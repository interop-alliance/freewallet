// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import * as vc from '@interop/vc'
import { securityLoader } from '@interop/security-document-loader'
import type { Session } from '@/types/auth'
import { composeVP } from '@/lib/walletRequest/composeVP'
import {
  negotiateCryptosuite,
  presentationSuiteFor,
  EDDSA_RDFC_2022
} from '@/lib/walletRequest/presentationSuite'
import type { IVPRQuery } from '@/lib/walletRequest'

const documentLoader = securityLoader({ fetchRemoteContexts: true }).build()

const CHALLENGE = '99612b24-63d9-11ea-b99f-4f66f3e4f81a'
const DOMAIN = 'verifier.example'

/**
 * composeVp only touches session.profile.keyAgent + session.user.id, so a
 * partial session is sufficient here.
 */
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

describe('negotiateCryptosuite', () => {
  it('honors an explicit supported acceptedCryptosuites preference', () => {
    const queries: IVPRQuery[] = [
      {
        type: 'DIDAuthentication',
        acceptedCryptosuites: [{ cryptosuite: EDDSA_RDFC_2022 }]
      }
    ]
    expect(negotiateCryptosuite(queries)).toBe(EDDSA_RDFC_2022)
  })

  it('falls back to default when listed suites are unsupported', () => {
    const queries: IVPRQuery[] = [
      {
        type: 'DIDAuthentication',
        acceptedCryptosuites: [{ cryptosuite: 'some-unknown-suite' }]
      }
    ]
    expect(negotiateCryptosuite(queries)).toBeUndefined()
  })

  it('infers eddsa-rdfc-2022 from a VC 2.0 QueryByExample', () => {
    const queries: IVPRQuery[] = [
      {
        type: 'QueryByExample',
        credentialQuery: {
          example: { '@context': ['https://www.w3.org/ns/credentials/v2'] }
        }
      }
    ]
    expect(negotiateCryptosuite(queries)).toBe(EDDSA_RDFC_2022)
  })

  it('returns undefined when no signal is present', () => {
    const queries: IVPRQuery[] = [
      { type: 'QueryByExample', credentialQuery: { example: {} } }
    ]
    expect(negotiateCryptosuite(queries)).toBeUndefined()
  })
})

describe('composeVp (unsigned)', () => {
  it('throws when neither VCs nor DID Auth are present', async () => {
    await expect(
      composeVP({ session, didAuthRequested: false })
    ).rejects.toThrow(/either credentials or a DID Auth request/)
  })

  it('produces an unsigned VP with no proof', async () => {
    const fakeVc = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: 'did:key:z6MkExample',
      credentialSubject: { id: 'did:example:subject' }
    }
    const vp = await composeVP({
      session,
      selectedVCs: [fakeVc as never],
      didAuthRequested: false
    })
    expect(vp.proof).toBeUndefined()
    expect(vp.type).toContain('VerifiablePresentation')
  })
})

describe('composeVp (DID Auth)', () => {
  it('requires challenge and domain', async () => {
    await expect(
      composeVP({ session, didAuthRequested: true })
    ).rejects.toThrow(/challenge.*domain/)
  })

  it('signs a DID-Auth-only VP verifiable with Ed25519Signature2020', async () => {
    const vp = await composeVP({
      session,
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN
    })

    expect(vp.holder).toBe(session.user.id)
    expect(vp.verifiableCredential).toBeUndefined()
    const proof = vp.proof as Record<string, unknown>
    expect(proof).toBeDefined()
    expect(proof.proofPurpose).toBe('authentication')
    expect(proof.challenge).toBe(CHALLENGE)
    expect(proof.domain).toBe(DOMAIN)

    const { suite } = presentationSuiteFor({
      signer: session.profile.keyAgent!.getSigner()
    })
    const result = await vc.verify({
      presentation: vp as never,
      challenge: CHALLENGE,
      domain: DOMAIN,
      suite,
      documentLoader
    })
    expect(result.verified).toBe(true)
  })

  it('signs an eddsa-rdfc-2022 VP verifiable as a DataIntegrityProof', async () => {
    const vp = await composeVP({
      session,
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN,
      cryptosuite: EDDSA_RDFC_2022
    })

    const proof = vp.proof as Record<string, unknown>
    expect(proof.type).toBe('DataIntegrityProof')
    expect(proof.cryptosuite).toBe(EDDSA_RDFC_2022)
    expect(proof.proofPurpose).toBe('authentication')

    const { suite } = presentationSuiteFor({
      signer: session.profile.keyAgent!.getSigner(),
      cryptosuite: EDDSA_RDFC_2022
    })
    const result = await vc.verify({
      presentation: vp as never,
      challenge: CHALLENGE,
      domain: DOMAIN,
      suite,
      documentLoader
    })
    expect(result.verified).toBe(true)
  })
})
