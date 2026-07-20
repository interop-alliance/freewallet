// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import type { Session } from '@/types/auth'
import { composeVP } from './composeVP'

/**
 * Signing-path tests for the App Connect response marker: the `appConnect`
 * member is a JSON literal term added to the VP `@context`, and the DIDAuth
 * proof must canonicalize (safe mode) and cover it rather than reject it.
 */

const CHALLENGE = 'test-challenge-123'
const DOMAIN = 'https://app.example'

let session: Session

beforeAll(async () => {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret: new Uint8Array(32).fill(7),
    handle: 'test'
  })
  session = {
    user: { id: keyAgent.id },
    profile: { keyAgent },
    tier: 'full'
  } as unknown as Session
})

describe('composeVP with an appConnect marker', () => {
  it('embeds the marker and its context term on a signed VP', async () => {
    const presentation = (await composeVP({
      session,
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN,
      appConnect: { firstRun: true }
    })) as { appConnect?: unknown; '@context': unknown; proof?: unknown }

    expect(presentation.appConnect).toEqual({ firstRun: true })
    const contexts = presentation['@context'] as Array<string | object>
    expect(
      contexts.some(
        entry =>
          typeof entry === 'object' &&
          'appConnect' in (entry as Record<string, unknown>)
      )
    ).toBe(true)
    expect(presentation.proof).toBeDefined()
  })

  it('embeds the marker on an unsigned VP', async () => {
    const presentation = (await composeVP({
      session,
      didAuthRequested: false,
      selectedVCs: [
        {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential'],
          issuer: session.user.id,
          credentialSubject: { id: session.user.id }
        } as never
      ],
      appConnect: { firstRun: false }
    })) as { appConnect?: unknown; proof?: unknown }

    expect(presentation.appConnect).toEqual({ firstRun: false })
    expect(presentation.proof).toBeUndefined()
  })

  it('omits the marker and term when appConnect is absent', async () => {
    const presentation = (await composeVP({
      session,
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN
    })) as { appConnect?: unknown; '@context': unknown }

    expect(presentation.appConnect).toBeUndefined()
    const contexts = presentation['@context'] as Array<string | object>
    expect(
      contexts.every(
        entry =>
          typeof entry !== 'object' ||
          !('appConnect' in (entry as Record<string, unknown>))
      )
    ).toBe(true)
  })
})
