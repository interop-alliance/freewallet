// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import type { Session } from '@/types/auth'
import {
  inMemorySessionPersistence,
  transientSessionStores
} from '@/session/persistence'
import { composeVP } from './composeVP'

/**
 * Signing-path tests for the App Connect response marker: the `appConnect`
 * member is defined by the hosted App Connect context appended to the VP
 * `@context`, and the DIDAuth proof must canonicalize (safe mode) and cover it
 * rather than reject it.
 *
 * Plus the transient session's response identity (FW-203, over
 * app-connect-spec `decisions/0004`): the VP's `holder` and its DIDAuth
 * `proof.verificationMethod` are the visit key's BARE did:key forms. The
 * `<clientAnnexDid>#<vm>` form belongs to WAS invocations alone, and the
 * app-side loader has to be able to resolve what it reads here.
 */

const CHALLENGE = 'test-challenge-123'
const DOMAIN = 'https://app.example'
const APP_CONNECT_CONTEXT_URL = 'https://w3id.org/byoe/app-connect/v1'

let session: Session

beforeAll(async () => {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret: new Uint8Array(32).fill(7),
    handle: 'test'
  })
  session = {
    user: { id: keyAgent.id },
    profile: { keyAgent }
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
    expect(contexts).toContain(APP_CONNECT_CONTEXT_URL)
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
    expect(contexts).not.toContain(APP_CONNECT_CONTEXT_URL)
  })
})

describe('composeVP from a transient session', () => {
  const CLIENT_ANNEX_DID = 'did:webvh:QmAnnexScid:example.com:annex-space:id'
  let transient: Session

  beforeAll(async () => {
    const keyAgent = await CapabilityAgent.fromSecret({
      secret: new Uint8Array(32).fill(9),
      handle: 'transient-visit'
    })
    // The shape `transientSessionFromKeyringHit` assembles: a per-visit key
    // agent, the annex identity declared on the persistence strategy (rather
    // than on the profile's signing identity), and no KMS keystore -- so the
    // did:web arm of `presentationSignerFor` is structurally out of reach.
    transient = {
      user: { id: keyAgent.id },
      profile: {
        keyAgent,
        persistence: inMemorySessionPersistence({
          stores: transientSessionStores(),
          clientAnnex: {
            clientAnnexDid: CLIENT_ANNEX_DID,
            invocationCapability: { id: 'urn:zcap:generation' } as never
          }
        })
      }
    } as unknown as Session
  })

  it("holds and signs as the visit key's bare did:key, not the annex form", async () => {
    const presentation = (await composeVP({
      session: transient,
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN,
      appConnect: { firstRun: true }
    })) as {
      holder?: string
      proof?: { verificationMethod?: string }
    }

    expect(presentation.holder).toBe(transient.user.id)
    expect(transient.user.id.startsWith('did:key:')).toBe(true)
    const verificationMethod = presentation.proof?.verificationMethod ?? ''
    expect(verificationMethod.startsWith(`${transient.user.id}#`)).toBe(true)
    expect(presentation.holder).not.toContain(CLIENT_ANNEX_DID)
    expect(verificationMethod).not.toContain(CLIENT_ANNEX_DID)
  })
})
