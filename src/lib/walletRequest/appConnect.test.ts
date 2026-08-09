// @vitest-environment node
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import type { Session } from '@/types/auth'
import type { StoredCredential } from '@/types/credential'
import { mintAppKeyCredential } from '@/lib/appKey'
import { appConnectZcapRequests, processAppConnect } from './appConnect'
import type { IAppConnectCapabilityQuery, IZcap } from './types'

vi.mock('./processZcaps', () => ({
  processZcaps: vi.fn()
}))
import { processZcaps } from './processZcaps'

const APP = {
  name: 'Text Editor',
  credentialType: 'TextEditorAppKey',
  vocabBase: 'urn:text-editor:vocab#'
}
const ORIGIN = 'https://app.example'
const CAPABILITY_QUERY = {
  referenceId: 'text-editor-document',
  allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
  invocationTarget: {
    type: 'https://w3id.org/byoe#collection',
    name: 'text-editor-document'
  }
}

/**
 * A minimal session whose storage records added credentials and
 * lists a caller-provided set. The keyAgent signs the DIDAuth proof.
 */
async function fakeSession({
  stored = []
}: {
  stored?: StoredCredential[]
} = {}): Promise<{ session: Session; added: unknown[] }> {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret: new Uint8Array(32).fill(9),
    handle: 'test'
  })
  const added: unknown[] = []
  const session = {
    user: { id: keyAgent.id },
    profile: { keyAgent },
    storage: {
      listCredentials: async () => stored,
      // The mint path stores through its own door, never `addCredential`
      // (which refuses every marker credential).
      addMintedAppKey: async (entry: unknown) => {
        added.push(entry)
      }
    }
  } as unknown as Session
  return { session, added }
}

beforeEach(() => {
  vi.mocked(processZcaps).mockReset()
  vi.mocked(processZcaps).mockResolvedValue([
    { id: 'urn:zcap:delegated:test' } as IZcap
  ])
})

describe('appConnectZcapRequests', () => {
  it('fills the controller on every capability query', () => {
    const requests = appConnectZcapRequests({
      capabilityQueries: [CAPABILITY_QUERY],
      controller: 'did:key:z6MkTest'
    })
    expect(requests).toEqual([
      { ...CAPABILITY_QUERY, controller: 'did:key:z6MkTest' }
    ])
  })

  it('strips a wire-level reason the type-level Omit cannot block', () => {
    // The type omits `reason`, but an actual request body can carry it
    // anyway; it must never reach the App Connect consent screen.
    const smuggled = {
      ...CAPABILITY_QUERY,
      reason: 'Totally legitimate reason from the requesting site'
    } as IAppConnectCapabilityQuery
    const requests = appConnectZcapRequests({
      capabilityQueries: [smuggled],
      controller: 'did:key:z6MkTest'
    })
    expect(requests).toEqual([
      { ...CAPABILITY_QUERY, controller: 'did:key:z6MkTest' }
    ])
    expect(requests[0]).not.toHaveProperty('reason')
  })
})

describe('processAppConnect', () => {
  it('mints, stores, delegates, and marks firstRun on no match', async () => {
    const { session, added } = await fakeSession()
    const response = await processAppConnect({
      appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
      session,
      origin: ORIGIN,
      challenge: 'challenge-1',
      domain: ORIGIN,
      didAuthRequested: true
    })

    expect(response.appConnect?.firstRun).toBe(true)
    expect(added).toHaveLength(1)
    const subjectDid = response.appConnect?.subjectDid
    expect(subjectDid).toMatch(/^did:key:/)
    // The delegation used the minted key's DID as the controller.
    const delegated = vi.mocked(processZcaps).mock.calls[0][0]
    expect(delegated.zcapRequests[0].controller).toBe(subjectDid)

    const presentation = response.verifiablePresentation as {
      appConnect?: unknown
      verifiableCredential?: unknown[]
      zcap?: unknown[]
    }
    expect(presentation.appConnect).toEqual({ firstRun: true })
    expect(presentation.verifiableCredential).toHaveLength(1)
    expect(presentation.zcap).toEqual([{ id: 'urn:zcap:delegated:test' }])
  })

  it('returns the stored app key without minting on a match', async () => {
    const { credential, subjectDid } = await mintAppKeyCredential({
      app: APP,
      origin: ORIGIN
    })
    const stored = [{ cid: 'cid-1', vc: credential }] as StoredCredential[]
    const { session, added } = await fakeSession({ stored })

    const response = await processAppConnect({
      appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
      session,
      origin: ORIGIN,
      challenge: 'challenge-2',
      domain: ORIGIN,
      didAuthRequested: true
    })

    expect(response.appConnect).toEqual({ firstRun: false, subjectDid })
    expect(added).toHaveLength(0)
    const presentation = response.verifiablePresentation as {
      appConnect?: unknown
      verifiableCredential?: Array<{ credentialSubject: { id: string } }>
    }
    expect(presentation.appConnect).toEqual({ firstRun: false })
    expect(presentation.verifiableCredential?.[0].credentialSubject.id).toBe(
      subjectDid
    )
  })

  it('does not recover a key stored for another origin', async () => {
    const { credential } = await mintAppKeyCredential({
      app: APP,
      origin: 'https://phisher.example'
    })
    const stored = [{ cid: 'cid-1', vc: credential }] as StoredCredential[]
    const { session, added } = await fakeSession({ stored })

    const response = await processAppConnect({
      appConnect: { app: APP, capabilityQueries: [] },
      session,
      origin: ORIGIN,
      didAuthRequested: false
    })

    // A fresh key is minted for this origin rather than handing over the
    // other origin's key.
    expect(response.appConnect?.firstRun).toBe(true)
    expect(added).toHaveLength(1)
  })

  it('skips delegation when no capabilities were requested', async () => {
    const { session } = await fakeSession()
    const response = await processAppConnect({
      appConnect: { app: APP, capabilityQueries: [] },
      session,
      origin: ORIGIN,
      didAuthRequested: false
    })
    expect(processZcaps).not.toHaveBeenCalled()
    expect(response.zcaps).toEqual([])
    expect(response.appConnect?.firstRun).toBe(true)
  })
})
