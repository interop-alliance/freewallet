// @vitest-environment node
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { CapabilityAgent } from '@interop/webkms-client'
import type { Session } from '@/types/auth'
import type { StoredCredential } from '@/types/credential'
import { mintAppKeyCredential } from '@interop/wallet-core/request'
import {
  AppKeysUnreadableError,
  appConnectZcapRequests,
  processAppConnect
} from './appConnect'
import type { IZcap } from './types'

vi.mock('./processZcaps', () => ({
  processZcaps: vi.fn()
}))
import { processZcaps } from './processZcaps'

const APP = {
  name: 'Text Editor',
  appUrl: 'https://app.example/editor'
}
const ORIGIN = 'https://app.example'
const CAPABILITY_QUERY = {
  referenceId: 'text-editor-document',
  allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
  invocationTarget: {
    type: 'https://w3id.org/byoe#private-collection',
    name: 'text-editor-document'
  }
}

/**
 * A minimal session whose storage records added app keys and lists a
 * caller-provided set. Two listings, deliberately distinct: `appKeys` is the
 * dedicated `app-connections` collection the match path reads, `credentials`
 * the user's own credential store, which the match path must never consult.
 * The keyAgent signs the DIDAuth proof.
 */
async function fakeSession({
  appKeys = [],
  credentials = [],
  skipped = { unknownEpoch: 0, noEpochKey: 0, undecryptable: 0 }
}: {
  appKeys?: StoredCredential[]
  credentials?: StoredCredential[]
  skipped?: {
    unknownEpoch: number
    noEpochKey: number
    undecryptable: number
  }
} = {}): Promise<{ session: Session; added: unknown[]; deleted: string[] }> {
  const keyAgent = await CapabilityAgent.fromSecret({
    secret: new Uint8Array(32).fill(9),
    handle: 'test'
  })
  const added: unknown[] = []
  const deleted: string[] = []
  const session = {
    user: { id: keyAgent.id },
    profile: { keyAgent },
    storage: {
      listAppKeys: async () => ({ appKeys, skipped }),
      listCredentials: async () => credentials,
      deleteCredential: async ({ cid }: { cid: string }) => {
        deleted.push(cid)
      },
      // The mint path stores through its own door, never `addCredential`
      // (which refuses every marker credential).
      addMintedAppKey: async (entry: unknown) => {
        added.push(entry)
      }
    }
  } as unknown as Session
  return { session, added, deleted }
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
    // The mint door takes the credential alone: the row lands in
    // `app-connections` and no credential-created activity is attributed.
    expect(added).toEqual([{ credential: expect.anything() }])
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

  it('refuses to mint when the scan skipped no-epoch-key rows', async () => {
    // The rotation residue: every app-connections row sits in an epoch this
    // session holds no wrap for, so "no match" does not mean "never
    // connected" and a mint would orphan the app's prior identity.
    const { session, added } = await fakeSession({
      skipped: { unknownEpoch: 0, noEpochKey: 1, undecryptable: 0 }
    })

    await expect(
      processAppConnect({
        appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
        session,
        origin: ORIGIN,
        challenge: 'challenge-skip-1',
        domain: ORIGIN,
        didAuthRequested: true
      })
    ).rejects.toThrow(AppKeysUnreadableError)
    expect(added).toHaveLength(0)
  })

  it('refuses to mint when rows are still unknown-epoch after the refresh', async () => {
    // The facade spends at most one descriptor refresh per collection per
    // session, and a failed fetch is swallowed -- so an unknown-epoch row can
    // reach the match path unresolved (the consent preview already spent the
    // refresh before this scan ran).
    const { session, added } = await fakeSession({
      skipped: { unknownEpoch: 1, noEpochKey: 0, undecryptable: 0 }
    })

    await expect(
      processAppConnect({
        appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
        session,
        origin: ORIGIN,
        challenge: 'challenge-skip-0',
        domain: ORIGIN,
        didAuthRequested: true
      })
    ).rejects.toThrow(AppKeysUnreadableError)
    expect(added).toHaveLength(0)
  })

  it('refuses to mint when the scan skipped undecryptable rows', async () => {
    const { session, added } = await fakeSession({
      skipped: { unknownEpoch: 0, noEpochKey: 0, undecryptable: 2 }
    })

    await expect(
      processAppConnect({
        appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
        session,
        origin: ORIGIN,
        challenge: 'challenge-skip-2',
        domain: ORIGIN,
        didAuthRequested: true
      })
    ).rejects.toThrow(AppKeysUnreadableError)
    expect(added).toHaveLength(0)
  })

  it('serves a match found despite skipped rows', async () => {
    const { credential, subjectDid } = await mintAppKeyCredential({
      app: APP,
      origin: ORIGIN
    })
    const stored = [{ cid: 'cid-1', vc: credential }] as StoredCredential[]
    const { session, added } = await fakeSession({
      appKeys: stored,
      skipped: { unknownEpoch: 1, noEpochKey: 1, undecryptable: 1 }
    })

    const response = await processAppConnect({
      appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
      session,
      origin: ORIGIN,
      challenge: 'challenge-skip-3',
      domain: ORIGIN,
      didAuthRequested: true
    })

    expect(response.appConnect).toEqual({ firstRun: false, subjectDid })
    expect(added).toHaveLength(0)
  })

  it('returns the stored app key without minting on a match', async () => {
    const { credential, subjectDid } = await mintAppKeyCredential({
      app: APP,
      origin: ORIGIN
    })
    const stored = [{ cid: 'cid-1', vc: credential }] as StoredCredential[]
    const { session, added } = await fakeSession({ appKeys: stored })

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
    const { session, added } = await fakeSession({ appKeys: stored })

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

  it('delegates to the previewed DID when the match is unchanged', async () => {
    const { credential, subjectDid } = await mintAppKeyCredential({
      app: APP,
      origin: ORIGIN
    })
    const stored = [{ cid: 'cid-1', vc: credential }] as StoredCredential[]
    const { session } = await fakeSession({ appKeys: stored })

    const response = await processAppConnect({
      appConnect: { app: APP, capabilityQueries: [] },
      session,
      origin: ORIGIN,
      didAuthRequested: false,
      expectedSubjectDid: subjectDid
    })
    expect(response.appConnect).toEqual({ firstRun: false, subjectDid })
  })

  it('fails closed when the matched DID diverges from the previewed one', async () => {
    // The credential the consent screen previewed was deleted (or superseded)
    // between preview and approval: the approve-time re-match resolves a
    // different subject DID, and the delegation must not silently go to a
    // recipient the user never saw.
    const { credential } = await mintAppKeyCredential({
      app: APP,
      origin: ORIGIN
    })
    const stored = [{ cid: 'cid-1', vc: credential }] as StoredCredential[]
    const { session } = await fakeSession({ appKeys: stored })

    await expect(
      processAppConnect({
        appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
        session,
        origin: ORIGIN,
        didAuthRequested: false,
        expectedSubjectDid: 'did:key:z6MkPreviewedElsewhere'
      })
    ).rejects.toThrow(/changed between consent and approval/)
    expect(processZcaps).not.toHaveBeenCalled()
  })

  it('never finds an app key left in the credential store', async () => {
    // A key from before app keys got their own collection, in the shape the
    // dropped re-issue path used to recover: same origin, no
    // `credentialSubject.appUrl` claim, sitting among the ordinary
    // credentials. The match path reads `app-connections` only, so it is
    // invisible -- the connect is a genuine first run under a fresh identity,
    // and the stranded row is the login-time sweep's business, not this
    // path's.
    const { credential, subjectDid } = await mintAppKeyCredential({
      app: APP,
      origin: ORIGIN
    })
    const legacy = {
      ...credential,
      credentialSubject: { ...credential.credentialSubject }
    } as typeof credential
    delete (legacy.credentialSubject as { appUrl?: unknown }).appUrl
    const stranded = [{ cid: 'cid-legacy', vc: legacy }] as StoredCredential[]
    const { session, added, deleted } = await fakeSession({
      credentials: stranded
    })

    const response = await processAppConnect({
      appConnect: { app: APP, capabilityQueries: [] },
      session,
      origin: ORIGIN,
      didAuthRequested: false
    })

    expect(response.appConnect?.firstRun).toBe(true)
    expect(response.appConnect?.subjectDid).not.toBe(subjectDid)
    // Minted through the mint door, and nothing was deleted from the
    // credential store on this path.
    expect(added).toHaveLength(1)
    expect(deleted).toEqual([])
    const presentation = response.verifiablePresentation as {
      verifiableCredential?: Array<{
        credentialSubject: { id: string; appUrl?: string }
      }>
    }
    expect(presentation.verifiableCredential?.[0].credentialSubject).toEqual(
      expect.objectContaining({
        id: response.appConnect?.subjectDid,
        appUrl: APP.appUrl
      })
    )
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
