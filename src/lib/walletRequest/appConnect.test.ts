// @vitest-environment node
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { CapabilityAgent } from '@interop/capability-agent'
import type { Session } from '@/types/auth'
import type { StoredAppKey, StoredCredential } from '@/types/credential'
import { mintAppKeyCredential } from '@interop/wallet-request'
import {
  AppKeysUnreadableError,
  appConnectZcapRequests,
  processAppConnect
} from './appConnect'
import type { IZcap } from './types'

vi.mock('./processZcaps', () => ({
  processZcaps: vi.fn()
}))
// The real composer, spied on, so a test can tell whether the VP was composed
// when the consent hook ran.
vi.mock('./composeVP', async importOriginal => {
  const actual = await importOriginal<typeof import('./composeVP')>()
  return { ...actual, composeVP: vi.fn(actual.composeVP) }
})
import { attestedRequestOrigin } from './getRequest'
import { composeVP } from './composeVP'
import { processZcaps } from './processZcaps'

const APP = {
  name: 'Text Editor',
  appUrl: 'https://app.example/editor'
}
const ORIGIN = 'https://app.example'
// The `app-keys` Resource id the fake mint store returns.
const MINTED_RESOURCE_ID = 'z1MintedAppKeyResource'
// The Resource id of a stored app key a test lists.
const STORED_RESOURCE_ID = 'z1StoredAppKeyResource'
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
 * dedicated `app-keys` collection the match path reads, `credentials`
 * the user's own credential store, which the match path must never consult.
 * The keyAgent signs the DIDAuth proof.
 */
async function fakeSession({
  appKeys = [],
  credentials = [],
  skipped = {
    unknownEpoch: 0,
    noEpochKey: 0,
    undecryptable: 0,
    integrity: 0,
    plaintext: 0
  }
}: {
  appKeys?: StoredAppKey[]
  credentials?: StoredCredential[]
  skipped?: {
    unknownEpoch: number
    noEpochKey: number
    undecryptable: number
    integrity: number
    plaintext: number
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
      // The mint path stores through its own method, never `addCredential`
      // (which refuses every marker credential).
      addMintedAppKey: async (entry: unknown) => {
        added.push(entry)
        return { resourceId: MINTED_RESOURCE_ID }
      }
    }
  } as unknown as Session
  return { session, added, deleted }
}

beforeEach(() => {
  vi.mocked(composeVP).mockClear()
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
    // The mint store method takes the credential alone: the Resource lands in
    // `app-keys` and no credential-created activity is attributed.
    expect(added).toEqual([{ credential: expect.anything() }])
    const subjectDid = response.appConnect?.subjectDid
    expect(subjectDid).toMatch(/^did:key:/)
    // The delegation used the minted key's DID as the controller.
    const delegated = vi.mocked(processZcaps).mock.calls[0][0]
    expect(delegated.zcapRequests[0].controller).toBe(subjectDid)
    // The App Connect request kind, under which the `#inbox` descriptor is
    // unsatisfiable (the resolver's own tests prove nothing is minted).
    expect(delegated.requestKind).toBe('app-connect')

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
    // The rotation residue: every app-keys Resource sits in an epoch
    // this session holds no wrap for, so "no match" does not mean "never
    // connected" and a mint would orphan the app's prior identity.
    const { session, added } = await fakeSession({
      skipped: {
        unknownEpoch: 0,
        noEpochKey: 1,
        undecryptable: 0,
        integrity: 0,
        plaintext: 0
      }
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
    // session, and a failed fetch is swallowed -- so an unknown-epoch Resource
    // can reach the match path unresolved (the consent preview already spent
    // the refresh before this scan ran).
    const { session, added } = await fakeSession({
      skipped: {
        unknownEpoch: 1,
        noEpochKey: 0,
        undecryptable: 0,
        integrity: 0,
        plaintext: 0
      }
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
      skipped: {
        unknownEpoch: 0,
        noEpochKey: 0,
        undecryptable: 2,
        integrity: 0,
        plaintext: 0
      }
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

  it('refuses to mint when the scan skipped a misbound row', async () => {
    // The one skip a host can produce with no keys at all: it served a body
    // that does not verify against the id it was read under. Treating it as
    // "absent" would let the host force a second identity for the app.
    const { session, added } = await fakeSession({
      skipped: {
        unknownEpoch: 0,
        noEpochKey: 0,
        undecryptable: 0,
        integrity: 1,
        plaintext: 0
      }
    })

    await expect(
      processAppConnect({
        appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
        session,
        origin: ORIGIN,
        challenge: 'challenge-skip-3',
        domain: ORIGIN,
        didAuthRequested: true
      })
    ).rejects.toThrow(AppKeysUnreadableError)
    expect(added).toHaveLength(0)
  })

  it('refuses to mint when the scan skipped a plaintext row', async () => {
    // A body that is not an envelope in the encrypted collection is refused
    // rather than read, so it is skipped like a misbound row. Treating it as
    // "absent" would mint a second identity for the app.
    const { session, added } = await fakeSession({
      skipped: {
        unknownEpoch: 0,
        noEpochKey: 0,
        undecryptable: 0,
        integrity: 0,
        plaintext: 1
      }
    })

    await expect(
      processAppConnect({
        appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
        session,
        origin: ORIGIN,
        challenge: 'challenge-skip-4',
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
    const stored = [
      { cid: 'cid-1', vc: credential, resourceId: STORED_RESOURCE_ID }
    ] as StoredAppKey[]
    const { session, added } = await fakeSession({
      appKeys: stored,
      skipped: {
        unknownEpoch: 1,
        noEpochKey: 1,
        undecryptable: 1,
        integrity: 1,
        plaintext: 1
      }
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
    const stored = [
      { cid: 'cid-1', vc: credential, resourceId: STORED_RESOURCE_ID }
    ] as StoredAppKey[]
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

  it('matches a returning app when the origin arrives with a trailing slash', async () => {
    const { credential, subjectDid } = await mintAppKeyCredential({
      app: APP,
      origin: ORIGIN
    })
    const stored = [
      { cid: 'cid-1', vc: credential, resourceId: STORED_RESOURCE_ID }
    ] as StoredAppKey[]
    const { session, added } = await fakeSession({ appKeys: stored })

    // The raw value goes through the get popup's intake, the one place an
    // origin is canonicalized; the match itself compares exact strings.
    const response = await processAppConnect({
      appConnect: { app: APP, capabilityQueries: [] },
      session,
      origin: attestedRequestOrigin(`${ORIGIN}/`),
      didAuthRequested: false
    })

    expect(response.appConnect).toEqual({ firstRun: false, subjectDid })
    expect(added).toHaveLength(0)
  })

  it('does not recover a key stored for another origin', async () => {
    const { credential } = await mintAppKeyCredential({
      app: APP,
      origin: 'https://phisher.example'
    })
    const stored = [
      { cid: 'cid-1', vc: credential, resourceId: STORED_RESOURCE_ID }
    ] as StoredAppKey[]
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
    const stored = [
      { cid: 'cid-1', vc: credential, resourceId: STORED_RESOURCE_ID }
    ] as StoredAppKey[]
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
    const stored = [
      { cid: 'cid-1', vc: credential, resourceId: STORED_RESOURCE_ID }
    ] as StoredAppKey[]
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
    // A key sitting among the ordinary credentials rather than in
    // `app-keys`, in the exact shape that would match this request:
    // marker type, this `appUrl`, this origin, and a seed that binds its
    // subject. The match path reads `app-keys` only, so it is
    // invisible -- the connect is a genuine first run under a fresh identity,
    // and the stranded Resource is the login-time sweep's business, not this
    // path's.
    const { credential, subjectDid } = await mintAppKeyCredential({
      app: APP,
      origin: ORIGIN
    })
    const stranded = [
      { cid: 'cid-stranded', vc: credential }
    ] as StoredCredential[]
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
    expect(response.appConnect?.subjectDid).toMatch(/^did:key:/)
    expect(response.appConnect?.subjectDid).not.toBe(subjectDid)
    // Minted through the mint store method, and nothing was deleted from the
    // credential store on this path.
    expect(added).toHaveLength(1)
    expect(added[0]).not.toEqual({ credential })
    expect(deleted).toEqual([])
    const presentation = response.verifiablePresentation as {
      verifiableCredential?: Array<{
        id?: string
        credentialSubject: { id: string; appUrl?: string }
      }>
    }
    expect(presentation.verifiableCredential?.[0].id).not.toBe(credential.id)
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

  describe('the consent hook', () => {
    /**
     * Records each `beforeProvision` call with whether the VP was composed
     * by then.
     *
     * @returns {object}   the hook and its recorded calls
     */
    function recordingHook(): {
      calls: Array<{
        zcaps: IZcap[]
        shareZcapIds: string[]
        appConnect: { firstRun: boolean; subjectDid: string; appKey: string }
        composedBefore: boolean
      }>
      beforeProvision: Parameters<
        typeof processAppConnect
      >[0]['beforeProvision']
    } {
      const calls: ReturnType<typeof recordingHook>['calls'] = []
      return {
        calls,
        beforeProvision: async options => {
          calls.push({
            ...options,
            composedBefore: vi.mocked(composeVP).mock.calls.length > 0
          })
        }
      }
    }

    it('runs once on a zero-grant first run, before compose, naming the minted key', async () => {
      const { session } = await fakeSession()
      const hook = recordingHook()
      const response = await processAppConnect({
        appConnect: { app: APP, capabilityQueries: [] },
        session,
        origin: ORIGIN,
        didAuthRequested: false,
        beforeProvision: hook.beforeProvision
      })
      expect(hook.calls).toEqual([
        {
          zcaps: [],
          shareZcapIds: [],
          appConnect: {
            firstRun: true,
            subjectDid: response.appConnect?.subjectDid,
            appKey: MINTED_RESOURCE_ID
          },
          composedBefore: false
        }
      ])
      expect(composeVP).toHaveBeenCalledTimes(1)
    })

    it("names a returning app's stored key Resource", async () => {
      const { credential, subjectDid } = await mintAppKeyCredential({
        app: APP,
        origin: ORIGIN
      })
      const stored = [
        { cid: 'cid-1', vc: credential, resourceId: STORED_RESOURCE_ID }
      ] as StoredAppKey[]
      const { session } = await fakeSession({ appKeys: stored })
      const hook = recordingHook()
      await processAppConnect({
        appConnect: { app: APP, capabilityQueries: [] },
        session,
        origin: ORIGIN,
        didAuthRequested: false,
        beforeProvision: hook.beforeProvision
      })
      expect(hook.calls).toHaveLength(1)
      expect(hook.calls[0].appConnect).toEqual({
        firstRun: false,
        subjectDid,
        appKey: STORED_RESOURCE_ID
      })
    })

    it('runs once, from inside processZcaps, when a grant needs escrow', async () => {
      const shareZcap = { id: 'urn:zcap:delegated:share' } as IZcap
      vi.mocked(processZcaps).mockImplementation(
        async ({ beforeProvision }) => {
          await beforeProvision?.({
            zcaps: [shareZcap],
            shareZcapIds: [shareZcap.id]
          })
          return [shareZcap]
        }
      )
      const { session } = await fakeSession()
      const hook = recordingHook()
      await processAppConnect({
        appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
        session,
        origin: ORIGIN,
        didAuthRequested: false,
        beforeProvision: hook.beforeProvision
      })
      expect(hook.calls).toHaveLength(1)
      expect(hook.calls[0]).toMatchObject({
        zcaps: [shareZcap],
        shareZcapIds: [shareZcap.id],
        appConnect: { firstRun: true, appKey: MINTED_RESOURCE_ID },
        composedBefore: false
      })
    })

    it('runs once after delegation when no grant needs escrow', async () => {
      const { session } = await fakeSession()
      const hook = recordingHook()
      await processAppConnect({
        appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
        session,
        origin: ORIGIN,
        didAuthRequested: false,
        beforeProvision: hook.beforeProvision
      })
      // The mocked processZcaps never calls the hook, as on grants over
      // collections that stand.
      expect(hook.calls).toHaveLength(1)
      expect(hook.calls[0]).toMatchObject({
        zcaps: [{ id: 'urn:zcap:delegated:test' }],
        shareZcapIds: [],
        composedBefore: false
      })
    })

    it('composes nothing when the hook throws', async () => {
      const { session } = await fakeSession()
      await expect(
        processAppConnect({
          appConnect: { app: APP, capabilityQueries: [] },
          session,
          origin: ORIGIN,
          didAuthRequested: false,
          beforeProvision: async () => {
            throw new Error('entry write failed')
          }
        })
      ).rejects.toThrow('entry write failed')
      expect(composeVP).not.toHaveBeenCalled()
    })

    it('threads onEscrowed to processZcaps', async () => {
      const { session } = await fakeSession()
      const onEscrowed = vi.fn()
      await processAppConnect({
        appConnect: { app: APP, capabilityQueries: [CAPABILITY_QUERY] },
        session,
        origin: ORIGIN,
        didAuthRequested: false,
        onEscrowed
      })
      expect(vi.mocked(processZcaps).mock.calls[0][0].onEscrowed).toBe(
        onEscrowed
      )
    })
  })
})
