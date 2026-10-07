// @vitest-environment node
/**
 * Unit tests for the CHAPI `get` response sequence
 * (`src/lib/walletRequest/respond.ts`).
 *
 * - The consent is recorded before anything is escrowed or delivered: first
 *   the party's `connections` entry carrying the grants, then the request's
 *   activity (a Grant for an App Connect connection or a capability request,
 *   a plain Login for a DIDAuth-only request).
 * - A failed entry write fails closed, with no Grant row, no escrow, and no
 *   delivery. A failure after it and before delivery removes this request's
 *   grants whose escrow did not land. When none escrowed, the Grant row goes
 *   too, and an entry that was absent or retired before the consent is
 *   retired again. When one escrowed, the Grant row and a live entry stay.
 * - An entry of another kind at the party's id refuses the consent, and the
 *   stored entry is left as it was.
 * - The typed failure reasons the popup renders.
 * - A connection request's pairwise seed: minted or reused once its tag
 *   verifies, written with the grants on either record path, refused when
 *   its tag fails or a concurrent consent wrote another, and kept by a
 *   rollback.
 *
 * `processRequest` and the exchange delivery are mocked. The directory logic
 * is wallet-core's own, over an in-memory store.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { base64urlnopad } from '@scure/base'
import {
  connectionDidKey,
  connectionResourceId,
  connectionSeedTag,
  readConnections,
  recordGrants,
  retireConnection,
  verifyConnectionSeedTag
} from '@interop/wallet-core/connections'
import type { ConnectionsStore } from '@interop/wallet-core/connections'
import type { StorageManager } from '@/stores/storageManager'
import { listConnectedAgents, listConnectedApps } from '@/lib/connectedApps'
import { HMAC_KEY, memoryConnectionsStore } from '../memoryConnections'
import { captureCeremonyEvents } from '../ceremonyEventCapture'

const SPACE_URL = 'https://was.example/space/s/'
const AGENT = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const APP_DID = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
const APP_KEY = 'z1AppKeyResource'
const FUTURE = '2099-01-01T00:00:00.000Z'

type TestZcap = {
  id: string
  invocationTarget: string
  controller: string
  parentCapability?: string
  allowedAction?: string[]
  expires?: string
}

const state = vi.hoisted(() => ({
  calls: [] as string[],
  zcaps: [] as unknown[],
  shareZcapIds: [] as string[],
  processThrows: null as Error | null,
  historyThrows: false,
  deleteThrows: false,
  deliverThrows: false,
  appConnectResult: undefined as
    { firstRun: boolean; subjectDid: string; appKey: string } | undefined,
  // When set, the mocked `processRequest` stands in for a request whose
  // grants need escrow: it awaits the `beforeProvision` hook, then runs the
  // escrow steps in order, reporting each one that lands.
  provisions: false,
  // The escrow steps. Empty means one step covering every grant, which
  // throws `provisionThrows` when that is set.
  escrows: [] as Array<{ zcapIds: string[]; throws?: Error }>,
  provisionThrows: null as Error | null,
  // The holder of the pairwise signer `processRequest` was handed, if any.
  pairwiseHolder: undefined as string | undefined,
  // Run inside `processRequest`, after the seed is resolved and before any
  // record: stands in for a concurrent consent.
  duringProcess: null as (() => Promise<void>) | null
}))

const { FakeZcapUnavailableError } = vi.hoisted(() => ({
  FakeZcapUnavailableError: class FakeZcapUnavailableError extends Error {}
}))

vi.mock('@/lib/walletRequest/processZcaps', () => ({
  ZcapUnavailableError: FakeZcapUnavailableError
}))

vi.mock('@/lib/walletRequest/processRequest', () => ({
  processRequest: vi.fn(
    async ({
      beforeProvision,
      onEscrowed,
      pairwiseSigner
    }: {
      pairwiseSigner?: { holder: string }
      beforeProvision?: (options: {
        zcaps: unknown[]
        shareZcapIds: string[]
        appConnect?: { firstRun: boolean; subjectDid: string; appKey: string }
      }) => Promise<void>
      onEscrowed?: (options: { zcapIds: string[] }) => void
    }) => {
      state.calls.push('processRequest')
      state.pairwiseHolder = pairwiseSigner?.holder
      await state.duringProcess?.()
      if (state.processThrows) {
        throw state.processThrows
      }
      // App Connect runs the hook on every connect, a zero-grant one
      // included; the standalone path only when a grant needs escrow.
      if (state.provisions || state.appConnectResult) {
        await beforeProvision?.({
          zcaps: state.zcaps,
          shareZcapIds: state.shareZcapIds,
          ...(state.appConnectResult && {
            appConnect: state.appConnectResult
          })
        })
      }
      if (state.provisions) {
        const steps =
          state.escrows.length > 0
            ? state.escrows
            : [
                {
                  zcapIds: (state.zcaps as Array<{ id: string }>).map(
                    zcap => zcap.id
                  ),
                  throws: state.provisionThrows ?? undefined
                }
              ]
        for (const step of steps) {
          state.calls.push(`escrow:${step.zcapIds.join(',')}`)
          if (step.throws) {
            throw step.throws
          }
          onEscrowed?.({ zcapIds: step.zcapIds })
        }
      }
      return {
        verifiablePresentation: { type: 'VerifiablePresentation' },
        zcaps: state.zcaps,
        ...(state.appConnectResult && {
          appConnect: {
            firstRun: state.appConnectResult.firstRun,
            subjectDid: state.appConnectResult.subjectDid
          }
        })
      }
    }
  )
}))

vi.mock('@/lib/walletRequest/vcApiExchange', () => ({
  deliverPresentation: vi.fn(async () => {
    state.calls.push('deliverPresentation')
    if (state.deliverThrows) {
      throw new Error('exchange down')
    }
  })
}))

const { composeAndDeliverResponse, WalletResponseFailure } =
  await import('@/lib/walletRequest/respond')
const { EXTERNAL_REQUEST_ORIGIN } =
  await import('@/lib/walletRequest/externalRequest')

type RespondProfile = Parameters<typeof composeAndDeliverResponse>[0]['profile']
type RespondSession = Parameters<typeof composeAndDeliverResponse>[0]['session']

const profile = {
  didAuth: true,
  vcQueries: [],
  zcapRequests: [],
  appConnect: null
} as unknown as RespondProfile

// An interaction-URL request: a standalone capability query, no App Connect.
const agentProfile = {
  didAuth: false,
  vcQueries: [],
  zcapRequests: [{ referenceId: 'agent-data', controller: AGENT }],
  appConnect: null,
  agent: { name: 'research-bot' }
} as unknown as RespondProfile

/**
 * An App Connect request for the "Text Editor" app.
 *
 * @param options {object}
 * @param [options.name] {string}   the app's self-declared name
 * @returns {RespondProfile}
 */
function appConnectProfile({
  name = 'Text Editor'
}: { name?: string } = {}): RespondProfile {
  return {
    didAuth: true,
    vcQueries: [],
    zcapRequests: [],
    appConnect: {
      app: { name, appUrl: 'https://app.example/editor' },
      capabilityQueries: []
    }
  } as unknown as RespondProfile
}

/**
 * A grant delegated to `controller` on one collection of the Space.
 *
 * @param options {object}
 * @param options.id {string}
 * @param [options.controller] {string}
 * @param [options.collection] {string}
 * @returns {TestZcap}
 */
function grant({
  id,
  controller = AGENT,
  collection = 'agent-data'
}: {
  id: string
  controller?: string
  collection?: string
}): TestZcap {
  return {
    id,
    invocationTarget: `${SPACE_URL}${collection}/`,
    parentCapability: `urn:zcap:root:${encodeURIComponent(SPACE_URL)}`,
    controller,
    allowedAction: ['GET', 'HEAD'],
    expires: FUTURE
  }
}

let directory: ReturnType<typeof memoryConnectionsStore>
// The directory's container URL as the session reports it; `undefined` on
// a guest or no-WAS session.
let directorySpaceUrl: string | undefined
// Every directory put from this ordinal on (1-based) fails.
let entryThrowsFrom: number | null
// The directory put at this ordinal (1-based) lands, then its response is
// lost and the call throws.
let entryLandsThenThrowsAt: number | null

/**
 * The in-memory directory store, recording each put in `state.calls`,
 * failing the puts `entryThrowsFrom` names, and losing the response of the
 * put `entryLandsThenThrowsAt` names.
 *
 * @returns {ConnectionsStore}
 */
function recordingStore(): ConnectionsStore {
  let puts = 0
  return {
    ...directory.store,
    async put(options) {
      puts += 1
      state.calls.push('entryWrite')
      if (entryThrowsFrom !== null && puts >= entryThrowsFrom) {
        throw new Error('directory write failed')
      }
      if (puts === entryLandsThenThrowsAt) {
        await directory.store.put(options)
        throw new Error('directory write response lost')
      }
      return directory.store.put(options)
    }
  }
}

/**
 * A session whose storage records each history call and hands out the
 * in-memory directory.
 *
 * @returns {RespondSession}
 */
function makeSession(): RespondSession {
  const store = recordingStore()
  return {
    user: { id: 'did:key:zUser' },
    storage: {
      connectionsDirectory: vi.fn(async () => ({
        store,
        hmacKey: HMAC_KEY,
        ...(directorySpaceUrl !== undefined && { spaceUrl: directorySpaceUrl })
      })),
      addHistoryLogin: vi.fn(async () => {
        state.calls.push('addHistoryLogin')
        if (state.historyThrows) {
          throw new Error('history write failed')
        }
        return 'login-1'
      }),
      addHistoryGrant: vi.fn(async () => {
        state.calls.push('addHistoryGrant')
        if (state.historyThrows) {
          throw new Error('history write failed')
        }
        return 'grant-1'
      }),
      deleteHistoryActivity: vi.fn(async () => {
        state.calls.push('deleteHistoryActivity')
        if (state.deleteThrows) {
          throw new Error('history delete failed')
        }
      })
    }
  } as unknown as RespondSession
}

/**
 * Runs the response sequence.
 *
 * @param options {object}
 * @param [options.exchangeUrl] {string}
 * @param [options.session] {RespondSession}
 * @param [options.requestProfile] {RespondProfile}
 * @param [options.requestOrigin] {string}
 * @param [options.delegateStandaloneZcaps] {boolean}
 * @param [options.requestKind] {'interaction-url' | 'connection-request'}
 * @returns {Promise<object>}   the composed response
 */
async function respond({
  exchangeUrl,
  session = makeSession(),
  requestProfile = profile,
  requestOrigin = 'https://app.example',
  delegateStandaloneZcaps,
  requestKind
}: {
  exchangeUrl?: string
  session?: RespondSession
  requestProfile?: RespondProfile
  requestOrigin?: string
  delegateStandaloneZcaps?: boolean
  requestKind?: 'interaction-url' | 'connection-request'
} = {}) {
  return composeAndDeliverResponse({
    request: { query: [] } as unknown as Parameters<
      typeof composeAndDeliverResponse
    >[0]['request'],
    session,
    profile: requestProfile,
    requestOrigin,
    selectedVCs: [],
    exchangeUrl,
    ...(delegateStandaloneZcaps !== undefined && { delegateStandaloneZcaps }),
    ...(requestKind !== undefined && { requestKind })
  })
}

/**
 * The stored entry body at a party's id, or `undefined`.
 *
 * @param options {object}
 * @param options.did {string}
 * @returns {Promise<Record<string, unknown> | undefined>}
 */
async function storedEntry({
  did
}: {
  did: string
}): Promise<Record<string, unknown> | undefined> {
  const resourceId = await connectionResourceId({ hmacKey: HMAC_KEY, did })
  return directory.rows.get(resourceId)?.body as
    Record<string, unknown> | undefined
}

/**
 * The capability ids recorded on a party's entry, with their grant kinds.
 *
 * @param options {object}
 * @param options.did {string}
 * @returns {Promise<Array<{ id: string; grantKind: string }>>}
 */
async function recordedGrants({
  did
}: {
  did: string
}): Promise<Array<{ id: string; grantKind: string }>> {
  const entry = await storedEntry({ did })
  const grants = (entry?.grants ?? []) as Array<{
    zcap: { id: string }
    grantKind: string
  }>
  return grants.map(({ zcap, grantKind }) => ({ id: zcap.id, grantKind }))
}

beforeEach(() => {
  state.calls = []
  state.zcaps = []
  state.shareZcapIds = []
  state.processThrows = null
  state.historyThrows = false
  state.deleteThrows = false
  state.deliverThrows = false
  state.appConnectResult = undefined
  state.provisions = false
  state.escrows = []
  state.provisionThrows = null
  state.pairwiseHolder = undefined
  state.duringProcess = null
  directory = memoryConnectionsStore()
  directorySpaceUrl = SPACE_URL
  entryThrowsFrom = null
  entryLandsThenThrowsAt = null
})

describe('composeAndDeliverResponse', () => {
  it('persists the Login activity before delivering to the exchange', async () => {
    await respond({ exchangeUrl: 'https://verifier.example/exchange/1' })
    // A plain DID Auth names no party, so no entry is written.
    expect(state.calls).toEqual([
      'processRequest',
      'addHistoryLogin',
      'deliverPresentation'
    ])
    expect(directory.rows.size).toBe(0)
  })

  it('still responds when the history write fails with no capabilities granted', async () => {
    state.historyThrows = true
    const response = await respond()
    expect(response.verifiablePresentation).toBeTruthy()
    expect(state.calls).toEqual(['processRequest', 'addHistoryLogin'])
  })

  it('records a DIDAuth-only request as a plain Login with no grants', async () => {
    const session = makeSession()
    await respond({ session })
    expect(session.storage.addHistoryLogin).toHaveBeenCalledWith({
      user: { id: 'did:key:zUser' },
      origin: 'https://app.example'
    })
    expect(session.storage.addHistoryGrant).not.toHaveBeenCalled()
  })

  it('records nothing for a request that asked for no DIDAuth or grant', async () => {
    const session = makeSession()
    await respond({
      session,
      requestProfile: { ...profile, didAuth: false }
    })
    expect(session.storage.addHistoryLogin).not.toHaveBeenCalled()
    expect(session.storage.addHistoryGrant).not.toHaveBeenCalled()
    expect(session.storage.connectionsDirectory).not.toHaveBeenCalled()
  })

  it('reports an unavailable zcap target with its own reason', async () => {
    state.processThrows = new FakeZcapUnavailableError()
    const failure = await respond().catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(WalletResponseFailure)
    expect((failure as InstanceType<typeof WalletResponseFailure>).reason).toBe(
      'zcapUnavailable'
    )
  })

  it('reports a failed exchange delivery as such, carrying the composed response', async () => {
    state.deliverThrows = true
    const failure = await respond({
      exchangeUrl: 'https://verifier.example/exchange/1'
    }).catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(WalletResponseFailure)
    const typed = failure as InstanceType<typeof WalletResponseFailure>
    expect(typed.reason).toBe('exchangeFailed')
    // The Login activity is already recorded, so the page with no other
    // channel to the requester can offer the response for manual delivery.
    expect(typed.response?.verifiablePresentation).toEqual({
      type: 'VerifiablePresentation'
    })
    expect(state.calls).toEqual([
      'processRequest',
      'addHistoryLogin',
      'deliverPresentation'
    ])
  })

  describe('an App Connect request', () => {
    it('writes the app entry, then the Grant row, before delivery', async () => {
      state.appConnectResult = {
        firstRun: true,
        subjectDid: APP_DID,
        appKey: APP_KEY
      }
      const session = makeSession()
      await respond({
        session,
        requestProfile: appConnectProfile(),
        exchangeUrl: 'https://verifier.example/exchange/1'
      })

      expect(state.calls).toEqual([
        'processRequest',
        'entryWrite',
        'addHistoryGrant',
        'deliverPresentation'
      ])
      expect(session.storage.addHistoryLogin).not.toHaveBeenCalled()
      expect(session.storage.addHistoryGrant).toHaveBeenCalledWith(
        expect.objectContaining({
          origin: 'https://app.example',
          appConnect: {
            name: 'Text Editor',
            firstRun: true,
            appUrl: 'https://app.example/editor'
          }
        })
      )
      expect(await storedEntry({ did: APP_DID })).toMatchObject({
        kind: 'app',
        id: APP_DID,
        name: 'Text Editor',
        origin: 'https://app.example',
        url: 'https://app.example/editor',
        appKey: APP_KEY,
        grants: []
      })
    })

    it('writes a zero-grant entry on a session with no Space', async () => {
      // A guest or no-WAS session: the directory has no container URL.
      directorySpaceUrl = undefined
      state.appConnectResult = {
        firstRun: true,
        subjectDid: APP_DID,
        appKey: APP_KEY
      }
      await respond({ requestProfile: appConnectProfile() })

      expect(await storedEntry({ did: APP_DID })).toMatchObject({
        kind: 'app',
        appKey: APP_KEY,
        grants: []
      })
      const listing = await readConnections({
        store: directory.store,
        hmacKey: HMAC_KEY
      })
      expect(
        listConnectedApps({ connections: listing?.entries ?? [] }).map(
          app => app.subjectDid
        )
      ).toEqual([APP_DID])
    })

    it('records the grants and the app result on the early Grant', async () => {
      const appGrant = grant({ id: 'urn:zcap:app', controller: APP_DID })
      state.provisions = true
      state.zcaps = [appGrant]
      state.appConnectResult = {
        firstRun: false,
        subjectDid: APP_DID,
        appKey: APP_KEY
      }
      const session = makeSession()
      await respond({ session, requestProfile: appConnectProfile() })

      expect(state.calls).toEqual([
        'processRequest',
        'entryWrite',
        'addHistoryGrant',
        'escrow:urn:zcap:app'
      ])
      expect(session.storage.addHistoryGrant).toHaveBeenCalledTimes(1)
      expect(session.storage.addHistoryGrant).toHaveBeenCalledWith(
        expect.objectContaining({
          appConnect: {
            name: 'Text Editor',
            firstRun: false,
            appUrl: 'https://app.example/editor'
          }
        })
      )
      expect(await recordedGrants({ did: APP_DID })).toEqual([
        { id: 'urn:zcap:app', grantKind: 'grant' }
      ])
    })

    it('does not store a name longer than the display-name rule allows', async () => {
      state.appConnectResult = {
        firstRun: true,
        subjectDid: APP_DID,
        appKey: APP_KEY
      }
      await respond({
        requestProfile: appConnectProfile({ name: 'x'.repeat(65) })
      })

      const entry = await storedEntry({ did: APP_DID })
      expect(entry).toMatchObject({ kind: 'app', appKey: APP_KEY })
      expect(entry).not.toHaveProperty('name')
    })

    it('fails closed with no Grant row when the entry write fails', async () => {
      entryThrowsFrom = 1
      state.appConnectResult = {
        firstRun: true,
        subjectDid: APP_DID,
        appKey: APP_KEY
      }
      const session = makeSession()
      await expect(
        respond({
          session,
          requestProfile: appConnectProfile(),
          exchangeUrl: 'https://verifier.example/exchange/1'
        })
      ).rejects.toMatchObject({ reason: 'processFailed' })
      expect(state.calls).toEqual(['processRequest', 'entryWrite'])
      expect(session.storage.addHistoryGrant).not.toHaveBeenCalled()
      expect(session.storage.deleteHistoryActivity).not.toHaveBeenCalled()
    })

    describe('from an app the user disconnected', () => {
      beforeEach(async () => {
        // A disconnected app: its entry stands retired, with no grants and
        // no app key.
        await recordGrants({
          store: directory.store,
          hmacKey: HMAC_KEY,
          did: APP_DID,
          kind: 'app',
          spaceUrl: SPACE_URL,
          grants: [],
          appKey: 'z1OldAppKey',
          name: 'Text Editor'
        })
        await retireConnection({
          store: directory.store,
          hmacKey: HMAC_KEY,
          did: APP_DID,
          handledZcapIds: [],
          spaceUrl: SPACE_URL
        })
        state.appConnectResult = {
          firstRun: true,
          subjectDid: APP_DID,
          appKey: APP_KEY
        }
      })

      /**
       * The apps the Applications page lists.
       *
       * @returns {Promise<string[]>}   their subject DIDs
       */
      async function listedApps(): Promise<string[]> {
        const listing = await readConnections({
          store: directory.store,
          hmacKey: HMAC_KEY
        })
        return listConnectedApps({
          connections: listing?.entries ?? []
        }).map(app => app.subjectDid)
      }

      it('retires the entry again when nothing escrowed', async () => {
        state.provisions = true
        state.zcaps = [grant({ id: 'urn:zcap:app', controller: APP_DID })]
        state.provisionThrows = new Error('provisioning failed')
        const session = makeSession()
        await expect(
          respond({ session, requestProfile: appConnectProfile() })
        ).rejects.toMatchObject({ reason: 'processFailed' })

        const entry = await storedEntry({ did: APP_DID })
        expect(entry).toMatchObject({
          kind: 'app',
          name: 'Text Editor',
          grants: [],
          retired: expect.any(String)
        })
        expect(entry).not.toHaveProperty('appKey')
        expect(await listedApps()).toEqual([])
        expect(session.storage.deleteHistoryActivity).toHaveBeenCalledWith({
          id: 'grant-1'
        })
      })

      it('retires a zero-grant connect again when processing fails after the record', async () => {
        state.provisions = true
        state.zcaps = []
        state.provisionThrows = new Error('compose failed')
        await expect(
          respond({ requestProfile: appConnectProfile() })
        ).rejects.toMatchObject({ reason: 'processFailed' })

        const entry = await storedEntry({ did: APP_DID })
        expect(entry).toMatchObject({ retired: expect.any(String) })
        expect(entry).not.toHaveProperty('appKey')
        expect(await listedApps()).toEqual([])
      })

      it('keeps the entry live when a grant escrowed, with its Grant row', async () => {
        const grantX = grant({
          id: 'urn:zcap:x',
          controller: APP_DID,
          collection: 'app-x'
        })
        const grantY = grant({
          id: 'urn:zcap:y',
          controller: APP_DID,
          collection: 'app-y'
        })
        state.provisions = true
        state.zcaps = [grantX, grantY]
        state.escrows = [
          { zcapIds: ['urn:zcap:x'] },
          { zcapIds: ['urn:zcap:y'], throws: new Error('provisioning failed') }
        ]
        const session = makeSession()
        await expect(
          respond({ session, requestProfile: appConnectProfile() })
        ).rejects.toMatchObject({ reason: 'processFailed' })

        const entry = await storedEntry({ did: APP_DID })
        expect(entry).toMatchObject({ appKey: APP_KEY })
        expect(entry).not.toHaveProperty('retired')
        expect(await recordedGrants({ did: APP_DID })).toEqual([
          { id: 'urn:zcap:x', grantKind: 'grant' }
        ])
        expect(await listedApps()).toEqual([APP_DID])
        expect(session.storage.deleteHistoryActivity).not.toHaveBeenCalled()
      })
    })
  })

  describe('a request whose grants need escrow', () => {
    const agentGrant = grant({ id: 'urn:zcap:1' })

    it('writes the entry, then the Grant row, then escrows, then delivers', async () => {
      state.provisions = true
      state.zcaps = [agentGrant]
      const session = makeSession()
      await respond({
        session,
        requestProfile: agentProfile,
        requestOrigin: EXTERNAL_REQUEST_ORIGIN,
        exchangeUrl: 'https://verifier.example/exchange/1'
      })
      expect(state.calls).toEqual([
        'processRequest',
        'entryWrite',
        'addHistoryGrant',
        'escrow:urn:zcap:1',
        'deliverPresentation'
      ])
      expect(session.storage.addHistoryGrant).toHaveBeenCalledTimes(1)
      expect(session.storage.addHistoryGrant).toHaveBeenCalledWith(
        expect.objectContaining({
          grants: [
            expect.objectContaining({ id: 'urn:zcap:1', zcap: agentGrant })
          ]
        })
      )
      // An agent entry, named from the request's self-declared agent.
      expect(await storedEntry({ did: AGENT })).toMatchObject({
        kind: 'agent',
        id: AGENT,
        name: 'research-bot'
      })
      expect(await recordedGrants({ did: AGENT })).toEqual([
        { id: 'urn:zcap:1', grantKind: 'grant' }
      ])
    })

    it('marks the share grants as shares on the entry', async () => {
      const shareGrant = grant({
        id: 'urn:zcap:share',
        collection: 'private-credentials'
      })
      state.provisions = true
      state.zcaps = [shareGrant, agentGrant]
      state.shareZcapIds = ['urn:zcap:share']
      await respond({
        requestProfile: agentProfile,
        requestOrigin: EXTERNAL_REQUEST_ORIGIN
      })
      expect(await recordedGrants({ did: AGENT })).toEqual([
        { id: 'urn:zcap:share', grantKind: 'share' },
        { id: 'urn:zcap:1', grantKind: 'grant' }
      ])
    })

    it('fails closed with nothing escrowed when the entry write fails', async () => {
      state.provisions = true
      state.zcaps = [agentGrant]
      entryThrowsFrom = 1
      const session = makeSession()
      await expect(
        respond({
          session,
          requestProfile: agentProfile,
          requestOrigin: EXTERNAL_REQUEST_ORIGIN,
          exchangeUrl: 'https://verifier.example/exchange/1'
        })
      ).rejects.toMatchObject({ reason: 'processFailed' })
      // No Grant row, no escrow, no delivery.
      expect(state.calls).toEqual(['processRequest', 'entryWrite'])
      expect(session.storage.addHistoryGrant).not.toHaveBeenCalled()
      expect(session.storage.deleteHistoryActivity).not.toHaveBeenCalled()
      expect(await storedEntry({ did: AGENT })).toBeUndefined()
    })

    it('removes the grants and retires the new entry again when the Grant row write fails', async () => {
      state.provisions = true
      state.zcaps = [agentGrant]
      state.historyThrows = true
      await expect(
        respond({
          requestProfile: agentProfile,
          requestOrigin: EXTERNAL_REQUEST_ORIGIN,
          exchangeUrl: 'https://verifier.example/exchange/1'
        })
      ).rejects.toMatchObject({ reason: 'processFailed' })
      expect(state.calls).toEqual([
        'processRequest',
        'entryWrite',
        'addHistoryGrant',
        'entryWrite',
        'entryWrite'
      ])
      // The consent created the entry, so the rollback retires it: it keeps
      // the agent's name, and a later consent un-retires it.
      expect(await storedEntry({ did: AGENT })).toMatchObject({
        kind: 'agent',
        name: 'research-bot',
        grants: [],
        retired: expect.any(String)
      })
    })

    it('removes the grants and the Grant row when escrow fails after them', async () => {
      state.provisions = true
      state.zcaps = [agentGrant]
      state.provisionThrows = new Error('provisioning failed')
      const session = makeSession()
      await expect(
        respond({
          session,
          requestProfile: agentProfile,
          requestOrigin: EXTERNAL_REQUEST_ORIGIN,
          exchangeUrl: 'https://verifier.example/exchange/1'
        })
      ).rejects.toMatchObject({ reason: 'processFailed' })
      // Nothing is delivered, so the grant goes from the entry, the entry
      // the consent created is retired, and the Grant row naming it goes too.
      expect(state.calls).toEqual([
        'processRequest',
        'entryWrite',
        'addHistoryGrant',
        'escrow:urn:zcap:1',
        'entryWrite',
        'entryWrite',
        'deleteHistoryActivity'
      ])
      expect(session.storage.addHistoryGrant).toHaveBeenCalledTimes(1)
      expect(session.storage.deleteHistoryActivity).toHaveBeenCalledWith({
        id: 'grant-1'
      })
      expect(await storedEntry({ did: AGENT })).toMatchObject({
        kind: 'agent',
        grants: [],
        retired: expect.any(String)
      })
    })

    it('leaves a live entry live when escrow fails, keeping its earlier grants', async () => {
      const earlier = grant({ id: 'urn:zcap:earlier', collection: 'agent-old' })
      await recordGrants({
        store: directory.store,
        hmacKey: HMAC_KEY,
        did: AGENT,
        kind: 'agent',
        spaceUrl: SPACE_URL,
        grants: [{ zcap: earlier, grantKind: 'grant' }]
      })
      state.provisions = true
      state.zcaps = [agentGrant]
      state.provisionThrows = new Error('provisioning failed')
      await expect(
        respond({
          requestProfile: agentProfile,
          requestOrigin: EXTERNAL_REQUEST_ORIGIN
        })
      ).rejects.toMatchObject({ reason: 'processFailed' })

      expect(await recordedGrants({ did: AGENT })).toEqual([
        { id: 'urn:zcap:earlier', grantKind: 'grant' }
      ])
      expect(await storedEntry({ did: AGENT })).not.toHaveProperty('retired')
    })

    it('keeps a grant whose escrow landed and removes only the one that failed', async () => {
      const grantX = grant({ id: 'urn:zcap:x', collection: 'agent-x' })
      const grantY = grant({ id: 'urn:zcap:y', collection: 'agent-y' })
      state.provisions = true
      state.zcaps = [grantX, grantY]
      state.escrows = [
        { zcapIds: ['urn:zcap:x'] },
        { zcapIds: ['urn:zcap:y'], throws: new Error('provisioning failed') }
      ]
      const session = makeSession()
      await expect(
        respond({
          session,
          requestProfile: agentProfile,
          requestOrigin: EXTERNAL_REQUEST_ORIGIN
        })
      ).rejects.toMatchObject({ reason: 'processFailed' })

      // X's grantee holds the decryption material, so its grant stays
      // recorded, and the agent stays listed with a row to revoke it from.
      expect(await recordedGrants({ did: AGENT })).toEqual([
        { id: 'urn:zcap:x', grantKind: 'grant' }
      ])
      expect(await storedEntry({ did: AGENT })).not.toHaveProperty('retired')
      // The Grant row stays as the audit trail for X.
      expect(session.storage.deleteHistoryActivity).not.toHaveBeenCalled()
      const listing = await readConnections({
        store: directory.store,
        hmacKey: HMAC_KEY
      })
      const agents = await listConnectedAgents({
        storage: {} as StorageManager,
        connections: listing?.entries ?? [],
        spaceUrl: SPACE_URL
      })
      expect(agents.map(agent => agent.controller)).toEqual([AGENT])
      expect(agents[0].grants.map(row => row.id)).toEqual(['urn:zcap:x'])
    })

    it('keeps the original failure when the Grant removal fails', async () => {
      state.provisions = true
      state.zcaps = [agentGrant]
      state.provisionThrows = new Error('provisioning failed')
      state.deleteThrows = true
      const failure = await respond({
        requestProfile: agentProfile,
        requestOrigin: EXTERNAL_REQUEST_ORIGIN
      }).catch((err: unknown) => err)
      expect(failure).toMatchObject({ reason: 'processFailed' })
      expect((failure as Error).cause).toBe(state.provisionThrows)
      expect(state.calls.at(-1)).toBe('deleteHistoryActivity')
    })

    it('keeps the original failure when the grant removal fails, and the grant stays listed', async () => {
      state.provisions = true
      state.zcaps = [agentGrant]
      state.provisionThrows = new Error('provisioning failed')
      entryThrowsFrom = 2
      const session = makeSession()
      const failure = await respond({
        session,
        requestProfile: agentProfile,
        requestOrigin: EXTERNAL_REQUEST_ORIGIN
      }).catch((err: unknown) => err)
      expect(failure).toMatchObject({ reason: 'processFailed' })
      expect((failure as Error).cause).toBe(state.provisionThrows)
      // The Grant row still goes; the grant stays for a revoke to handle.
      expect(session.storage.deleteHistoryActivity).toHaveBeenCalledWith({
        id: 'grant-1'
      })
      expect(await recordedGrants({ did: AGENT })).toEqual([
        { id: 'urn:zcap:1', grantKind: 'grant' }
      ])
    })

    it('removes nothing when processing fails before any record', async () => {
      state.processThrows = new Error('boom')
      const session = makeSession()
      await expect(
        respond({ session, requestProfile: agentProfile })
      ).rejects.toMatchObject({ reason: 'processFailed' })
      expect(session.storage.deleteHistoryActivity).not.toHaveBeenCalled()
      expect(session.storage.connectionsDirectory).not.toHaveBeenCalled()
    })

    it("refuses a grant to a disconnected app's DID, leaving its entry as it was", async () => {
      // A disconnected app: an `app` entry at the DID, retired.
      await recordGrants({
        store: directory.store,
        hmacKey: HMAC_KEY,
        did: AGENT,
        kind: 'app',
        spaceUrl: SPACE_URL,
        grants: [],
        appKey: APP_KEY,
        origin: 'https://app.example'
      })
      await retireConnection({
        store: directory.store,
        hmacKey: HMAC_KEY,
        did: AGENT,
        handledZcapIds: [],
        spaceUrl: SPACE_URL
      })
      const resourceId = await connectionResourceId({
        hmacKey: HMAC_KEY,
        did: AGENT
      })
      const before = structuredClone(directory.rows.get(resourceId))

      state.provisions = true
      state.zcaps = [agentGrant]
      const session = makeSession()
      const failure = await respond({
        session,
        requestProfile: agentProfile,
        requestOrigin: EXTERNAL_REQUEST_ORIGIN
      }).catch((err: unknown) => err)

      expect(failure).toMatchObject({ reason: 'processFailed' })
      expect(((failure as Error).cause as Error).name).toBe(
        'ConnectionKindMismatchError'
      )
      // Not un-retired, not re-kinded, not written at all.
      expect(directory.rows.get(resourceId)).toEqual(before)
      expect(state.calls).toEqual(['processRequest'])
      expect(session.storage.addHistoryGrant).not.toHaveBeenCalled()
    })
  })

  describe('a request that escrows nothing', () => {
    const agentGrant = grant({ id: 'urn:zcap:1' })

    it('writes the entry, then the Grant row, before delivery', async () => {
      state.zcaps = [agentGrant]
      const session = makeSession()
      await respond({
        session,
        requestProfile: agentProfile,
        requestOrigin: EXTERNAL_REQUEST_ORIGIN,
        exchangeUrl: 'https://was.example/workflows/ephemeral/exchanges/1'
      })
      expect(state.calls).toEqual([
        'processRequest',
        'entryWrite',
        'addHistoryGrant',
        'deliverPresentation'
      ])
      expect(session.storage.addHistoryGrant).toHaveBeenCalledWith(
        expect.objectContaining({
          origin: 'n/a (API request)',
          actor: { name: 'research-bot' }
        })
      )
      expect(await storedEntry({ did: AGENT })).toMatchObject({
        kind: 'agent',
        name: 'research-bot'
      })
      expect(await recordedGrants({ did: AGENT })).toEqual([
        { id: 'urn:zcap:1', grantKind: 'grant' }
      ])
    })

    it('records the origin-less request page marker verbatim, with no actor when none was declared', async () => {
      state.zcaps = [agentGrant]
      const session = makeSession()
      await respond({
        session,
        requestProfile: { ...agentProfile, agent: undefined },
        requestOrigin: EXTERNAL_REQUEST_ORIGIN
      })
      expect(session.storage.addHistoryGrant).toHaveBeenCalledWith(
        expect.objectContaining({ origin: 'n/a (API request)' })
      )
      expect(session.storage.addHistoryGrant).not.toHaveBeenCalledWith(
        expect.objectContaining({ actor: expect.anything() })
      )
      expect(await storedEntry({ did: AGENT })).not.toHaveProperty('name')
    })

    it('fails closed with no Grant row when the entry write fails', async () => {
      state.zcaps = [agentGrant]
      entryThrowsFrom = 1
      const session = makeSession()
      await expect(
        respond({
          session,
          requestProfile: agentProfile,
          requestOrigin: EXTERNAL_REQUEST_ORIGIN,
          exchangeUrl: 'https://was.example/workflows/ephemeral/exchanges/1'
        })
      ).rejects.toMatchObject({ reason: 'processFailed' })
      expect(state.calls).toEqual(['processRequest', 'entryWrite'])
      expect(session.storage.addHistoryGrant).not.toHaveBeenCalled()
    })

    it('removes the grants again when the entry write lands with its response lost', async () => {
      state.zcaps = [agentGrant]
      entryLandsThenThrowsAt = 1
      const session = makeSession()
      await expect(
        respond({
          session,
          requestProfile: agentProfile,
          requestOrigin: EXTERNAL_REQUEST_ORIGIN,
          exchangeUrl: 'https://was.example/workflows/ephemeral/exchanges/1'
        })
      ).rejects.toMatchObject({ reason: 'processFailed' })
      // Nothing is delivered and no Grant row is written; the landed put is
      // undone by a removal, then a retirement of the entry it created.
      expect(state.calls).toEqual([
        'processRequest',
        'entryWrite',
        'entryWrite',
        'entryWrite'
      ])
      expect(session.storage.addHistoryGrant).not.toHaveBeenCalled()
      expect(await storedEntry({ did: AGENT })).toMatchObject({
        kind: 'agent',
        grants: [],
        retired: expect.any(String)
      })
    })

    it('fails closed and removes the grants when the Grant row write fails', async () => {
      state.zcaps = [agentGrant]
      state.historyThrows = true
      await expect(
        respond({
          requestProfile: agentProfile,
          requestOrigin: EXTERNAL_REQUEST_ORIGIN,
          exchangeUrl: 'https://verifier.example/exchange/1'
        })
      ).rejects.toMatchObject({ reason: 'processFailed' })
      // Nothing was delivered, so the signed delegations stay inert.
      expect(state.calls).toEqual([
        'processRequest',
        'entryWrite',
        'addHistoryGrant',
        'entryWrite',
        'entryWrite'
      ])
      expect(await storedEntry({ did: AGENT })).toMatchObject({
        kind: 'agent',
        grants: [],
        retired: expect.any(String)
      })
    })

    it('keeps the entry and the Grant row when the exchange delivery fails', async () => {
      state.zcaps = [agentGrant]
      state.deliverThrows = true
      const session = makeSession()
      const failure = await respond({
        session,
        requestProfile: agentProfile,
        requestOrigin: EXTERNAL_REQUEST_ORIGIN,
        exchangeUrl: 'https://was.example/workflows/ephemeral/exchanges/1'
      }).catch((err: unknown) => err)
      expect(failure).toMatchObject({ reason: 'exchangeFailed' })
      expect(session.storage.deleteHistoryActivity).not.toHaveBeenCalled()
      expect(await recordedGrants({ did: AGENT })).toEqual([
        { id: 'urn:zcap:1', grantKind: 'grant' }
      ])
      expect(state.calls).toEqual([
        'processRequest',
        'entryWrite',
        'addHistoryGrant',
        'deliverPresentation'
      ])
    })

    it("refuses a grant to a disconnected app's DID, leaving its entry as it was", async () => {
      await recordGrants({
        store: directory.store,
        hmacKey: HMAC_KEY,
        did: AGENT,
        kind: 'app',
        spaceUrl: SPACE_URL,
        grants: [],
        appKey: APP_KEY
      })
      await retireConnection({
        store: directory.store,
        hmacKey: HMAC_KEY,
        did: AGENT,
        handledZcapIds: [],
        spaceUrl: SPACE_URL
      })
      const resourceId = await connectionResourceId({
        hmacKey: HMAC_KEY,
        did: AGENT
      })
      const before = structuredClone(directory.rows.get(resourceId))

      state.zcaps = [agentGrant]
      const session = makeSession()
      const failure = await respond({
        session,
        requestProfile: agentProfile,
        requestOrigin: EXTERNAL_REQUEST_ORIGIN,
        exchangeUrl: 'https://was.example/workflows/ephemeral/exchanges/1'
      }).catch((err: unknown) => err)

      expect(failure).toMatchObject({ reason: 'processFailed' })
      expect(((failure as Error).cause as Error).name).toBe(
        'ConnectionKindMismatchError'
      )
      expect(directory.rows.get(resourceId)).toEqual(before)
      expect(state.calls).toEqual(['processRequest'])
      expect(session.storage.addHistoryGrant).not.toHaveBeenCalled()
    })
  })
})

describe('the request consent events', () => {
  let capture: ReturnType<typeof captureCeremonyEvents>

  beforeEach(() => {
    capture = captureCeremonyEvents()
  })

  afterEach(() => {
    capture.stop()
  })

  it('marks the record, the escrow, and the delivery, and ends clean, counts only', async () => {
    state.provisions = true
    state.zcaps = [grant({ id: 'urn:zcap:1' })]
    await respond({
      requestProfile: agentProfile,
      requestOrigin: EXTERNAL_REQUEST_ORIGIN,
      exchangeUrl: 'https://verifier.example/exchange/1'
    })

    expect(capture.stageNames('request-consent')).toEqual([
      'record-entry',
      'record-activity',
      'escrow',
      'deliver'
    ])
    expect(capture.soleOutcome('request-consent').data).toMatchObject({
      outcome: 'clean',
      grants: 1
    })
    expect(capture.serialized()).not.toContain(AGENT)
  })

  it('marks no escrow when a failure rolls the record back', async () => {
    state.provisions = true
    state.zcaps = [grant({ id: 'urn:zcap:1' })]
    state.provisionThrows = new Error('escrow refused')
    await respond({
      requestProfile: agentProfile,
      requestOrigin: EXTERNAL_REQUEST_ORIGIN
    }).catch(() => undefined)

    expect(capture.stageNames('request-consent')).toEqual([
      'record-entry',
      'record-activity'
    ])
    expect(capture.soleOutcome('request-consent').data).toMatchObject({
      outcome: 'failed',
      reason: 'processFailed'
    })
  })

  it('refuses a request whose remote Space is unavailable', async () => {
    state.processThrows = new FakeZcapUnavailableError()
    await respond().catch(() => undefined)

    expect(capture.stageNames('request-consent')).toEqual([])
    expect(capture.soleOutcome('request-consent').data).toMatchObject({
      outcome: 'refused',
      reason: 'zcapUnavailable',
      errorName: 'WalletResponseFailure'
    })
  })

  it('fails a run whose exchange delivery failed, after its record', async () => {
    state.deliverThrows = true
    await respond({
      exchangeUrl: 'https://verifier.example/exchange/1'
    }).catch(() => undefined)

    expect(capture.stageNames('request-consent')).toEqual(['record-activity'])
    expect(capture.soleOutcome('request-consent').data).toMatchObject({
      outcome: 'failed',
      reason: 'exchangeFailed'
    })
  })
})

describe('a connection request', () => {
  const EXCHANGE = 'https://agent.example/exchanges/1'
  // A connection request: a read on one audience by URL, POST on the inbox.
  const connectionProfile = {
    didAuth: false,
    vcQueries: [],
    zcapRequests: [
      {
        referenceId: 'friends',
        controller: AGENT,
        invocationTarget: `${SPACE_URL}friends/`
      },
      {
        referenceId: 'inbox',
        controller: AGENT,
        invocationTarget: { type: 'https://w3id.org/byoe#inbox' }
      }
    ],
    appConnect: null,
    agent: { name: 'Feed agent' }
  } as unknown as RespondProfile

  /**
   * Answers the connection request through the interaction-URL path.
   *
   * @param options {object}
   * @param [options.session] {RespondSession}
   * @returns {Promise<object>}
   */
  function connect({ session }: { session?: RespondSession } = {}) {
    return respond({
      exchangeUrl: EXCHANGE,
      requestProfile: connectionProfile,
      requestOrigin: EXTERNAL_REQUEST_ORIGIN,
      delegateStandaloneZcaps: true,
      requestKind: 'connection-request',
      ...(session && { session })
    })
  }

  /**
   * A seed of repeated bytes, with its tag under the test directory's key.
   *
   * @param fill {number}
   * @returns {Promise<{ seed: string, seedTag: string }>}
   */
  async function seedOf(fill: number) {
    const seed = base64urlnopad.encode(new Uint8Array(32).fill(fill))
    return {
      seed,
      seedTag: await connectionSeedTag({ hmacKey: HMAC_KEY, seed })
    }
  }

  /**
   * The did:key a stored seed derives.
   *
   * @param options {object}
   * @param options.seed {string}
   * @param options.seedTag {string}
   * @returns {Promise<string>}
   */
  async function didOf({ seed, seedTag }: { seed: string; seedTag: string }) {
    return (await connectionDidKey({ hmacKey: HMAC_KEY, seed, seedTag })).did
  }

  beforeEach(() => {
    state.zcaps = [
      grant({ id: 'urn:zcap:friends', collection: 'friends' }),
      {
        ...grant({ id: 'urn:zcap:inbox', collection: 'inbox' }),
        allowedAction: ['POST']
      }
    ]
  })

  it('mints a seed and its tag, writes them with the grants before delivery, and signs with its key', async () => {
    await connect()
    expect(state.calls).toEqual([
      'processRequest',
      'entryWrite',
      'addHistoryGrant',
      'deliverPresentation'
    ])
    const entry = await storedEntry({ did: AGENT })
    const seed = entry?.seed as string
    const seedTag = entry?.seedTag as string
    expect(seed).toHaveLength(43)
    expect(
      await verifyConnectionSeedTag({ hmacKey: HMAC_KEY, seed, seedTag })
    ).toBe(true)
    expect(state.pairwiseHolder).toBe(await didOf({ seed, seedTag }))
    expect(await recordedGrants({ did: AGENT })).toHaveLength(2)
  })

  it('writes the seed on the record path ahead of escrow too', async () => {
    state.provisions = true
    await connect()
    expect(state.calls.indexOf('entryWrite')).toBeLessThan(
      state.calls.findIndex(call => call.startsWith('escrow:'))
    )
    const entry = await storedEntry({ did: AGENT })
    expect(entry?.seed).toBeDefined()
    expect(state.pairwiseHolder).toBe(
      await didOf({
        seed: entry?.seed as string,
        seedTag: entry?.seedTag as string
      })
    )
  })

  it("reuses a returning agent's seed once its tag verifies", async () => {
    const stored = await seedOf(3)
    await recordGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT,
      kind: 'agent',
      spaceUrl: SPACE_URL,
      grants: [],
      ...stored
    })
    await connect()
    const entry = await storedEntry({ did: AGENT })
    expect(entry?.seed).toBe(stored.seed)
    expect(state.pairwiseHolder).toBe(await didOf(stored))
  })

  it('gives an entry with no seed a fresh seed and its tag', async () => {
    await recordGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT,
      kind: 'agent',
      spaceUrl: SPACE_URL,
      grants: []
    })
    await connect()
    const entry = await storedEntry({ did: AGENT })
    expect(entry?.seed).toHaveLength(43)
    expect(entry?.seedTag).toHaveLength(43)
  })

  it('fails closed on a stored seed whose tag does not verify, writing nothing', async () => {
    const stored = await seedOf(3)
    await recordGrants({
      store: directory.store,
      hmacKey: HMAC_KEY,
      did: AGENT,
      kind: 'agent',
      spaceUrl: SPACE_URL,
      grants: [],
      ...stored
    })
    // The host swaps in a seed of its own, with the old tag beside it.
    const resourceId = await connectionResourceId({
      hmacKey: HMAC_KEY,
      did: AGENT
    })
    const planted = (await seedOf(4)).seed
    const row = directory.rows.get(resourceId)!
    directory.rows.set(resourceId, {
      ...row,
      body: { ...(row.body as object), seed: planted }
    })
    const failure = await connect().catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(WalletResponseFailure)
    expect((failure as InstanceType<typeof WalletResponseFailure>).reason).toBe(
      'processFailed'
    )
    expect(state.calls).toEqual([])
    expect((await storedEntry({ did: AGENT }))?.seed).toBe(planted)
  })

  it('fails closed with nothing delivered when a concurrent consent wrote another seed', async () => {
    const racing = await seedOf(9)
    state.duringProcess = async () => {
      await recordGrants({
        store: directory.store,
        hmacKey: HMAC_KEY,
        did: AGENT,
        kind: 'agent',
        spaceUrl: SPACE_URL,
        grants: [],
        ...racing
      })
    }
    const failure = await connect().catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(WalletResponseFailure)
    expect(state.calls).not.toContain('deliverPresentation')
    expect(state.calls).not.toContain('addHistoryGrant')
    expect((await storedEntry({ did: AGENT }))?.seed).toBe(racing.seed)
    expect(await recordedGrants({ did: AGENT })).toEqual([])
  })

  it('delivers nothing when the entry write fails', async () => {
    entryThrowsFrom = 1
    const failure = await connect().catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(WalletResponseFailure)
    expect(state.calls).not.toContain('deliverPresentation')
    expect(await storedEntry({ did: AGENT })).toBeUndefined()
  })

  it('leaves the seed on the entry when the consent rolls back', async () => {
    state.historyThrows = true
    const failure = await connect().catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(WalletResponseFailure)
    expect(state.calls).not.toContain('deliverPresentation')
    const entry = await storedEntry({ did: AGENT })
    expect(entry?.retired).toBeDefined()
    expect(entry?.seed).toHaveLength(43)
    expect(await recordedGrants({ did: AGENT })).toEqual([])
  })

  it('mints no seed for an interaction-URL request', async () => {
    state.zcaps = [grant({ id: 'urn:zcap:agent-data' })]
    await respond({
      exchangeUrl: EXCHANGE,
      requestProfile: agentProfile,
      requestOrigin: EXTERNAL_REQUEST_ORIGIN,
      delegateStandaloneZcaps: true,
      requestKind: 'interaction-url'
    })
    expect(state.pairwiseHolder).toBeUndefined()
    expect((await storedEntry({ did: AGENT }))?.seed).toBeUndefined()
  })
})
