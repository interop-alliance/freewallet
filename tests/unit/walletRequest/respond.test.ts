// @vitest-environment node
/**
 * Unit tests for the CHAPI `get` response sequence
 * (`src/lib/walletRequest/respond.ts`): the request's activity (a Grant for
 * an App Connect connection or a capability request, a plain Login for a
 * DIDAuth-only request) is persisted before anything is delivered externally, a failed history write with granted
 * capabilities fails closed (nothing delivered), and the typed failure reasons
 * the popup renders. `processRequest` and the exchange delivery are mocked.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  calls: [] as string[],
  zcaps: [] as unknown[],
  processThrows: null as Error | null,
  historyThrows: false,
  deleteThrows: false,
  deliverThrows: false,
  appConnectResult: undefined as { firstRun: boolean } | undefined,
  // When set, the mocked `processRequest` stands in for a request whose
  // grants provision a collection: it awaits the `beforeProvision` hook, then
  // records the escrow (or throws `provisionThrows` there).
  provisions: false,
  provisionThrows: null as Error | null
}))

class FakeZcapUnavailableError extends Error {}

vi.mock('@/lib/walletRequest/processZcaps', () => ({
  ZcapUnavailableError: FakeZcapUnavailableError
}))

vi.mock('@/lib/walletRequest/processRequest', () => ({
  processRequest: vi.fn(
    async ({
      beforeProvision
    }: {
      beforeProvision?: (options: {
        zcaps: unknown[]
        appConnect?: { firstRun: boolean }
      }) => Promise<void>
    }) => {
      state.calls.push('processRequest')
      if (state.processThrows) {
        throw state.processThrows
      }
      if (state.provisions) {
        await beforeProvision?.({
          zcaps: state.zcaps,
          appConnect: state.appConnectResult
        })
        state.calls.push('provisionEncryptedCollection')
        if (state.provisionThrows) {
          throw state.provisionThrows
        }
      }
      return {
        verifiablePresentation: { type: 'VerifiablePresentation' },
        zcaps: state.zcaps,
        appConnect: state.appConnectResult
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

const profile = {
  didAuth: true,
  vcQueries: [],
  zcapRequests: [],
  appConnect: null
} as unknown as Parameters<typeof composeAndDeliverResponse>[0]['profile']

function makeSession() {
  return {
    user: { id: 'did:key:zUser' },
    storage: {
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
  } as unknown as Parameters<typeof composeAndDeliverResponse>[0]['session']
}

type RespondSession = Parameters<typeof composeAndDeliverResponse>[0]['session']

async function respond({
  exchangeUrl,
  session = makeSession(),
  requestProfile = profile
}: {
  exchangeUrl?: string
  session?: RespondSession
  requestProfile?: typeof profile
} = {}) {
  return composeAndDeliverResponse({
    request: { query: [] } as unknown as Parameters<
      typeof composeAndDeliverResponse
    >[0]['request'],
    session,
    profile: requestProfile,
    requestOrigin: 'https://app.example',
    selectedVCs: [],
    exchangeUrl
  })
}

beforeEach(() => {
  state.calls = []
  state.zcaps = []
  state.processThrows = null
  state.historyThrows = false
  state.deleteThrows = false
  state.deliverThrows = false
  state.appConnectResult = undefined
  state.provisions = false
  state.provisionThrows = null
})

describe('composeAndDeliverResponse', () => {
  it('persists the Login activity before delivering to the exchange', async () => {
    await respond({ exchangeUrl: 'https://verifier.example/exchange/1' })
    expect(state.calls).toEqual([
      'processRequest',
      'addHistoryLogin',
      'deliverPresentation'
    ])
  })

  it('fails closed when the history write fails and capabilities were granted', async () => {
    state.zcaps = [{ id: 'urn:zcap:1', invocationTarget: 'https://was/x' }]
    state.historyThrows = true
    await expect(
      respond({ exchangeUrl: 'https://verifier.example/exchange/1' })
    ).rejects.toMatchObject({ reason: 'processFailed' })
    // Nothing was delivered, so the signed delegations stay inert.
    expect(state.calls).toEqual(['processRequest', 'addHistoryGrant'])
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
  })

  it('reports an unavailable zcap target with its own reason', async () => {
    state.processThrows = new FakeZcapUnavailableError()
    const failure = await respond().catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(WalletResponseFailure)
    expect((failure as InstanceType<typeof WalletResponseFailure>).reason).toBe(
      'zcapUnavailable'
    )
  })

  it('records the validated appUrl on an App Connect Grant activity', async () => {
    state.appConnectResult = { firstRun: true }
    const session = makeSession()
    const appConnectProfile = {
      didAuth: true,
      vcQueries: [],
      zcapRequests: [],
      appConnect: {
        app: { name: 'Text Editor', appUrl: 'https://app.example/editor' },
        capabilityQueries: []
      }
    } as unknown as typeof profile

    await respond({ session, requestProfile: appConnectProfile })

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

  it('records the origin-less request page marker verbatim as the activity origin', async () => {
    const { EXTERNAL_REQUEST_ORIGIN } =
      await import('@/lib/walletRequest/externalRequest')
    state.zcaps = [{ id: 'urn:zcap:1', invocationTarget: 'https://was/x' }]
    const session = makeSession()
    const grantProfile = {
      didAuth: false,
      vcQueries: [],
      zcapRequests: [{ referenceId: 'web' }],
      appConnect: null
    } as unknown as typeof profile

    await composeAndDeliverResponse({
      request: { query: [] } as unknown as Parameters<
        typeof composeAndDeliverResponse
      >[0]['request'],
      session,
      profile: grantProfile,
      requestOrigin: EXTERNAL_REQUEST_ORIGIN,
      selectedVCs: [],
      exchangeUrl: 'https://was.example/workflows/ephemeral/exchanges/1'
    })

    expect(session.storage.addHistoryGrant).toHaveBeenCalledWith(
      expect.objectContaining({ origin: 'n/a (API request)' })
    )
    expect(session.storage.addHistoryGrant).not.toHaveBeenCalledWith(
      expect.objectContaining({ actor: expect.anything() })
    )
  })

  it('records the self-declared agent name as the activity actor', async () => {
    const { EXTERNAL_REQUEST_ORIGIN } =
      await import('@/lib/walletRequest/externalRequest')
    state.zcaps = [{ id: 'urn:zcap:1', invocationTarget: 'https://was/x' }]
    const session = makeSession()
    const agentProfile = {
      didAuth: false,
      vcQueries: [],
      zcapRequests: [{ referenceId: 'web' }],
      appConnect: null,
      agent: { name: 'research-bot' }
    } as unknown as typeof profile

    await composeAndDeliverResponse({
      request: { query: [] } as unknown as Parameters<
        typeof composeAndDeliverResponse
      >[0]['request'],
      session,
      profile: agentProfile,
      requestOrigin: EXTERNAL_REQUEST_ORIGIN,
      selectedVCs: [],
      exchangeUrl: 'https://was.example/workflows/ephemeral/exchanges/1'
    })

    expect(session.storage.addHistoryGrant).toHaveBeenCalledWith(
      expect.objectContaining({
        origin: 'n/a (API request)',
        actor: { name: 'research-bot' }
      })
    )
  })

  describe('a request whose grants provision a collection', () => {
    const agentZcap = {
      id: 'urn:zcap:1',
      invocationTarget: 'https://was/space/s/agent-data/',
      parentCapability: 'urn:zcap:root:https%3A%2F%2Fwas%2Fspace%2Fs%2F',
      controller: 'did:key:zAgent'
    }
    const grantProfile = {
      didAuth: false,
      vcQueries: [],
      zcapRequests: [{ referenceId: 'agent-data' }],
      appConnect: null
    } as unknown as typeof profile

    it('persists the Grant before escrow, once, carrying the signed zcaps', async () => {
      state.provisions = true
      state.zcaps = [agentZcap]
      const session = makeSession()
      await respond({
        session,
        requestProfile: grantProfile,
        exchangeUrl: 'https://verifier.example/exchange/1'
      })
      expect(state.calls).toEqual([
        'processRequest',
        'addHistoryGrant',
        'provisionEncryptedCollection',
        'deliverPresentation'
      ])
      expect(session.storage.addHistoryGrant).toHaveBeenCalledTimes(1)
      expect(session.storage.addHistoryGrant).toHaveBeenCalledWith(
        expect.objectContaining({
          grants: [
            expect.objectContaining({ id: 'urn:zcap:1', zcap: agentZcap })
          ]
        })
      )
    })

    it('fails closed with nothing escrowed when the early persist fails', async () => {
      state.provisions = true
      state.zcaps = [agentZcap]
      state.historyThrows = true
      await expect(
        respond({
          requestProfile: grantProfile,
          exchangeUrl: 'https://verifier.example/exchange/1'
        })
      ).rejects.toMatchObject({ reason: 'processFailed' })
      expect(state.calls).toEqual(['processRequest', 'addHistoryGrant'])
    })

    it('removes the early Grant when provisioning fails after it', async () => {
      state.provisions = true
      state.zcaps = [agentZcap]
      state.provisionThrows = new Error('provisioning failed')
      const session = makeSession()
      await expect(
        respond({
          session,
          requestProfile: grantProfile,
          exchangeUrl: 'https://verifier.example/exchange/1'
        })
      ).rejects.toMatchObject({ reason: 'processFailed' })
      // Nothing is delivered, so the Grant naming the signed grant goes.
      expect(state.calls).toEqual([
        'processRequest',
        'addHistoryGrant',
        'provisionEncryptedCollection',
        'deleteHistoryActivity'
      ])
      expect(session.storage.addHistoryGrant).toHaveBeenCalledTimes(1)
      expect(session.storage.deleteHistoryActivity).toHaveBeenCalledWith({
        id: 'grant-1'
      })
    })

    it('keeps the original failure when the Grant removal fails', async () => {
      state.provisions = true
      state.zcaps = [agentZcap]
      state.provisionThrows = new Error('provisioning failed')
      state.deleteThrows = true
      const failure = await respond({ requestProfile: grantProfile }).catch(
        (err: unknown) => err
      )
      expect(failure).toMatchObject({ reason: 'processFailed' })
      expect((failure as Error).cause).toBe(state.provisionThrows)
      expect(state.calls.at(-1)).toBe('deleteHistoryActivity')
    })

    it('removes nothing when processing fails before any Grant persist', async () => {
      state.processThrows = new Error('boom')
      const session = makeSession()
      await expect(
        respond({ session, requestProfile: grantProfile })
      ).rejects.toMatchObject({ reason: 'processFailed' })
      expect(session.storage.deleteHistoryActivity).not.toHaveBeenCalled()
    })

    it('records the App Connect result on the early Grant', async () => {
      state.provisions = true
      state.zcaps = [agentZcap]
      state.appConnectResult = { firstRun: false }
      const session = makeSession()
      const appConnectProfile = {
        didAuth: true,
        vcQueries: [],
        zcapRequests: [],
        appConnect: {
          app: { name: 'Text Editor', appUrl: 'https://app.example/editor' },
          capabilityQueries: [{ referenceId: 'agent-data' }]
        }
      } as unknown as typeof profile

      await respond({ session, requestProfile: appConnectProfile })

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
    })
  })
})
