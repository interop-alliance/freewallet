// @vitest-environment node
/**
 * Unit tests for the CHAPI `get` response sequence
 * (`src/lib/walletRequest/respond.ts`): the Login activity is persisted before
 * anything is delivered externally, a failed history write with granted
 * capabilities fails closed (nothing delivered), and the typed failure reasons
 * the popup renders. `processRequest` and the exchange delivery are mocked.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  calls: [] as string[],
  zcaps: [] as unknown[],
  processThrows: null as Error | null,
  historyThrows: false,
  deliverThrows: false,
  appConnectResult: undefined as { firstRun: boolean } | undefined
}))

class FakeZcapUnavailableError extends Error {}

vi.mock('@/lib/walletRequest/processZcaps', () => ({
  ZcapUnavailableError: FakeZcapUnavailableError
}))

vi.mock('@/lib/walletRequest/processRequest', () => ({
  processRequest: vi.fn(async () => {
    state.calls.push('processRequest')
    if (state.processThrows) {
      throw state.processThrows
    }
    return {
      verifiablePresentation: { type: 'VerifiablePresentation' },
      zcaps: state.zcaps,
      appConnect: state.appConnectResult
    }
  })
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
  state.deliverThrows = false
  state.appConnectResult = undefined
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
    expect(state.calls).toEqual(['processRequest', 'addHistoryLogin'])
  })

  it('still responds when the history write fails with no capabilities granted', async () => {
    state.historyThrows = true
    const response = await respond()
    expect(response.verifiablePresentation).toBeTruthy()
    expect(state.calls).toEqual(['processRequest', 'addHistoryLogin'])
  })

  it('reports an unavailable zcap target with its own reason', async () => {
    state.processThrows = new FakeZcapUnavailableError()
    const failure = await respond().catch((err: unknown) => err)
    expect(failure).toBeInstanceOf(WalletResponseFailure)
    expect((failure as InstanceType<typeof WalletResponseFailure>).reason).toBe(
      'zcapUnavailable'
    )
  })

  it('records the validated appUrl on an App Connect Login activity', async () => {
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

    expect(session.storage.addHistoryLogin).toHaveBeenCalledWith(
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

  it('reports a failed exchange delivery as such', async () => {
    state.deliverThrows = true
    await expect(
      respond({ exchangeUrl: 'https://verifier.example/exchange/1' })
    ).rejects.toMatchObject({ reason: 'exchangeFailed' })
  })
})
