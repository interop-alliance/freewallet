// @vitest-environment node
/**
 * Unit tests for the approving half of the client enrollment ceremony
 * (`approveEnrollment` in `src/lib/enrollment.ts`), which now runs on both
 * account-ceremony kinds.
 *
 * The ceremony body itself -- the roster escrow, the commit entry, the add
 * entry, and the escrow's placement by signer kind -- is wallet-core's and is
 * covered there. What is exercised here is the freewallet-side resolution:
 * which signer, which stores and which key-agreement key each kind hands
 * over. A remembered session enrolls with this client's own update keys and
 * its own key-agreement key; a transient session on a standing credential
 * enrolls with the credential's ladder, through the record's bridge store,
 * and unwraps every epoch with the credential's standing key. Handing the
 * wrong one over produces a capability that verifies nowhere, so the kinds
 * are asserted structurally rather than through a live signer. The
 * best-effort tail -- the `connections` entry, then the ClientConnect
 * activity row -- is asserted here too.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined,
  calls: [] as string[],
  /** which kind the session's ceremony context resolves to, or none at all */
  kind: 'ladder' as 'enrolled' | 'ladder' | 'none',
  labelFails: false,
  activityFails: false
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_BASE_URL() {
    return state.wasUrl
  }
}))

vi.mock('@interop/wallet-core/enrollment', () => ({
  approveEnrollment: vi.fn(async () => {
    state.calls.push('approveEnrollmentCore')
    return {
      did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
      clientDid: 'did:key:z6MkEnrolleeClient',
      signingKeyMultibase: 'z6MkEnrolleeClient'
    }
  }),
  completeEnrollmentCore: vi.fn(async () => ({ userKey: null }))
}))

vi.mock('@/session/clients', () => ({
  recordWalletClientEntry: vi.fn(async () => {
    state.calls.push('recordWalletClientEntry')
    if (state.labelFails) {
      throw new Error('the connections directory is refused')
    }
  })
}))

vi.mock('@/session/verifiedLog', () => ({
  invalidateVerifiedLog: vi.fn(() => {
    state.calls.push('invalidateVerifiedLog')
  }),
  reprimeVerifiedAccountLog: vi.fn(async () => {
    state.calls.push('reprimeVerifiedAccountLog')
  })
}))

vi.mock('@/session/keyring', () => ({
  bindPassphrase: vi.fn(async () => ({ unlockSpaceId: 'unlock-space' })),
  deriveUnlockCredential: vi.fn(async () => ({})),
  fetchKeyring: vi.fn(async () => null)
}))

vi.mock('@/session/initSession', () => ({
  loginWithPassphrase: vi.fn(async () => ({ session: null }))
}))

vi.mock('@/session/accountCeremonyContext', () => ({
  accountCeremonyContext: vi.fn(async () => ceremonyContext())
}))

import { approveEnrollment as approveEnrollmentCore } from '@interop/wallet-core/enrollment'
import type { EnrollmentRequest } from '@interop/wallet-core/enrollment'
import { recordWalletClientEntry } from '@/session/clients'
import { accountCeremonyContext } from '@/session/accountCeremonyContext'
import { reprimeVerifiedAccountLog } from '@/session/verifiedLog'
import { approveEnrollment } from '@/lib/enrollment'
import type { Session } from '@/types/auth'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

const LADDER_SEED = new Uint8Array(32).fill(7)
const CLIENT_UPDATE_KEYS = {
  updateSeed: new Uint8Array(32).fill(1),
  stagedSeed: new Uint8Array(32).fill(2)
}
/** the enrolled client's own key-agreement key: the enrolled kind's unwrapper */
const CLIENT_KAK = { id: 'did:key:z6MkThisClient#z6LSThisClient' }
/** the standing credential's key-agreement key: the ladder kind's unwrapper */
const STANDING_KAK = { id: 'did:key:z6MkStanding#z6LSStanding' }
const BRIDGE_ID_STORE = { isUnlockLogStore: true }
const ROOT_ID_STORE = { isWebvhIdStore: true }
const LADDER_ROSTER_STORE = { isLadderRosterStore: true }
const ENROLLED_ROSTER_STORE = { isEnrolledRosterStore: true }

/**
 * The connect code the enrollee minted, as the parse hands it over. Nothing
 * here is read by this module -- it is passed through to the ceremony -- so
 * only its identity matters for the assertions.
 */
const REQUEST = {
  clientDid: 'did:key:z6MkEnrolleeClient',
  signingKeyMultibase: 'z6MkEnrolleeClient',
  keyAgreementKeyMultibase: 'z6LSEnrolleeClient',
  updateKeyMultibase: 'z6MkEnrolleeUpdate',
  stagedKeyMultibase: 'z6MkEnrolleeStaged'
} as unknown as EnrollmentRequest

/**
 * The account-ceremony context this session resolves, by kind. The lazy
 * store getters the real context exposes are plain members here: what the
 * assertions care about is which store reaches the ceremony.
 *
 * @returns {object | null}
 */
function ceremonyContext(): object | null {
  if (state.kind === 'none') {
    return null
  }
  const remoteStore = { isRemoteStore: true }
  if (state.kind === 'enrolled') {
    return {
      kind: 'enrolled',
      remoteStore,
      pointer: POINTER,
      controller: 'did:key:z6MkAccountController',
      signer: { kind: 'enrolled', updateKeys: CLIENT_UPDATE_KEYS },
      idStore: ROOT_ID_STORE,
      rosterStore: ENROLLED_ROSTER_STORE,
      invoker: { zcapClient: { isZcapClient: true } },
      clientWebvhKeys: CLIENT_UPDATE_KEYS,
      clientKeyAgreementKey: CLIENT_KAK,
      keyAgent: { id: 'did:key:z6MkThisClient' }
    }
  }
  return {
    kind: 'ladder',
    remoteStore,
    pointer: POINTER,
    controller: 'did:key:z6MkAccountController',
    signer: { kind: 'ladder', ladderSeed: LADDER_SEED },
    ladderSeed: LADDER_SEED,
    idStore: BRIDGE_ID_STORE,
    rosterStore: LADDER_ROSTER_STORE,
    invoker: {
      zcapClient: { isAnnexVmZcapClient: true },
      capability: { id: 'urn:zcap:generation' }
    },
    standingKeyAgreementKey: STANDING_KAK,
    unlockSpaceId: 'unlock-space-old'
  }
}

/**
 * The approving session. Everything the module reads off it is the profile
 * the memo helpers take, since every authority comes off the context.
 *
 * @returns {Session}
 */
function approvingSession(): Session {
  return {
    user: { id: 'did:key:z6MkApprovingClient' },
    isGuest: false,
    storage: {
      remoteStore: { isStore: true },
      addHistoryClientConnected: vi.fn(async () => {
        state.calls.push('addHistoryClientConnected')
        if (state.activityFails) {
          throw new Error('the activity collection is refused')
        }
      })
    },
    profile: { accountPointer: POINTER }
  } as unknown as Session
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
  state.calls = []
  state.kind = 'ladder'
  state.labelFails = false
  state.activityFails = false
  vi.clearAllMocks()
})

describe('the ladder kind (a transient session on a standing credential)', () => {
  it("signs with the credential's ladder, through the record's bridge store", async () => {
    const approved = await approveEnrollment({
      request: REQUEST,
      session: approvingSession()
    })

    expect(vi.mocked(approveEnrollmentCore)).toHaveBeenCalledWith({
      request: REQUEST,
      signer: { kind: 'ladder', ladderSeed: LADDER_SEED },
      // The credential's standing key is what opens every epoch here: no
      // enrolled client's key-agreement key exists on this session.
      clientKeyAgreementKey: STANDING_KAK,
      // The capability-bound roster store, invoked by the annex VM under the
      // generation delegation.
      userKeyRosterStore: LADDER_ROSTER_STORE,
      // The bridge store: the record's PUT-on-`did.jsonl` delegation is the
      // credential's one way into the log.
      idStore: BRIDGE_ID_STORE
    })
    expect(approved.signingKeyMultibase).toBe('z6MkEnrolleeClient')
  })

  it('drops the memo before the ceremony and re-primes it after', async () => {
    const session = approvingSession()
    await approveEnrollment({ request: REQUEST, session })

    // The leading drop is load-bearing on this kind: the escrow append is
    // licensed only at the version the add entry mints, and the roster store
    // resolves its controller view through the memo. A view primed before the
    // entries (the listing that opened the dialog primes one) would anchor
    // the append at the pre-add head, which licenses nothing.
    expect(state.calls).toEqual([
      'invalidateVerifiedLog',
      'approveEnrollmentCore',
      'invalidateVerifiedLog',
      'reprimeVerifiedAccountLog',
      'recordWalletClientEntry',
      'addHistoryClientConnected'
    ])
    expect(vi.mocked(reprimeVerifiedAccountLog)).toHaveBeenCalledWith({
      session,
      pointer: POINTER
    })
  })

  it('drops the memo even when the ceremony throws part-way', async () => {
    // A torn approval may have published the commit entry before failing, so
    // no surface may keep reading a memo taken before it.
    vi.mocked(approveEnrollmentCore).mockRejectedValueOnce(
      new Error('the add entry lost its compare-and-swap')
    )
    await expect(
      approveEnrollment({ request: REQUEST, session: approvingSession() })
    ).rejects.toThrow('compare-and-swap')
    // The leading drop, then the `.finally`: the memo is dropped either way,
    // and the re-prime after it never runs.
    expect(state.calls).toEqual([
      'invalidateVerifiedLog',
      'invalidateVerifiedLog'
    ])
    expect(vi.mocked(reprimeVerifiedAccountLog)).not.toHaveBeenCalled()
  })
})

describe('the enrolled kind (a remembered session)', () => {
  beforeEach(() => {
    state.kind = 'enrolled'
  })

  it("signs with this client's own update keys and unwraps with its own key", async () => {
    await approveEnrollment({ request: REQUEST, session: approvingSession() })

    expect(vi.mocked(approveEnrollmentCore)).toHaveBeenCalledWith({
      request: REQUEST,
      signer: { kind: 'enrolled', updateKeys: CLIENT_UPDATE_KEYS },
      clientKeyAgreementKey: CLIENT_KAK,
      userKeyRosterStore: ENROLLED_ROSTER_STORE,
      idStore: ROOT_ID_STORE
    })
  })
})

describe('the preconditions and the best-effort entry write', () => {
  it('throws before the ceremony when neither kind resolves', async () => {
    state.kind = 'none'
    await expect(
      approveEnrollment({ request: REQUEST, session: approvingSession() })
    ).rejects.toThrow('reached either from a connected browser')
    expect(vi.mocked(approveEnrollmentCore)).not.toHaveBeenCalled()
    expect(vi.mocked(accountCeremonyContext)).toHaveBeenCalledOnce()
  })

  it("writes the offered name and the approver's edited label on the new client's entry", async () => {
    const session = approvingSession()
    await approveEnrollment({
      request: REQUEST,
      session,
      name: 'Wallet 2',
      label: 'Old laptop'
    })
    expect(vi.mocked(recordWalletClientEntry)).toHaveBeenCalledWith({
      session,
      did: 'did:key:z6MkEnrolleeClient',
      name: 'Wallet 2',
      label: 'Old laptop'
    })
  })

  it('writes the offered name alone when the approver did not edit it', async () => {
    const session = approvingSession()
    await approveEnrollment({ request: REQUEST, session, name: 'Wallet 2' })
    expect(vi.mocked(recordWalletClientEntry)).toHaveBeenCalledWith({
      session,
      did: 'did:key:z6MkEnrolleeClient',
      name: 'Wallet 2'
    })
  })

  it('completes the approval when the entry write fails', async () => {
    // The listing degrades to an unnamed row rather than the ceremony
    // reporting a failure.
    state.labelFails = true
    const approved = await approveEnrollment({
      request: REQUEST,
      session: approvingSession(),
      label: 'Old laptop'
    })
    expect(approved.clientDid).toBe('did:key:z6MkEnrolleeClient')
    expect(state.calls).toContain('recordWalletClientEntry')
  })

  it('writes no blank name or label', async () => {
    const session = approvingSession()
    await approveEnrollment({
      request: REQUEST,
      session,
      name: ' ',
      label: '   '
    })
    expect(vi.mocked(recordWalletClientEntry)).toHaveBeenCalledWith({
      session,
      did: 'did:key:z6MkEnrolleeClient'
    })
  })
})

describe('the best-effort ClientConnect activity', () => {
  it('records the connected client with the label the approver gave it', async () => {
    const session = approvingSession()
    await approveEnrollment({
      request: REQUEST,
      session,
      name: 'Wallet 2',
      label: 'Old laptop'
    })
    expect(session.storage.addHistoryClientConnected).toHaveBeenCalledWith({
      user: session.user,
      signingKeyMultibase: 'z6MkEnrolleeClient',
      clientDid: 'did:key:z6MkEnrolleeClient',
      label: 'Old laptop'
    })
  })

  it('records no label when the approver gave none or a blank one', async () => {
    const session = approvingSession()
    await approveEnrollment({
      request: REQUEST,
      session,
      name: 'Wallet 2',
      label: '   '
    })
    expect(session.storage.addHistoryClientConnected).toHaveBeenCalledWith({
      user: session.user,
      signingKeyMultibase: 'z6MkEnrolleeClient',
      clientDid: 'did:key:z6MkEnrolleeClient'
    })
  })

  it('records the activity after the connections entry is written', async () => {
    await approveEnrollment({ request: REQUEST, session: approvingSession() })
    expect(state.calls.slice(-2)).toEqual([
      'recordWalletClientEntry',
      'addHistoryClientConnected'
    ])
  })

  it('records the activity even when the entry write fails', async () => {
    state.labelFails = true
    await approveEnrollment({ request: REQUEST, session: approvingSession() })
    expect(state.calls.slice(-2)).toEqual([
      'recordWalletClientEntry',
      'addHistoryClientConnected'
    ])
  })

  it('completes the approval and warns when the activity write fails', async () => {
    state.activityFails = true
    const capture = captureSink()
    const removeSink = addSink(capture.sink)
    let approved
    try {
      approved = await approveEnrollment({
        request: REQUEST,
        session: approvingSession()
      })
    } finally {
      removeSink()
    }
    expect(approved.clientDid).toBe('did:key:z6MkEnrolleeClient')
    const warnings = capture.events.filter(
      event => event.ns === 'fw:enrollment' && event.level === 'warn'
    )
    expect(warnings).toHaveLength(1)
    expect(warnings[0]?.msg).toBe(
      'Could not record the client-connected activity'
    )
  })
})

describe('a re-run with the same connect code', () => {
  it('hands the ceremony the same arguments on each run', async () => {
    // The ceremony's own stages are idempotent and resume from stored state
    // alone, which is wallet-core's to test (the one-request window the
    // ladder branch leaves is mended by such a re-run). The binding's half is
    // that it keeps no state across calls: a re-run re-offers exactly what
    // the first run offered.
    const session = approvingSession()
    await approveEnrollment({ request: REQUEST, session })
    await approveEnrollment({ request: REQUEST, session })

    const calls = vi.mocked(approveEnrollmentCore).mock.calls
    expect(calls).toHaveLength(2)
    expect(calls[0]?.[0]).toBeDefined()
    expect(calls[1]?.[0]).toEqual(calls[0]?.[0])
  })
})
