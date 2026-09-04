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
 * are asserted structurally rather than through a live signer.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined,
  calls: [] as string[],
  /** which kind the session's ceremony context resolves to, or none at all */
  kind: 'ladder' as 'enrolled' | 'ladder' | 'none',
  labelFails: false
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
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

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  setClientLabel: vi.fn(async () => {
    state.calls.push('setClientLabel')
    if (state.labelFails) {
      throw new Error('the labels store root-invokes')
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
import { setClientLabel } from '@interop/wallet-core/keys'
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
const LABELS_STORE = { isClientLabelsStore: true }

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
  const remoteStore = { clientLabelsStore: vi.fn(() => LABELS_STORE) }
  if (state.kind === 'enrolled') {
    return {
      kind: 'enrolled',
      remoteStore,
      pointer: POINTER,
      controller: 'did:key:z6MkAccountController',
      signer: { kind: 'client', updateKeys: CLIENT_UPDATE_KEYS },
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
    storage: { remoteStore: { isStore: true } },
    profile: { accountPointer: POINTER }
  } as unknown as Session
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
  state.calls = []
  state.kind = 'ladder'
  state.labelFails = false
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
      'reprimeVerifiedAccountLog'
    ])
    expect(vi.mocked(reprimeVerifiedAccountLog)).toHaveBeenCalledWith({
      profile: session.profile,
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
      signer: { kind: 'client', updateKeys: CLIENT_UPDATE_KEYS },
      clientKeyAgreementKey: CLIENT_KAK,
      userKeyRosterStore: ENROLLED_ROSTER_STORE,
      idStore: ROOT_ID_STORE
    })
  })
})

describe('the preconditions and the best-effort label', () => {
  it('throws before the ceremony when neither kind resolves', async () => {
    state.kind = 'none'
    await expect(
      approveEnrollment({ request: REQUEST, session: approvingSession() })
    ).rejects.toThrow('reached either from a connected browser')
    expect(vi.mocked(approveEnrollmentCore)).not.toHaveBeenCalled()
    expect(vi.mocked(accountCeremonyContext)).toHaveBeenCalledOnce()
  })

  it('writes the chosen label to the labels store', async () => {
    await approveEnrollment({
      request: REQUEST,
      session: approvingSession(),
      label: 'Old laptop'
    })
    expect(vi.mocked(setClientLabel)).toHaveBeenCalledWith({
      store: LABELS_STORE,
      signingKeyMultibase: 'z6MkEnrolleeClient',
      label: 'Old laptop'
    })
  })

  it('completes the approval when the label write fails', async () => {
    // Expected on the ladder kind today: the labels store root-invokes,
    // which a transient session's annex key cannot do. The listing degrades
    // to unlabeled rows rather than the ceremony reporting a failure.
    state.labelFails = true
    const approved = await approveEnrollment({
      request: REQUEST,
      session: approvingSession(),
      label: 'Old laptop'
    })
    expect(approved.clientDid).toBe('did:key:z6MkEnrolleeClient')
    expect(state.calls).toContain('setClientLabel')
  })

  it('skips the label write for a blank label', async () => {
    await approveEnrollment({
      request: REQUEST,
      session: approvingSession(),
      label: '   '
    })
    expect(vi.mocked(setClientLabel)).not.toHaveBeenCalled()
  })
})

describe('re-run convergence', () => {
  it('re-runs with the same connect code on the same arguments', async () => {
    // Every stage of the ceremony is idempotent and resumes from stored
    // state alone, so the approving half re-offers exactly what it offered
    // the first time; the one-request window the ladder branch leaves (the
    // new client standing with no roster wrap yet) is mended by this re-run.
    const session = approvingSession()
    await approveEnrollment({ request: REQUEST, session })
    const first = vi.mocked(approveEnrollmentCore).mock.calls[0]?.[0]

    await expect(
      approveEnrollment({ request: REQUEST, session })
    ).resolves.toMatchObject({ signingKeyMultibase: 'z6MkEnrolleeClient' })
    expect(vi.mocked(approveEnrollmentCore)).toHaveBeenCalledTimes(2)
    expect(vi.mocked(approveEnrollmentCore).mock.calls[1]?.[0]).toEqual(first)
  })
})
