// @vitest-environment node
/**
 * Unit tests for the LADDER kind of the account-ceremony context
 * (`src/session/accountCeremonyContext.ts`) and the one refusal it adds.
 *
 * The context is the seam the credential ceremonies are bound through twice.
 * What matters here is which authority each member carries: a transient
 * session's account-log entries are signed by a rung of the credential's
 * ladder, its roster appends by that credential's ladder VM, its HTTP
 * requests invoked by the annex VM under the generation delegation, and
 * every delegation it mints signed by the ladder VM rather than by the annex
 * key, which the account document never lists. The kinds are asserted
 * structurally, so a wrapper that reached for the wrong signer fails here
 * rather than at a verifier.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined,
  rosterStoreCalls: [] as unknown[],
  unlockLogStoreCalls: [] as unknown[]
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  }
}))

vi.mock('@interop/wallet-core/clientAnnex', () => ({
  ladderVmAgent: vi.fn(async ({ ladderSeed }: { ladderSeed: Uint8Array }) => ({
    id: `did:key:z6MkLadderVm${ladderSeed[0]}`,
    getSigner: () => ({ id: 'ladder-vm-signer' })
  })),
  ladderVmZcapClient: vi.fn(async () => ({ isLadderVmZcapClient: true }))
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  didKeyZcapClient: vi.fn(({ keyAgent }: { keyAgent: { id: string } }) => ({
    isDidKeyZcapClient: true,
    keyAgentId: keyAgent.id
  }))
}))

vi.mock('@/session/rosterStore', () => ({
  sessionRosterStore: vi.fn((options: unknown) => {
    state.rosterStoreCalls.push(options)
    return { isRosterStore: true }
  })
}))

vi.mock('@/session/standingUnlock', () => ({
  unlockLogStore: vi.fn((options: unknown) => {
    state.unlockLogStoreCalls.push(options)
    return { isUnlockLogStore: true }
  })
}))

vi.mock('@/session/annexReach', () => ({
  renewTransientGenerationDelegation: vi.fn(async () => ({ renewed: true }))
}))

vi.mock('@/session/keyring', () => ({
  bindRemoteUnlockRecord: vi.fn(async () => ({ unlockSpaceId: 'unlock-space' }))
}))

import {
  accountCeremonyContext,
  canRunAccountCeremonies,
  enrolledCeremonyContext
} from '@/session/accountCeremonyContext'
import { sessionRosterStore } from '@/session/rosterStore'
import { unlockLogStore } from '@/session/standingUnlock'
import type { Session } from '@/types/auth'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

const LADDER_SEED = new Uint8Array(32).fill(7)
const GENERATION_DELEGATION = { id: 'urn:zcap:generation' }
const BRIDGE = { id: 'urn:zcap:bridge' }
const SIBLING = { id: 'urn:zcap:delegated-clients' }
const STANDING_KAK = { id: 'did:key:z6MkStanding#z6LSStanding' }

/**
 * A transient session on a standing credential: the ladder seed, the
 * standing members the login stamps, and the generation delegation every
 * request rides. An override key present with `undefined` pokes that hole.
 */
function ladderSession(
  overrides: Partial<{
    ladderSeed: Uint8Array | undefined
    standingUnlock: unknown
    invocationCapability: unknown
    isGuest: boolean
  }> = {}
): Session {
  return {
    user: { id: 'did:key:z6MkVisitKey' },
    isGuest: overrides.isGuest ?? false,
    storage: { remoteStore: { isStore: true } },
    profile: {
      zcapClient: { isAnnexVmZcapClient: true },
      accountPointer: POINTER,
      accountController: 'did:key:z6MkAccountController',
      ladderSeed:
        'ladderSeed' in overrides ? overrides.ladderSeed : LADDER_SEED,
      standingUnlock:
        'standingUnlock' in overrides
          ? overrides.standingUnlock
          : {
              delegation: BRIDGE,
              delegatedClients: SIBLING,
              standingClient: {
                agents: {
                  zcapClient: { isStandingClientZcapClient: true },
                  keyAgreementKey: STANDING_KAK
                },
                keyAgreementKeyMultibase: 'z6LSStanding'
              },
              unlockSpaceId: 'unlock-space-old'
            },
      unlockMethod: {
        type: 'passphrase',
        unlockSpaceId: 'unlock-space-old',
        manageCapability: { id: 'urn:zcap:manage' }
      },
      invocationCapability:
        'invocationCapability' in overrides
          ? overrides.invocationCapability
          : GENERATION_DELEGATION
    }
  } as unknown as Session
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
  state.rosterStoreCalls = []
  state.unlockLogStoreCalls = []
  vi.clearAllMocks()
})

describe('the ceremony context by kind', () => {
  it('resolves the ladder kind on a transient session with standing members', async () => {
    const session = ladderSession()
    const context = await accountCeremonyContext({ session })
    expect(context?.kind).toBe('ladder')
    expect(enrolledCeremonyContext({ session })).toBeNull()
  })

  it('resolves null for a guest, a store-less session, and a record with no standing members', async () => {
    expect(
      await accountCeremonyContext({
        session: ladderSession({ isGuest: true })
      })
    ).toBeNull()
    state.wasUrl = undefined
    expect(
      await accountCeremonyContext({ session: ladderSession() })
    ).toBeNull()
    state.wasUrl = 'https://was.example.test'
    expect(
      await accountCeremonyContext({
        session: ladderSession({ standingUnlock: undefined })
      })
    ).toBeNull()
    expect(
      await accountCeremonyContext({
        session: ladderSession({ ladderSeed: undefined })
      })
    ).toBeNull()
  })

  it('derives the gate from the same resolution', () => {
    expect(canRunAccountCeremonies({ session: ladderSession() })).toBe(true)
    expect(
      canRunAccountCeremonies({
        session: ladderSession({ standingUnlock: undefined })
      })
    ).toBe(false)
    expect(
      canRunAccountCeremonies({ session: ladderSession({ isGuest: true }) })
    ).toBe(false)
  })
})

describe("the ladder kind's authorities", () => {
  it('signs account-log entries with the ladder seed, through the bridge store', async () => {
    const context = await accountCeremonyContext({ session: ladderSession() })
    expect(context?.signer).toEqual({ kind: 'ladder', ladderSeed: LADDER_SEED })
    // The store is lazy: a gate that only asked for the kind builds none.
    expect(vi.mocked(unlockLogStore)).not.toHaveBeenCalled()
    expect(context?.idStore).toEqual({ isUnlockLogStore: true })
    expect(state.unlockLogStoreCalls[0]).toMatchObject({
      pointer: POINTER,
      delegation: BRIDGE,
      zcapClient: { isStandingClientZcapClient: true }
    })
  })

  it("signs roster appends with the credential's ladder VM, under the generation delegation", async () => {
    const context = await accountCeremonyContext({ session: ladderSession() })
    expect(vi.mocked(sessionRosterStore)).not.toHaveBeenCalled()
    expect(context?.rosterStore).toEqual({ isRosterStore: true })
    expect(state.rosterStoreCalls[0]).toMatchObject({
      capability: GENERATION_DELEGATION,
      keyAgent: { id: `did:key:z6MkLadderVm${LADDER_SEED[0]}` }
    })
  })

  it('invokes every request as the annex VM under the generation delegation', async () => {
    const context = await accountCeremonyContext({ session: ladderSession() })
    expect(context?.invoker).toEqual({
      zcapClient: { isAnnexVmZcapClient: true },
      capability: GENERATION_DELEGATION
    })
  })

  it('mints every delegation with the ladder VM rather than the annex key', async () => {
    const context = await accountCeremonyContext({ session: ladderSession() })
    if (context?.kind !== 'ladder') {
      throw new Error('expected the ladder kind')
    }
    expect(context.delegationSigner).toEqual({ isLadderVmZcapClient: true })
    // The single-verb child's delegatee and invoker: the ladder VM's own bare
    // did:key, which resolves from its own bytes and so outlives the Space.
    expect(context.ladderDeleter.zcapClient).toBe(context.delegationSigner)
    expect(context.ladderDeleter.controller).toBe(
      `did:key:z6MkLadderVm${LADDER_SEED[0]}`
    )
    expect(context.ladderDeleter.invoker).toMatchObject({
      isDidKeyZcapClient: true,
      keyAgentId: `did:key:z6MkLadderVm${LADDER_SEED[0]}`
    })
  })

  it('carries the record binder, the sibling, and the standing unwrap key', async () => {
    const context = await accountCeremonyContext({ session: ladderSession() })
    if (context?.kind !== 'ladder') {
      throw new Error('expected the ladder kind')
    }
    expect(typeof context.bindRecord).toBe('function')
    expect(context.sibling).toBe(SIBLING)
    expect(context.manageCapability).toEqual({ id: 'urn:zcap:manage' })
    expect(context.unlockSpaceId).toBe('unlock-space-old')
    expect(context.standingKeyAgreementKey).toBe(STANDING_KAK)
    expect(typeof context.renew).toBe('function')
  })

  it('invokes root when the visit holds no generation delegation', async () => {
    const context = await accountCeremonyContext({
      session: ladderSession({ invocationCapability: undefined })
    })
    expect(context?.invoker.capability).toBeUndefined()
    void context?.rosterStore
    expect(state.rosterStoreCalls[0]).not.toHaveProperty('capability')
  })
})

describe('the invoker after a mid-ceremony renewal', () => {
  /**
   * A ceremony that strikes the key which signed the generation delegation
   * replaces that delegation before its pivot and adopts it into the live
   * session, which rewrites `profile.invocationCapability`. Everything the
   * context hands out afterwards must ride the replacement: the one it was
   * resolved with is signed by a key the pivot has struck, so every
   * post-pivot request under it is refused.
   */
  const FRESH_DELEGATION = { id: 'urn:zcap:generation-fresh' }

  it('follows the live profile stamp rather than the resolution snapshot', async () => {
    const session = ladderSession()
    const context = await accountCeremonyContext({ session })
    expect(context?.invoker.capability).toBe(GENERATION_DELEGATION)
    session.profile.invocationCapability = FRESH_DELEGATION as never
    expect(context?.invoker.capability).toBe(FRESH_DELEGATION)
  })

  it('rebuilds the roster store on the replaced capability', async () => {
    const session = ladderSession()
    const context = await accountCeremonyContext({ session })
    void context?.rosterStore
    expect(state.rosterStoreCalls[0]).toMatchObject({
      capability: GENERATION_DELEGATION
    })
    session.profile.invocationCapability = FRESH_DELEGATION as never
    void context?.rosterStore
    expect(state.rosterStoreCalls).toHaveLength(2)
    expect(state.rosterStoreCalls[1]).toMatchObject({
      capability: FRESH_DELEGATION
    })
    // Unchanged between reads, the memo still holds: one store per
    // capability, not one per read.
    void context?.rosterStore
    expect(state.rosterStoreCalls).toHaveLength(2)
  })

  it('is what the enrolled kind reads live too', async () => {
    // The enrolled kind root-invokes, so its invoker carries no capability;
    // what it must not do is pin a stale signing client.
    const session = ladderSession()
    session.profile.clientWebvhKeys = { updateKeys: [] } as never
    session.profile.clientKeyAgreementKey = {
      id: 'did:key:z6LSclient'
    } as never
    session.profile.keyAgent = { id: 'did:key:z6MkClient' } as never
    const context = enrolledCeremonyContext({ session })
    expect(context?.invoker.capability).toBeUndefined()
    const swapped = { isRotatedZcapClient: true }
    session.profile.zcapClient = swapped as never
    expect(context?.invoker.zcapClient).toBe(swapped)
  })
})
