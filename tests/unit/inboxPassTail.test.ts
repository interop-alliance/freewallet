// @vitest-environment node
/**
 * Where the inbox pass runs (`src/session/menders/run.ts` and
 * `encounterSites.ts`): behind each login chain's block, on its own
 * `session.inboxPass`, which neither `registryReady` nor `mends` waits on;
 * never in the CHAPI popup, on a guest, or on a session with no Space; and
 * at the two encounter sites, each of which waits for the login's own pass
 * before running. The pass itself is a mock here: its behavior is
 * `inboxPass.test.ts`'s.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mendReportAccumulator } from '@interop/wallet-core/menders'
import type { MendReportEntry } from '@interop/wallet-core/menders'
import type { CeremonyId } from '@interop/wallet-core'
import type { Session } from '@/types/auth'
import type { LoginMenderDeps } from '@/session/menders/registrations'

vi.mock('@interop/wallet-core/menders', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/menders')>()),
  runMenderBlock: vi.fn(async () => [])
}))

vi.mock('@/session/inboxPass', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/inboxPass')>()),
  runInboxPass: vi.fn()
}))

import { runMenderBlock } from '@interop/wallet-core/menders'
import { runInboxPass } from '@/session/inboxPass'
import { startLoginMenderBlock } from '@/session/menders/run'
import {
  REMEMBERED_INBOX_TAIL,
  TRANSIENT_INBOX_TAIL
} from '@/session/menders/registrations'
import {
  openInboxNotifications,
  renewAgentGrantsAfterCeremony
} from '@/session/menders/encounterSites'

const { runMenderBlock: realRunMenderBlock } = await vi.importActual<
  typeof import('@interop/wallet-core/menders')
>('@interop/wallet-core/menders')

type Entries = [MendReportEntry<CeremonyId>, MendReportEntry<CeremonyId>]

/**
 * The two entries a pass reports, both of one outcome.
 *
 * @param outcome {'clean' | 'partial' | 'refused'}
 * @returns {Entries}
 */
function entriesOf(outcome: 'clean' | 'partial' | 'refused'): Entries {
  return [
    { invariant: 'inbox-is-drained', outcome },
    { invariant: 'agent-grants-are-current', outcome }
  ]
}

const EMPTY_OUTCOME = {
  invitations: [],
  renewalsPushed: [],
  refused: [],
  pushFailures: []
}

/**
 * A session bare enough for the starter and the encounter runner.
 *
 * @param [options] {object}
 * @param [options.space] {boolean}   whether it has a remote Space
 * @param [options.guest] {boolean}
 * @returns {Session}
 */
function fakeSession({
  space = true,
  guest = false
}: { space?: boolean; guest?: boolean } = {}): Session {
  return {
    profile: {},
    isGuest: guest,
    storage: { hasRemoteStorage: space },
    encounterGate: Promise.resolve()
  } as unknown as Session
}

/**
 * The chain deps the starter hands the runner unread.
 *
 * @param session {Session}
 * @param [chain] {'transient' | 'remembered'}
 * @returns {LoginMenderDeps}
 */
function fakeDeps(
  session: Session,
  chain: 'transient' | 'remembered' = 'transient'
): LoginMenderDeps {
  return {
    chain,
    session,
    found: {},
    context: async () => null,
    rosterRead: {},
    generationDelegation: {}
  } as unknown as LoginMenderDeps
}

/**
 * Whether a promise has settled, read after the pending callbacks run.
 *
 * @param promise {Promise<unknown>}
 * @returns {Promise<boolean>}
 */
async function hasSettled(promise: Promise<unknown>): Promise<boolean> {
  let settled = false
  void promise.then(() => {
    settled = true
  })
  await new Promise(resolve => setTimeout(resolve, 0))
  return settled
}

beforeEach(() => {
  vi.mocked(runInboxPass).mockReset()
  vi.mocked(runInboxPass).mockResolvedValue({
    entries: entriesOf('clean'),
    outcome: EMPTY_OUTCOME
  })
  vi.mocked(runMenderBlock).mockReset()
  // The block runs nothing; an inbox tail runs under the real runner.
  vi.mocked(runMenderBlock).mockImplementation(async options =>
    options.registrations === TRANSIENT_INBOX_TAIL ||
    options.registrations === REMEMBERED_INBOX_TAIL
      ? await realRunMenderBlock(options)
      : []
  )
})

describe('the login inbox tail', () => {
  it('runs neither the drain nor the renewal in the CHAPI popup', async () => {
    const session = fakeSession()
    startLoginMenderBlock({
      accumulator: mendReportAccumulator<CeremonyId>(),
      route: { popup: true },
      deps: fakeDeps(session)
    })

    await expect(session.inboxPass).resolves.toEqual([])
    expect(runInboxPass).not.toHaveBeenCalled()
  })

  it.each([
    ['a session with no Space', { space: false }],
    ['a guest', { guest: true }]
  ] as const)('runs none on %s', async (_label, shape) => {
    for (const chain of ['transient', 'remembered'] as const) {
      const session = fakeSession(shape)
      startLoginMenderBlock({
        accumulator: mendReportAccumulator<CeremonyId>(),
        route: { popup: false },
        deps: fakeDeps(session, chain)
      })

      await expect(session.inboxPass).resolves.toEqual([])
    }
    expect(runInboxPass).not.toHaveBeenCalled()
  })

  it.each(['transient', 'remembered'] as const)(
    'runs behind the %s block on its own promise, which mends does not wait on',
    async chain => {
      let release: () => void = () => undefined
      vi.mocked(runInboxPass).mockImplementation(async () => {
        await new Promise<void>(resolve => {
          release = resolve
        })
        return { entries: entriesOf('partial'), outcome: EMPTY_OUTCOME }
      })
      const session = fakeSession()
      startLoginMenderBlock({
        accumulator: mendReportAccumulator<CeremonyId>(),
        route: { popup: false },
        deps: fakeDeps(session, chain)
      })

      await session.registryReady
      await session.mends
      expect(await hasSettled(session.inboxPass!)).toBe(false)
      release()
      expect(
        (await session.inboxPass)!.map(entry => [
          entry.invariant,
          entry.outcome
        ])
      ).toEqual([
        ['inbox-is-drained', 'partial'],
        ['agent-grants-are-current', 'partial']
      ])
      expect(runInboxPass).toHaveBeenCalledTimes(1)
    }
  )
})

describe('the inbox encounters', () => {
  it("wait for the login's own pass, and renew nothing beside it", async () => {
    let release: () => void = () => undefined
    const session = fakeSession()
    session.inboxPass = new Promise(resolve => {
      release = () => resolve([])
    })

    const raised = renewAgentGrantsAfterCeremony({ session })

    expect(await hasSettled(raised)).toBe(false)
    expect(runInboxPass).not.toHaveBeenCalled()
    release()
    expect((await raised).entries).toEqual(entriesOf('clean'))
    expect(runInboxPass).toHaveBeenCalledTimes(1)
  })

  it('leave the budget unspent on a partial run, and spend it on a refused one', async () => {
    const session = fakeSession()
    vi.mocked(runInboxPass).mockResolvedValue({
      entries: entriesOf('partial'),
      outcome: EMPTY_OUTCOME
    })

    await openInboxNotifications({ session })
    await openInboxNotifications({ session })
    expect(runInboxPass).toHaveBeenCalledTimes(2)

    vi.mocked(runInboxPass).mockResolvedValue({
      entries: entriesOf('refused'),
      outcome: EMPTY_OUTCOME
    })
    await openInboxNotifications({ session })
    await openInboxNotifications({ session })
    expect(runInboxPass).toHaveBeenCalledTimes(3)

    // The ceremony site runs past the spent budget: a fresh delegation is
    // evidence no earlier run saw.
    await renewAgentGrantsAfterCeremony({ session })
    expect(runInboxPass).toHaveBeenCalledTimes(4)
  })
})
