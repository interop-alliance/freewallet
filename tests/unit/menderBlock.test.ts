// @vitest-environment node
/**
 * The block starter's own discipline (`src/session/menders/run.ts`), around
 * the runner rather than inside it: a rejecting runner still settles both of
 * the session's promises, a registration listed under the wrong trigger
 * refuses the block at construction, and a report fired beside the block
 * lands in `session.mends` before it settles.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Registration } from '@interop/wallet-core/menders'
import { mendReportAccumulator } from '@interop/wallet-core/menders'
import type { Session } from '@/types/auth'
import type { FreewalletCeremonyId } from '@/session/ceremonies'
import type { LoginMenderDeps } from '@/session/menders/registrations'

const state = vi.hoisted(() => ({
  transient: undefined as unknown[] | undefined
}))

vi.mock('@interop/wallet-core/menders', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/menders')>()),
  runMenderBlock: vi.fn(async () => [])
}))

vi.mock('@/session/menders/registrations', async importOriginal => {
  const actual =
    await importOriginal<typeof import('@/session/menders/registrations')>()
  return {
    ...actual,
    get TRANSIENT_REGISTRATIONS() {
      return state.transient ?? actual.TRANSIENT_REGISTRATIONS
    }
  }
})

import { runMenderBlock } from '@interop/wallet-core/menders'
import { startLoginMenderBlock } from '@/session/menders/run'

/**
 * A session bare enough for the starter: it reads the profile for the held
 * authorities and stamps the two promises on the object.
 */
function fakeSession(): Session {
  return { profile: {} } as unknown as Session
}

/**
 * The transient deps the starter hands the runner unread.
 */
function fakeDeps(session: Session): LoginMenderDeps {
  return {
    chain: 'transient',
    session,
    found: {},
    context: async () => null,
    rosterRead: {},
    generationDelegation: {}
  } as unknown as LoginMenderDeps
}

beforeEach(() => {
  vi.mocked(runMenderBlock).mockReset()
  vi.mocked(runMenderBlock).mockResolvedValue([])
  state.transient = undefined
})

describe('the block starter', () => {
  it('settles both promises when the runner itself rejects', async () => {
    vi.mocked(runMenderBlock).mockRejectedValue(
      new Error('A registration reports an undeclared invariant: nope')
    )
    const session = fakeSession()
    const accumulator = mendReportAccumulator<FreewalletCeremonyId>()

    startLoginMenderBlock({
      accumulator,
      route: { popup: false },
      deps: fakeDeps(session)
    })

    await expect(session.registryReady).resolves.toBeUndefined()
    await expect(session.mends).resolves.toEqual([])
  })

  it('refuses a block carrying a registration listed under another trigger', () => {
    const misfiled: Registration<LoginMenderDeps, FreewalletCeremonyId> = {
      trigger: 'remembered-login-chain',
      reports: ['app-keys-live-only-in-app-connections'],
      converge: async () => [
        { invariant: 'app-keys-live-only-in-app-connections', outcome: 'noop' }
      ]
    }
    state.transient = [misfiled]
    const session = fakeSession()

    expect(() =>
      startLoginMenderBlock({
        accumulator: mendReportAccumulator<FreewalletCeremonyId>(),
        route: { popup: false },
        deps: fakeDeps(session)
      })
    ).toThrow(/registered under remembered-login-chain/)
    expect(runMenderBlock).not.toHaveBeenCalled()
  })

  it('carries a report fired beside the block, which settles after it', async () => {
    const session = fakeSession()
    const accumulator = mendReportAccumulator<FreewalletCeremonyId>()
    // The did:web projection mend's shape: fired before the block, reporting
    // from its own `.then` a turn or more later. In the popup the block runs
    // empty and settles at once, so without the wait the entry would land
    // after the report was assembled.
    const projection = new Promise<void>(resolve => {
      setTimeout(() => {
        accumulator.report({
          invariant: 'did-web-projection-matches-the-log',
          outcome: 'clean'
        })
        resolve()
      }, 10)
    })

    startLoginMenderBlock({
      accumulator,
      route: { popup: true },
      deps: fakeDeps(session),
      pendingReports: [projection]
    })

    // `registryReady` does not wait on it.
    await session.registryReady
    expect((await session.mends)!.map(entry => entry.invariant)).toEqual([
      'did-web-projection-matches-the-log'
    ])
  })
})
