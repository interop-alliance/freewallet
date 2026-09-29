// @vitest-environment node
/**
 * The block starter's own discipline (`src/session/menders/run.ts`), around
 * the runner rather than inside it: a rejecting runner -- which is how a
 * registration listed under the wrong trigger surfaces -- still settles both
 * of the session's promises, a report fired beside the block lands in
 * `session.mends` before it settles, and the runner's mender events match
 * the entries `session.mends` carries.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mendReportAccumulator } from '@interop/wallet-core/menders'
import { createLogger } from '@/lib/log'
import type { Registration } from '@interop/wallet-core/menders'
import type { Session } from '@/types/auth'
import type { CeremonyId } from '@interop/wallet-core'
import type { LoginMenderDeps } from '@/session/menders/registrations'

vi.mock('@interop/wallet-core/menders', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/menders')>()),
  runMenderBlock: vi.fn(async () => [])
}))

import { runMenderBlock } from '@interop/wallet-core/menders'
import { startLoginMenderBlock } from '@/session/menders/run'
import { TRANSIENT_REGISTRATIONS } from '@/session/menders'
import { captureCeremonyEvents } from './ceremonyEventCapture'

const { runMenderBlock: realRunMenderBlock } = await vi.importActual<
  typeof import('@interop/wallet-core/menders')
>('@interop/wallet-core/menders')

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
})

describe('the block starter', () => {
  it('settles both promises when the runner itself rejects', async () => {
    vi.mocked(runMenderBlock).mockRejectedValue(
      new Error('A registration reports an undeclared invariant: nope')
    )
    const session = fakeSession()
    const accumulator = mendReportAccumulator<CeremonyId>()

    startLoginMenderBlock({
      accumulator,
      route: { popup: false },
      deps: fakeDeps(session)
    })

    await expect(session.registryReady).resolves.toBeUndefined()
    await expect(session.mends).resolves.toEqual([])
  })

  it('carries a report fired beside the block, which settles after it', async () => {
    const session = fakeSession()
    const accumulator = mendReportAccumulator<CeremonyId>()
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

describe("the runner's mender events", () => {
  let capture: ReturnType<typeof captureCeremonyEvents>
  beforeEach(() => {
    capture = captureCeremonyEvents()
  })
  afterEach(() => {
    capture.stop()
  })

  it('emits one event per entry session.mends carries, matching it', async () => {
    // The real runner over the real transient list, each registration's
    // converge stubbed: the first throws, the rest hold.
    const stubbed = TRANSIENT_REGISTRATIONS.map(
      (registration, index): Registration<LoginMenderDeps, CeremonyId> => ({
        ...registration,
        converge: async () => {
          if (index === 0) {
            throw new TypeError('a registration broke')
          }
          return registration.reports.map(invariant => ({
            invariant,
            outcome: 'noop' as const
          }))
        }
      })
    )
    vi.mocked(runMenderBlock).mockImplementation(options =>
      realRunMenderBlock({
        ...(options as Parameters<typeof realRunMenderBlock>[0]),
        registrations: stubbed as never
      })
    )
    const session = {
      profile: { ladderSeed: new Uint8Array(32), standingUnlock: {} }
    } as unknown as Session
    const accumulator = mendReportAccumulator<CeremonyId>({
      logger: createLogger('fw:session:transient')
    })

    startLoginMenderBlock({
      accumulator,
      route: { popup: false },
      deps: fakeDeps(session)
    })
    const mends = (await session.mends)!

    expect(mends.length).toBeGreaterThan(1)
    const events = capture.menders()
    expect(
      events.map(event => {
        const { invariant, outcome, errorName } = event.data as {
          invariant: string
          outcome: string
          errorName?: string
        }
        return { invariant, outcome, ...(errorName ? { errorName } : {}) }
      })
    ).toEqual(
      mends.map(({ invariant, outcome, errorName }) => ({
        invariant,
        outcome,
        ...(errorName ? { errorName } : {})
      }))
    )
    // The throwing registration's entries are failed, at error, carrying
    // the error's name and no error value.
    const failed = events.filter(
      event => (event.data as { outcome: string }).outcome === 'failed'
    )
    expect(failed.length).toBe(TRANSIENT_REGISTRATIONS[0]!.reports.length)
    for (const event of failed) {
      expect(event.level).toBe('error')
      expect(event.data).toMatchObject({ errorName: 'TypeError' })
      expect(event.err).toBeUndefined()
    }
    // A healthy check lands at debug.
    expect(
      events
        .filter(event => (event.data as { outcome: string }).outcome === 'noop')
        .every(event => event.level === 'debug')
    ).toBe(true)
  })
})
