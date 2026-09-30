// @vitest-environment node
/**
 * The encounter runner (`src/session/menders/encounter.ts`): the authority
 * stand-down, the wait on the session's encounter gate, the single flight
 * per session and invariant, the once-per-session budget, the try, warn, and
 * skip discipline, and the disposal signal. Outcomes are asserted on the
 * entries a run resolves to and on the logger output, since the login's
 * mend report never carries them.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
import type {
  MendReportEntry,
  Registration
} from '@interop/wallet-core/menders'
import type { CeremonyId } from '@interop/wallet-core'
import type { Session } from '@/types/auth'
import { captureCeremonyEvents } from './ceremonyEventCapture'

const { runEncounter, joinEncounter } =
  await import('@/session/menders/encounter')
const { MENDER_WARNINGS } = await import('@/session/menders/warnings')
const {
  armEncounterGate,
  disposeSession,
  isSessionDisposed,
  openEncounterGateBehindBlock,
  sessionDisposalSignal
} = await import('@/session/sessionLifecycle')

const INVARIANT = 'unlock-registry-opens-under-the-current-user-key' as const

/**
 * A live session of the given kind, its gate open unless a test arms it.
 *
 * @param [options] {object}
 * @param [options.kind] {'enrolled' | 'ladder' | 'guest'}
 * @returns {Session}
 */
function sessionOf({
  kind = 'enrolled'
}: { kind?: 'enrolled' | 'ladder' | 'guest' } = {}): Session {
  const profile =
    kind === 'enrolled'
      ? {
          clientWebvhKeys: { updateSeed: new Uint8Array(32) },
          clientKeyAgreementKey: { id: 'did:key:z6LSClient' },
          keyAgent: { id: 'did:key:z6MkClient' }
        }
      : kind === 'ladder'
        ? {
            ladderSeed: new Uint8Array(32),
            standingUnlock: { unlockSpaceId: 'unlock-space' }
          }
        : {}
  return {
    user: { id: 'did:key:z6MkClient' },
    isGuest: kind === 'guest',
    profile,
    disposal: sessionDisposalSignal(),
    encounterGate: Promise.resolve()
  } as unknown as Session
}

/**
 * An encounter registration over the one invariant these tests report, with
 * the given converger.
 *
 * @param converge {Function}
 * @returns {Registration}
 */
function registrationOf(
  converge: (deps: {
    session: Session
  }) => Promise<ReadonlyArray<MendReportEntry<CeremonyId>>>
): Registration<{ session: Session }, CeremonyId> {
  return {
    trigger: 'encounter',
    reports: [INVARIANT],
    reachedBy: ['remembered', 'transient'],
    converge: vi.fn(converge)
  }
}

/**
 * Lets pending callbacks run.
 *
 * @returns {Promise<void>}
 */
async function tick(): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, 0))
}

let stopCapture: (() => void) | undefined
afterEach(() => {
  stopCapture?.()
  stopCapture = undefined
})

describe('runEncounter', () => {
  it('stands a guest session down with refused entries and no call', async () => {
    const events = captureCeremonyEvents()
    stopCapture = events.stop
    const registration = registrationOf(async () => [
      { invariant: INVARIANT, outcome: 'clean' }
    ])
    const entries = await runEncounter({
      session: sessionOf({ kind: 'guest' }),
      registration
    })
    expect(entries).toEqual([
      {
        invariant: INVARIANT,
        outcome: 'refused',
        detail: { reason: 'authority-not-held' }
      }
    ])
    expect(registration.converge).not.toHaveBeenCalled()
    expect(events.menders(INVARIANT)).toHaveLength(1)
  })

  it('runs on both session kinds that hold the claimed authority', async () => {
    for (const kind of ['enrolled', 'ladder'] as const) {
      const registration = registrationOf(async () => [
        { invariant: INVARIANT, outcome: 'clean' }
      ])
      const entries = await runEncounter({
        session: sessionOf({ kind }),
        registration
      })
      expect(entries).toEqual([{ invariant: INVARIANT, outcome: 'clean' }])
      expect(registration.converge).toHaveBeenCalledTimes(1)
    }
  })

  it('waits on a pending registryReady before it runs', async () => {
    const session = sessionOf()
    let settleRegistry: () => void = () => undefined
    session.registryReady = new Promise<void>(resolve => {
      settleRegistry = resolve
    })
    armEncounterGate({ session, blockFollows: true })
    openEncounterGateBehindBlock({ session })
    const registration = registrationOf(async () => [
      { invariant: INVARIANT, outcome: 'clean' }
    ])
    const run = runEncounter({ session, registration })
    await tick()
    expect(registration.converge).not.toHaveBeenCalled()
    settleRegistry()
    expect(await run).toEqual([{ invariant: INVARIANT, outcome: 'clean' }])
    expect(registration.converge).toHaveBeenCalledTimes(1)
  })

  it('waits for a block that has not started yet', async () => {
    const session = sessionOf()
    // Armed for a block at construction; the block starts later.
    armEncounterGate({ session, blockFollows: true })
    const registration = registrationOf(async () => [
      { invariant: INVARIANT, outcome: 'clean' }
    ])
    const run = runEncounter({ session, registration })
    await tick()
    expect(registration.converge).not.toHaveBeenCalled()
    session.registryReady = Promise.resolve()
    openEncounterGateBehindBlock({ session })
    await run
    expect(registration.converge).toHaveBeenCalledTimes(1)
  })

  it('runs two concurrent encounters of the same invariant once', async () => {
    const session = sessionOf()
    let release: () => void = () => undefined
    const held = new Promise<void>(resolve => {
      release = resolve
    })
    const registration = registrationOf(async () => {
      await held
      return [{ invariant: INVARIANT, outcome: 'clean' }]
    })
    const first = runEncounter({ session, registration })
    const second = runEncounter({ session, registration })
    let joined = false
    const join = joinEncounter({ session, invariant: INVARIANT }).then(() => {
      joined = true
    })
    await tick()
    expect(joined).toBe(false)
    release()
    expect(await first).toEqual(await second)
    await join
    expect(registration.converge).toHaveBeenCalledTimes(1)
  })

  it('does not re-run a failed run in the same session, short of fresh evidence', async () => {
    const session = sessionOf()
    const failed = [
      {
        invariant: INVARIANT,
        outcome: 'failed' as const,
        detail: { reason: 'unrepaired' }
      }
    ]
    const registration = registrationOf(async () => failed)
    expect(await runEncounter({ session, registration })).toEqual(failed)
    expect(await runEncounter({ session, registration })).toEqual(failed)
    expect(registration.converge).toHaveBeenCalledTimes(1)
    await runEncounter({ session, registration, freshEvidence: true })
    expect(registration.converge).toHaveBeenCalledTimes(2)
    // Another session keeps its own budget.
    await runEncounter({ session: sessionOf(), registration })
    expect(registration.converge).toHaveBeenCalledTimes(3)
  })

  it('clears a spent budget once a fresh-evidence run comes back clean', async () => {
    const session = sessionOf()
    const failed = [
      {
        invariant: INVARIANT,
        outcome: 'failed' as const,
        detail: { reason: 'unrepaired' }
      }
    ]
    const clean = [{ invariant: INVARIANT, outcome: 'clean' as const }]
    const converge = vi
      .fn<
        (deps: { session: Session }) => Promise<MendReportEntry<CeremonyId>[]>
      >()
      .mockResolvedValueOnce(failed)
      .mockResolvedValue(clean)
    const registration = registrationOf(converge)
    await runEncounter({ session, registration })
    expect(
      await runEncounter({ session, registration, freshEvidence: true })
    ).toEqual(clean)
    // No fresh evidence this time, and the earlier failure no longer
    // stands the run down.
    expect(await runEncounter({ session, registration })).toEqual(clean)
    expect(converge).toHaveBeenCalledTimes(3)
  })

  it('re-runs a clean run on the next encounter', async () => {
    const session = sessionOf()
    const registration = registrationOf(async () => [
      { invariant: INVARIANT, outcome: 'clean' }
    ])
    await runEncounter({ session, registration })
    await runEncounter({ session, registration })
    expect(registration.converge).toHaveBeenCalledTimes(2)
  })

  it('returns failed entries and logs the declared warn when the converger throws', async () => {
    const capture = captureSink()
    const remove = addSink(capture.sink)
    stopCapture = remove
    const session = sessionOf()
    const registration = registrationOf(async () => {
      throw Object.assign(new Error('the host went away'), {
        name: 'HostGoneError'
      })
    })
    const entries = await runEncounter({ session, registration })
    expect(entries).toEqual([
      expect.objectContaining({
        invariant: INVARIANT,
        outcome: 'failed',
        errorName: 'HostGoneError'
      })
    ])
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        ns: 'fw:session:registry',
        level: 'warn',
        msg: MENDER_WARNINGS[INVARIANT]
      })
    )
    // A throw spends the budget like any failure.
    await runEncounter({ session, registration })
    expect(registration.converge).toHaveBeenCalledTimes(1)
  })

  it('hands the converger the session', async () => {
    const session = sessionOf()
    const registration = registrationOf(async deps => {
      expect(deps).toEqual({ session })
      return [{ invariant: INVARIANT, outcome: 'noop' }]
    })
    await runEncounter({ session, registration })
    expect(registration.converge).toHaveBeenCalledTimes(1)
  })

  it('writes nothing once the session is disposed while it waits at the gate', async () => {
    const session = sessionOf()
    armEncounterGate({ session, blockFollows: true })
    const registration = registrationOf(async () => [
      { invariant: INVARIANT, outcome: 'clean' }
    ])
    const run = runEncounter({ session, registration })
    await tick()
    disposeSession({ session })
    session.registryReady = Promise.resolve()
    openEncounterGateBehindBlock({ session })
    expect(await run).toEqual([
      {
        invariant: INVARIANT,
        outcome: 'noop',
        detail: { reason: 'session-disposed' }
      }
    ])
    expect(registration.converge).not.toHaveBeenCalled()
  })

  it('lets a converger in flight see the abort before its next write', async () => {
    const session = sessionOf()
    let release: () => void = () => undefined
    const held = new Promise<void>(resolve => {
      release = resolve
    })
    const writes: string[] = []
    const registration = registrationOf(async ({ session }) => {
      await held
      if (isSessionDisposed({ session })) {
        return [
          {
            invariant: INVARIANT,
            outcome: 'noop',
            detail: { reason: 'session-disposed' }
          }
        ]
      }
      writes.push('write')
      return [{ invariant: INVARIANT, outcome: 'clean' }]
    })
    const run = runEncounter({ session, registration })
    await tick()
    // A popup page's teardown, or a logout.
    disposeSession({ session })
    release()
    await run
    expect(writes).toEqual([])
  })
})
