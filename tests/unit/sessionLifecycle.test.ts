// @vitest-environment node
/**
 * The session's two lifecycle signals (`src/session/sessionLifecycle.ts`):
 * the disposal signal every teardown aborts, and the encounter gate's
 * openers. The gate's timing against a running mender block is covered
 * beside the block starter.
 */
import { describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'

vi.mock('@/stores/syncController', () => ({
  syncController: { stop: vi.fn(async () => {}) }
}))

const {
  armEncounterGate,
  disposeSession,
  isSessionDisposed,
  openEncounterGate,
  openEncounterGateBehindBlock,
  sessionDisposalSignal
} = await import('@/session/sessionLifecycle')
const { discardSession, closeUnenteredSession } =
  await import('@/stores/sessionTeardown')

/**
 * A session carrying a fresh disposal signal and a storage double.
 *
 * @returns {Session}
 */
function liveSession(): Session {
  return {
    storage: { close: vi.fn(async () => {}) },
    disposal: sessionDisposalSignal()
  } as unknown as Session
}

/**
 * Whether a promise has settled once pending callbacks have run.
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

describe('the disposal signal', () => {
  it('aborts once, idempotently, and only through disposeSession', () => {
    const session = liveSession()
    expect(isSessionDisposed({ session })).toBe(false)
    disposeSession({ session })
    disposeSession({ session })
    expect(session.disposal.aborted).toBe(true)
    expect(isSessionDisposed({ session })).toBe(true)
  })

  it('reads a session carrying no signal as live, and disposing it is a no-op', () => {
    const fixture = {} as Session
    expect(isSessionDisposed({ session: fixture })).toBe(false)
    expect(() => disposeSession({ session: fixture })).not.toThrow()
  })

  it('is aborted by a logout teardown and by releasing a never-entered session', async () => {
    const loggedOut = liveSession()
    await discardSession(loggedOut)
    expect(loggedOut.disposal.aborted).toBe(true)

    const unentered = liveSession()
    await closeUnenteredSession(unentered)
    expect(unentered.disposal.aborted).toBe(true)
  })
})

describe('the encounter gate openers', () => {
  it('opens behind registryReady, whether it resolves or rejects', async () => {
    const session = liveSession()
    armEncounterGate({ session, blockFollows: true })
    let fail: (err: Error) => void = () => undefined
    session.registryReady = new Promise<void>((_resolve, reject) => {
      fail = reject
    })
    openEncounterGateBehindBlock({ session })
    expect(await hasSettled(session.encounterGate)).toBe(false)
    fail(new Error('never, by contract, but the gate must not hang'))
    await expect(session.encounterGate).resolves.toBeUndefined()
  })

  it('opens on demand for a composition that decided to start no block', async () => {
    const session = liveSession()
    armEncounterGate({ session, blockFollows: true })
    expect(await hasSettled(session.encounterGate)).toBe(false)
    openEncounterGate({ session })
    await expect(session.encounterGate).resolves.toBeUndefined()
  })
})
