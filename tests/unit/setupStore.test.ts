/**
 * The setup store: the stage ordering the lobby page renders while the
 * account-setup ceremony runs, and the run's lifecycle -- one run at a time,
 * and an abandoned run's outcome discarded rather than parked. A mark fires
 * when a stage ENDS, so the store marks the named stage and everything before
 * it done and the page shows the first not-yet-marked step as the running one.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
import { CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGES } from '@interop/wallet-core/clientAnnex'
import type { Session } from '@/types/auth'
import { closeUnenteredSession } from '@/stores/sessionTeardown'
import { promptForPrfRetry, usePrfRetryStore } from '@/stores/prfRetryStore'
import {
  SETUP_STAGE_LISTS,
  SETUP_STAGES,
  setupInFlight,
  useSetupStore,
  type SetupStep
} from '@/stores/setupStore'
import en from '@/i18n/locales/en.json'
import es from '@/i18n/locales/es.json'

vi.mock('@/stores/sessionTeardown', () => ({
  closeUnenteredSession: vi.fn(async () => {})
}))

// The step lists differ per deployment, and the unit environment configures
// no WAS server. Pinning one here keeps `SETUP_STAGES` the WAS pair, which is
// what these ordering tests walk; the no-WAS pair is asserted through
// `SETUP_STAGE_LISTS.local` directly.
vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  WAS_SERVER_URL: 'https://was.example'
}))

/**
 * A stand-in for the session a settled run carries. Only its identity
 * matters here: the store hands it to the teardown seam and holds nothing
 * else of it.
 *
 * @returns {Session}
 */
function fakeSession(): Session {
  return { user: { id: 'did:key:z-fake' } } as unknown as Session
}

/**
 * The store's current steps.
 *
 * @returns {SetupStep[]}
 */
function steps(): SetupStep[] {
  return useSetupStore.getState().steps
}

/**
 * The stage the lobby would show as running: the first not-yet-marked step.
 *
 * @returns {string | undefined}
 */
function running(): string | undefined {
  return steps().find(step => !step.done)?.stage
}

describe('setupStore stage ordering', () => {
  beforeEach(() => {
    useSetupStore.getState().clearSetup()
    vi.mocked(closeUnenteredSession).mockClear()
  })

  it('builds the passphrase path in order, ending at the wallet entry', () => {
    useSetupStore.getState().beginSetup({ method: 'passphrase' })
    expect(steps().map(step => step.stage)).toEqual([
      ...SETUP_STAGES.passphrase
    ])
    expect(steps().every(step => !step.done)).toBe(true)
    expect(running()).toBe('kdf')
  })

  it('puts the WebAuthn ceremony first on the passkey path', () => {
    useSetupStore.getState().beginSetup({ method: 'passkey' })
    expect(running()).toBe('webauthn-create')
    // A fresh passkey cannot collide with an existing account.
    expect(steps().map(step => step.stage)).not.toContain(
      'existing-account-probe'
    )
  })

  it('advances one step at a time as stages are marked', () => {
    const { beginSetup, markStage } = useSetupStore.getState()
    beginSetup({ method: 'passphrase' })
    markStage('kdf')
    expect(running()).toBe('existing-account-probe')
    markStage('existing-account-probe')
    expect(running()).toBe('interim-bind')
  })

  it('marks a skipped stage done when a later one is reported', () => {
    const { beginSetup, markStage } = useSetupStore.getState()
    beginSetup({ method: 'passphrase' })
    // No KMS configured, so the key-server stage never fires.
    markStage('webvh-genesis')
    expect(running()).toBe('roster-genesis')
    expect(steps().find(step => step.stage === 'did-web-keys')?.done).toBe(true)
  })

  it('ignores a known stage that carries no line of its own', () => {
    const { beginSetup, markStage } = useSetupStore.getState()
    const capture = captureSink()
    addSink(capture.sink)
    beginSetup({ method: 'passphrase' })
    markStage('kdf')
    // The establishment reports it and no list displays it: not drift.
    markStage('account-log-read')
    expect(running()).toBe('existing-account-probe')
    expect(capture.events).toEqual([])
  })

  it('warns on a stage name no list carries, and displays nothing', () => {
    const { beginSetup, markStage } = useSetupStore.getState()
    const capture = captureSink()
    addSink(capture.sink)
    beginSetup({ method: 'passphrase' })
    markStage('kdf')
    markStage('not-a-stage')
    expect(running()).toBe('existing-account-probe')
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        ns: 'fw:session:setup',
        level: 'warn',
        data: { stage: 'not-a-stage' }
      })
    )
  })

  it('derives the establishment steps from wallet-core, in order', () => {
    // The names and their order have one home: a rename upstream reaches the
    // lobby with no edit here, so the feed cannot silently freeze on a name
    // nothing reports any more.
    const upstream = CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGES.filter(
      // The one establishment stage the lobby hides.
      stage => stage !== 'account-log-read'
    )
    const listed = SETUP_STAGES.passphrase.filter(stage =>
      (upstream as readonly string[]).includes(stage)
    )
    expect(listed).toEqual([...upstream])
  })

  it('lists no establishment stage on a deployment with no WAS server', () => {
    // A no-WAS signup runs no establishment, so listing its stages there
    // would show a feed of lines that can never be reported.
    for (const stages of Object.values(SETUP_STAGE_LISTS.local)) {
      for (const stage of CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGES) {
        expect(stages).not.toContain(stage)
      }
    }
  })

  it('shares a line between a stage and its alias', () => {
    const { beginSetup, markStage } = useSetupStore.getState()
    beginSetup({ method: 'passphrase' })
    // The heal branch delivers the epochs off an adopted roster.
    markStage('roster-delivered-epochs')
    expect(running()).toBe('annex-generation')
    // The keystore promotion is the second half of the key-server stage.
    markStage('keystore-promotion')
    expect(running()).toBe('annex-generation')
  })

  it('records a completed run and marks every step done', () => {
    const { beginSetup, markStage, finishSetup } = useSetupStore.getState()
    beginSetup({ method: 'passphrase' })
    markStage('kdf')
    finishSetup({ userExists: false })
    expect(running()).toBeUndefined()
    expect(useSetupStore.getState().result).toEqual({
      kind: 'done',
      userExists: false
    })
  })

  it('records a failed run with the wizard error key', () => {
    const { beginSetup, failSetup } = useSetupStore.getState()
    beginSetup({ method: 'passkey' })
    failSetup({ errorKey: 'auth.errors.setupFailed' })
    expect(useSetupStore.getState().result).toEqual({
      kind: 'failed',
      errorKey: 'auth.errors.setupFailed'
    })
  })

  it('clears the run, so a reload finds nothing in flight', () => {
    const { beginSetup, clearSetup } = useSetupStore.getState()
    beginSetup({ method: 'passphrase' })
    clearSetup()
    expect(useSetupStore.getState().method).toBeNull()
    expect(steps()).toEqual([])
    expect(useSetupStore.getState().result).toEqual({ kind: 'pending' })
  })
})

describe('setupStore run lifecycle', () => {
  beforeEach(() => {
    useSetupStore.getState().clearSetup()
    vi.mocked(closeUnenteredSession).mockClear()
  })

  it('refuses a second run while one is going', () => {
    const { beginSetup, markStage } = useSetupStore.getState()
    expect(beginSetup({ method: 'passphrase' })).toBe(true)
    markStage('kdf')
    // The wizard remounted behind the lobby and submitted again.
    expect(beginSetup({ method: 'passkey' })).toBe(false)
    expect(useSetupStore.getState().method).toBe('passphrase')
    expect(
      useSetupStore.getState().steps.find(step => step.stage === 'kdf')?.done
    ).toBe(true)
  })

  it('reports a going run as in flight until it settles', () => {
    const { beginSetup, failSetup } = useSetupStore.getState()
    expect(setupInFlight(useSetupStore.getState())).toBe(false)
    beginSetup({ method: 'passphrase' })
    expect(setupInFlight(useSetupStore.getState())).toBe(true)
    failSetup({ errorKey: 'auth.errors.setupFailed' })
    expect(setupInFlight(useSetupStore.getState())).toBe(false)
  })

  it('takes a fresh run once the settled one is cleared', () => {
    const { beginSetup, finishSetup, clearSetup } = useSetupStore.getState()
    beginSetup({ method: 'passphrase' })
    finishSetup({ userExists: false })
    clearSetup()
    expect(beginSetup({ method: 'passkey' })).toBe(true)
    expect(useSetupStore.getState().method).toBe('passkey')
  })

  it('discards an abandoned run session instead of parking it', () => {
    const { beginSetup, abandonSetup, finishSetup } = useSetupStore.getState()
    const session = fakeSession()
    beginSetup({ method: 'passphrase' })
    // The lobby unmounted before the ceremony settled.
    abandonSetup()
    finishSetup({ session, userExists: false })
    expect(closeUnenteredSession).toHaveBeenCalledWith(session)
    // Nothing parked: a later `/lobby` mount finds no run to enter.
    expect(useSetupStore.getState().method).toBeNull()
    expect(useSetupStore.getState().result).toEqual({ kind: 'pending' })
    expect(useSetupStore.getState().abandoned).toBe(false)
  })

  it('clears an abandoned run that failed', () => {
    const { beginSetup, abandonSetup, failSetup } = useSetupStore.getState()
    beginSetup({ method: 'passkey' })
    abandonSetup()
    failSetup({ errorKey: 'auth.errors.setupFailed' })
    expect(useSetupStore.getState().method).toBeNull()
    expect(useSetupStore.getState().result).toEqual({ kind: 'pending' })
  })

  it('keeps the outcome for a lobby that came back', () => {
    const { beginSetup, abandonSetup, attendSetup, finishSetup } =
      useSetupStore.getState()
    const session = fakeSession()
    beginSetup({ method: 'passphrase' })
    // React's double-invoked effects: unmount then mount again.
    abandonSetup()
    attendSetup()
    finishSetup({ session, userExists: false })
    expect(closeUnenteredSession).not.toHaveBeenCalled()
    expect(useSetupStore.getState().result).toEqual({
      kind: 'done',
      session,
      userExists: false
    })
  })

  it('discards a run that settled with nobody watching', () => {
    const { beginSetup, finishSetup, abandonSetup } = useSetupStore.getState()
    const session = fakeSession()
    beginSetup({ method: 'passphrase' })
    // The outcome landed in the same pass that took the lobby away, so its
    // effect never consumed it.
    finishSetup({ session, userExists: false })
    abandonSetup()
    expect(closeUnenteredSession).toHaveBeenCalledWith(session)
    expect(useSetupStore.getState().method).toBeNull()
  })

  it('abandons nothing when the store is empty', () => {
    useSetupStore.getState().abandonSetup()
    expect(useSetupStore.getState().abandoned).toBe(false)
    expect(closeUnenteredSession).not.toHaveBeenCalled()
  })

  it('settles a pending PRF-retry prompt when the run is cleared', async () => {
    const { beginSetup, clearSetup } = useSetupStore.getState()
    beginSetup({ method: 'passkey' })
    const consented = promptForPrfRetry()
    expect(usePrfRetryStore.getState().open).toBe(true)
    clearSetup()
    await expect(consented).resolves.toBe(false)
    expect(usePrfRetryStore.getState().open).toBe(false)
  })

  it('settles a pending PRF-retry prompt when the run is abandoned', async () => {
    const { beginSetup, abandonSetup } = useSetupStore.getState()
    beginSetup({ method: 'passkey' })
    const consented = promptForPrfRetry()
    abandonSetup()
    await expect(consented).resolves.toBe(false)
    expect(usePrfRetryStore.getState().open).toBe(false)
  })
})

describe('the lobby step copy', () => {
  const stages = [
    ...new Set(
      Object.values(SETUP_STAGE_LISTS).flatMap(byMethod =>
        Object.values(byMethod).flat()
      )
    )
  ]

  it.each(stages)('has en and es copy for the %s step', stage => {
    // A displayed stage with no key renders the key itself in the feed.
    expect(en.auth.lobby.steps).toHaveProperty(stage)
    expect(es.auth.lobby.steps).toHaveProperty(stage)
  })
})
