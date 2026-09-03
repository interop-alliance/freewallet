/**
 * The setup store's stage ordering: what the lobby page renders while the
 * account-setup ceremony runs. A mark fires when a stage ENDS, so the store
 * marks the named stage and everything before it done and the page shows the
 * first not-yet-marked step as the running one.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import {
  SETUP_STAGES,
  useSetupStore,
  type SetupStep
} from '@/stores/setupStore'

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

  it('ignores an unknown stage name', () => {
    const { beginSetup, markStage } = useSetupStore.getState()
    beginSetup({ method: 'passphrase' })
    markStage('kdf')
    markStage('account-log-read')
    markStage('not-a-stage')
    expect(running()).toBe('existing-account-probe')
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
