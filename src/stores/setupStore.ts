/**
 * Zustand store holding the one in-flight account-setup run: the ordered
 * ceremony steps the Lobby page renders, and the run's outcome. It lives
 * outside the React tree on purpose -- the signup wizard starts the ceremony
 * inside its click handler (the passkey path needs the WebAuthn user
 * gesture) and navigates to `/lobby` at once, so the promise outlives the
 * page that started it. In-memory only; not persisted, so a reload leaves no
 * run and the Lobby page routes back to the wizard.
 *
 * The step list is a fixed order per signup path, and the ceremonies report
 * stage boundaries through the observational `StageNotifier` seam. A mark
 * fires when a stage ENDS, so the Lobby shows the first not-yet-marked step
 * as the one currently running. Every action is non-throwing and an unknown
 * stage name is ignored: the notifier must never tear the ceremony it
 * watches.
 */
import { create } from 'zustand'
import type { Session } from '@/types/auth'

export type SetupMethod = 'passphrase' | 'passkey'

export interface SetupStep {
  /**
   * The ceremony stage name this line stands for.
   */
  stage: string
  done: boolean
}

/**
 * The run's outcome. `pending` while the ceremony is in flight; `done`
 * carries what `signUpWithPassphrase` / `signUpWithPasskey` returned;
 * `failed` carries the i18n key the signup wizard shows on its return, or
 * `null` for a silent failure (the user dismissed the passkey ceremony).
 */
export type SetupResult =
  | { kind: 'pending' }
  | { kind: 'done'; session?: Session; userExists: boolean }
  | { kind: 'failed'; errorKey: string | null }

/**
 * The passphrase signup's stage order: the two signup-level marks, the
 * credential-anchored establishment's own stages, and a closing line for
 * the transient entry (no stage name of its own -- it is the current line
 * from the last real mark until the run settles).
 */
const PASSPHRASE_STAGES = [
  'kdf',
  'existing-account-probe',
  'interim-bind',
  'space-provisioning',
  'did-web-keys',
  'webvh-genesis',
  'roster-genesis',
  'collection-epochs',
  'annex-generation',
  'record-rebind',
  'registry-write',
  'controller-promotion',
  'entering-wallet'
] as const

/**
 * The passkey signup's stage order: the WebAuthn ceremony first, then the
 * same establishment. A fresh passkey cannot collide with an existing
 * account, so there is no existing-account probe.
 */
const PASSKEY_STAGES = [
  'webauthn-create',
  'kdf',
  'interim-bind',
  'space-provisioning',
  'did-web-keys',
  'webvh-genesis',
  'roster-genesis',
  'collection-epochs',
  'annex-generation',
  'record-rebind',
  'registry-write',
  'controller-promotion',
  'entering-wallet'
] as const

export const SETUP_STAGES: Record<SetupMethod, readonly string[]> = {
  passphrase: PASSPHRASE_STAGES,
  passkey: PASSKEY_STAGES
}

/**
 * Stage names that share a line with an earlier one. The heal branch
 * delivers the collection epochs off an adopted roster instead of minting
 * them, and the keystore promotion is the second half of the same key-server
 * stage; neither deserves a line of its own.
 */
const STAGE_ALIASES: Record<string, string> = {
  'roster-delivered-epochs': 'collection-epochs',
  'keystore-promotion': 'did-web-keys'
}

/**
 * Marks a stage and everything before it done. Marking forward rather than
 * one line at a time is what keeps a skipped stage (no KMS configured, so
 * the key-server line never fires) from stalling the display on a step that
 * will never be reported.
 *
 * @param options {object}
 * @param options.steps {SetupStep[]}   the run's ordered steps
 * @param options.stage {string}   the notified stage name
 * @returns {SetupStep[]}   the steps, or the same array when the stage name
 *   is not one this path displays
 */
function markStageIn({
  steps,
  stage
}: {
  steps: SetupStep[]
  stage: string
}): SetupStep[] {
  const name = STAGE_ALIASES[stage] ?? stage
  const index = steps.findIndex(step => step.stage === name)
  if (index === -1) {
    return steps
  }
  return steps.map((step, position) =>
    position <= index && !step.done ? { ...step, done: true } : step
  )
}

interface SetupState {
  method: SetupMethod | null
  steps: SetupStep[]
  result: SetupResult
  beginSetup: (options: { method: SetupMethod }) => void
  markStage: (stage: string) => void
  finishSetup: (outcome: { session?: Session; userExists: boolean }) => void
  failSetup: (options: { errorKey: string | null }) => void
  clearSetup: () => void
}

export const useSetupStore = create<SetupState>()(set => ({
  method: null,
  steps: [],
  result: { kind: 'pending' },
  beginSetup: ({ method }) =>
    set({
      method,
      steps: SETUP_STAGES[method].map(stage => ({ stage, done: false })),
      result: { kind: 'pending' }
    }),
  markStage: stage =>
    set(state => ({ steps: markStageIn({ steps: state.steps, stage }) })),
  finishSetup: outcome =>
    set(state => ({
      steps: state.steps.map(step =>
        step.done ? step : { ...step, done: true }
      ),
      result: { kind: 'done', ...outcome }
    })),
  failSetup: ({ errorKey }) => set({ result: { kind: 'failed', errorKey } }),
  clearSetup: () =>
    set({ method: null, steps: [], result: { kind: 'pending' } })
}))

/**
 * Registers a fresh setup run from outside a component (the signup wizard's
 * click handler, which starts the ceremony before it navigates away).
 *
 * @param options {object}
 * @param options.method {SetupMethod}
 */
export function beginSetup(options: { method: SetupMethod }): void {
  useSetupStore.getState().beginSetup(options)
}

/**
 * The `StageNotifier` the signup ceremonies are handed. Non-throwing by
 * construction, so a notifier can never tear the run it watches.
 *
 * @param stage {string}
 */
export function markSetupStage(stage: string): void {
  useSetupStore.getState().markStage(stage)
}

/**
 * Records a completed run's outcome.
 *
 * @param outcome {object}
 * @param [outcome.session] {Session}
 * @param outcome.userExists {boolean}
 */
export function finishSetup(outcome: {
  session?: Session
  userExists: boolean
}): void {
  useSetupStore.getState().finishSetup(outcome)
}

/**
 * Records a failed run.
 *
 * @param options {object}
 * @param options.errorKey {string | null}   the i18n key the signup wizard
 *   shows on its return, or `null` for a silent failure
 */
export function failSetup(options: { errorKey: string | null }): void {
  useSetupStore.getState().failSetup(options)
}
