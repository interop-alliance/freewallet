/**
 * Zustand store holding the one in-flight account-setup run: the ordered
 * ceremony steps the Lobby page renders, and the run's outcome. It lives
 * outside the React tree on purpose -- the signup wizard starts the ceremony
 * inside its click handler (the passkey path needs the WebAuthn user
 * gesture) and navigates to `/lobby` at once, so the promise outlives the
 * page that started it. In-memory only; not persisted, so a reload leaves no
 * run and the Lobby page routes back to the wizard.
 *
 * The lobby is the run's one consumer, so a lobby that unmounts while the run
 * is still going marks it abandoned: the settled run then tears its session
 * down and empties the store, rather than parking a live session here for a
 * later `/lobby` mount to enter.
 *
 * The step list is a fixed order per signup path AND per deployment (the
 * ceremonies a no-WAS signup runs are not the ones a WAS signup runs), and
 * the ceremonies report stage boundaries through the observational
 * `StageNotifier` seam. A mark fires when a stage ENDS, so the Lobby shows
 * the first not-yet-marked step as the one currently running. Every action is
 * non-throwing: an unreported stage cannot tear the ceremony it watches, and
 * a name no list carries is warned about rather than displayed, so an
 * upstream rename shows up in the log instead of silently freezing the feed.
 */
import { create } from 'zustand'
import {
  CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGE_ALIASES,
  CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGES
} from '@interop/wallet-core/clientAnnex'
import type { CredentialAnchoredEstablishmentStage } from '@interop/wallet-core/clientAnnex'
import type { Session } from '@/types/auth'
import { WAS_SERVER_URL } from '@/app.config'
import { createLogger } from '@/lib/log'
import { closeUnenteredSession } from '@/stores/sessionTeardown'
import { resetPrfRetryPrompt } from '@/stores/prfRetryStore'

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
 * The establishment stages that get no line of their own. `account-log-read`
 * names the stage-3 preamble, whose span is near-zero whenever the genesis's
 * own head is reused instead of read.
 */
const HIDDEN_ESTABLISHMENT_STAGES: readonly CredentialAnchoredEstablishmentStage[] =
  ['account-log-read']

/**
 * This app's own marks inside the establishment's run, each keyed by the
 * wallet-core stage it follows. They have no name upstream because their
 * bodies are freewallet's own closures: the KMS / did:web thunk runs inside
 * the genesis, and the unlock-methods registry write is the establishment's
 * `beforePromotion` hook. Keying on the upstream stage type is what makes an
 * upstream rename a type error here rather than a silently misplaced line.
 */
const APP_STAGES_IN_ESTABLISHMENT: Partial<
  Record<CredentialAnchoredEstablishmentStage, readonly string[]>
> = {
  'space-provisioning': ['did-web-keys'],
  'record-rebind': ['registry-write']
}

/**
 * The establishment's steps as the lobby lists them: wallet-core's own
 * ordered stage tuple, minus the hidden ones, with this app's marks spliced
 * in. Derived rather than re-declared, so the names and their order have one
 * home (`@interop/wallet-core/clientAnnex`).
 */
const ESTABLISHMENT_STEPS: readonly string[] =
  CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGES.flatMap(stage =>
    HIDDEN_ESTABLISHMENT_STAGES.includes(stage)
      ? []
      : [stage, ...(APP_STAGES_IN_ESTABLISHMENT[stage] ?? [])]
  )

/**
 * Every path's stage order, keyed by deployment and method. A signup on a
 * deployment with no WAS server runs none of the establishment, so listing
 * its stages there would show a feed of lines that can never be reported.
 *
 * Each list ends with a closing line for the wallet entry, which has no stage
 * name of its own: it is the current line from the last real mark until the
 * run settles. The WAS lists open with the signup-level marks
 * (`src/session/signup.ts`) and carry the establishment's steps between them;
 * the local lists are that module's own no-WAS marks throughout.
 */
export const SETUP_STAGE_LISTS: Record<
  'was' | 'local',
  Record<SetupMethod, readonly string[]>
> = {
  was: {
    passphrase: [
      'kdf',
      'existing-account-probe',
      ...ESTABLISHMENT_STEPS,
      'entering-wallet'
    ],
    // The WebAuthn ceremony first, then the same establishment and the
    // remembered login its self-enrollment runs. A fresh passkey cannot
    // collide with an existing account, so there is no existing-account probe.
    passkey: [
      'webauthn-create',
      'kdf',
      ...ESTABLISHMENT_STEPS,
      'remembered-login',
      'entering-wallet'
    ]
  },
  local: {
    passphrase: [
      'kdf',
      'existing-account-probe',
      'local-account-keys',
      'keyring-bind',
      'local-provisioning',
      'entering-wallet'
    ],
    // The no-WAS passkey flow mints the key set before the ceremony, and
    // registration and the keyring bind are one call, so they share a line.
    passkey: [
      'local-account-keys',
      'passkey-enrollment',
      'local-provisioning',
      'registry-write',
      'entering-wallet'
    ]
  }
}

/**
 * The lists this deployment's signups actually run.
 */
export const SETUP_STAGES: Record<SetupMethod, readonly string[]> =
  WAS_SERVER_URL ? SETUP_STAGE_LISTS.was : SETUP_STAGE_LISTS.local

/**
 * Stage names that share a line with an earlier one: wallet-core's own
 * aliases (the heal branch delivers the collection epochs off an adopted
 * roster instead of minting them) plus this app's -- the keystore promotion
 * is the second half of the same key-server stage.
 */
const STAGE_ALIASES: Record<string, string> = {
  ...CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGE_ALIASES,
  'keystore-promotion': 'did-web-keys'
}

/**
 * Names a signup legitimately reports that no list displays: the hidden
 * establishment stages, and the summary marks the signup module makes for its
 * own timing log. They are known, so they must not warn.
 */
const UNLISTED_STAGES: readonly string[] = [
  ...HIDDEN_ESTABLISHMENT_STAGES,
  'bootstrap-wiring',
  'establishment'
]

/**
 * Every stage name this app can legitimately report, across both deployments
 * and both methods. A name outside it is drift -- an upstream rename, or a
 * mark this store was never told about -- and warns.
 */
const KNOWN_STAGES: ReadonlySet<string> = new Set([
  ...Object.values(SETUP_STAGE_LISTS).flatMap(byMethod =>
    Object.values(byMethod).flat()
  ),
  ...Object.keys(STAGE_ALIASES),
  ...UNLISTED_STAGES
])

const log = createLogger('fw:session:setup')

/**
 * Marks a stage and everything before it done. Marking forward rather than
 * one line at a time is what keeps a skipped stage (no KMS configured, so
 * the key-server line never fires) from stalling the display on a step that
 * will never be reported.
 *
 * A name this path does not display leaves the steps untouched either way; an
 * unrecognised one warns on its way out, since the feed freezing on a stage
 * that will never be reported is exactly what a silent miss looks like.
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
    if (!KNOWN_STAGES.has(name)) {
      log.warn('A setup stage no step list carries was reported', { stage })
    }
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
  /**
   * Set when the lobby unmounts while the run is still going: nobody is left
   * to consume the outcome, so the settled run discards it instead of
   * parking it in this store.
   */
  abandoned: boolean
  beginSetup: (options: { method: SetupMethod }) => boolean
  markStage: (stage: string) => void
  finishSetup: (outcome: { session?: Session; userExists: boolean }) => void
  failSetup: (options: { errorKey: string | null }) => void
  attendSetup: () => void
  abandonSetup: () => void
  clearSetup: () => void
}

/**
 * Whether a run is going: registered, and not yet settled. The signup
 * wizard's submit button reads it, so a wizard remounted behind a live run
 * (a browser Back out of the lobby) shows itself busy rather than offering a
 * second run.
 *
 * @param state {object}
 * @param state.method {SetupMethod | null}
 * @param state.result {SetupResult}
 * @returns {boolean}
 */
export function setupInFlight(state: {
  method: SetupMethod | null
  result: SetupResult
}): boolean {
  return state.method !== null && state.result.kind === 'pending'
}

/**
 * The empty store: no run registered, nothing to consume.
 */
const NO_RUN = {
  method: null,
  steps: [],
  result: { kind: 'pending' },
  abandoned: false
} as const satisfies Partial<SetupState>

export const useSetupStore = create<SetupState>()((set, get) => ({
  ...NO_RUN,
  beginSetup: ({ method }) => {
    // One run at a time. A second "Create Wallet" while the first is going
    // (the wizard remounted behind the lobby) would share this one store and
    // race the first run's outcome, so it is refused here rather than
    // guarded at each call site.
    if (setupInFlight(get())) {
      return false
    }
    set({
      method,
      steps: SETUP_STAGES[method].map(stage => ({ stage, done: false })),
      result: { kind: 'pending' },
      abandoned: false
    })
    return true
  },
  markStage: stage =>
    set(state => ({ steps: markStageIn({ steps: state.steps, stage }) })),
  finishSetup: outcome => {
    if (get().abandoned) {
      // Nobody is waiting on this session: the lobby that would have entered
      // it is gone. Parking it here would leave a live session in a module
      // store for a later `/lobby` mount to log in, so its storage is closed.
      void closeUnenteredSession(outcome.session ?? null)
      get().clearSetup()
      return
    }
    set(state => ({
      steps: state.steps.map(step =>
        step.done ? step : { ...step, done: true }
      ),
      result: { kind: 'done', ...outcome }
    }))
  },
  failSetup: ({ errorKey }) => {
    if (get().abandoned) {
      get().clearSetup()
      return
    }
    set({ result: { kind: 'failed', errorKey } })
  },
  attendSetup: () => {
    if (get().abandoned) {
      set({ abandoned: false })
    }
  },
  abandonSetup: () => {
    const { abandoned, result } = get()
    if (setupInFlight(get())) {
      if (abandoned) {
        return
      }
      set({ abandoned: true })
      // The run keeps going, but no page will render its consent dialog.
      resetPrfRetryPrompt()
      return
    }
    if (result.kind !== 'pending') {
      // Settled in the same pass that took the lobby away, so nothing
      // consumed it. Whatever it carries is discarded rather than parked.
      void closeUnenteredSession(
        result.kind === 'done' ? (result.session ?? null) : null
      )
      get().clearSetup()
    }
  },
  clearSetup: () => {
    set({ ...NO_RUN })
    resetPrfRetryPrompt()
  }
}))

/**
 * Registers a fresh setup run from outside a component (the signup wizard's
 * click handler, which starts the ceremony before it navigates away).
 * Refuses while a run is going, so the caller must not start its ceremony on
 * a `false`.
 *
 * @param options {object}
 * @param options.method {SetupMethod}
 * @returns {boolean}   whether the run was registered
 */
export function beginSetup(options: { method: SetupMethod }): boolean {
  return useSetupStore.getState().beginSetup(options)
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

/**
 * Drops whatever the store holds, from outside a component (the auth store's
 * logout). Also settles a pending PRF-retry prompt.
 */
export function clearSetup(): void {
  useSetupStore.getState().clearSetup()
}
