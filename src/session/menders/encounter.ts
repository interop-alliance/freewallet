/**
 * The encounter runner: how a mend raised at a read or a write inside a live
 * session runs, after the login chain has settled. An encounter site is a
 * registration listed under the `encounter` trigger. The page or the storage
 * callback that hits the evidence calls {@link runEncounter} with it, and the
 * runner applies the same try, warn, and skip discipline the login chains
 * run under (wallet-core's `runMenderRegistration`).
 *
 * In order, a run:
 *
 * 1. Checks the authority claim once, from the session's own key material.
 *    A session that does not hold every reported declaration's authority
 *    gets `refused` entries, and the converger is not called.
 * 2. Joins a run of the same registration already in flight on this session,
 *    and returns that run's entries. A run counts as in flight from the call
 *    on, so one still waiting at the gate is joined too.
 * 3. Waits on the session's encounter gate, so it never runs beside the
 *    login block's registry writers.
 * 4. Spends a once-per-session budget: a run that ended `failed` or
 *    `refused` is not run again in the same session. A later call gets that
 *    run's entries back. A caller holding evidence no earlier run saw may
 *    pass `freshEvidence` to run past a spent budget. A run that does not
 *    end `failed` or `refused` clears the budget.
 * 5. Runs the converger with the session. The converger checks the
 *    session's disposal signal before each write, and the runner checks it
 *    between its own steps.
 *
 * Every entry is reported into a per-run accumulator whose logger emits the
 * `'ceremony mender'` event. The events are diagnostics: nothing branches on
 * them. A page reads the entries the run's promise resolves to instead. The
 * promise always settles and never rejects.
 *
 * The in-flight runs and the budget live in module-private maps keyed by
 * session, so the session type carries no flag for them.
 */
import {
  mendReportAccumulator,
  runMenderRegistration,
  type InvariantId,
  type MendReport,
  type MendReportEntry,
  type MenderRegistry,
  type Registration,
  type RegistrationSite
} from '@interop/wallet-core/menders'
import type { CeremonyId } from '@interop/wallet-core'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'
import { isSessionDisposed } from '@/session/sessionLifecycle'
import { freewalletMenderRegistry } from './index.js'
import { heldFor } from './run.js'

const log = createLogger('fw:session:registry')

/**
 * The registry, read with the encounter deps. The declarations take no deps
 * of their own (their `Deps` is `never`), so the chain deps the registry is
 * typed with are only a label here.
 */
const registry = freewalletMenderRegistry as unknown as MenderRegistry<
  RegistrationSite,
  { session: Session },
  CeremonyId
>

/**
 * The runs in flight, per session and then per registration.
 */
const inFlight = new WeakMap<
  Session,
  Map<RegistrationSite, Promise<MendReport<CeremonyId>>>
>()

/**
 * The spent budgets, per session and then per registration: the entries of
 * the run that spent it.
 */
const spent = new WeakMap<
  Session,
  Map<RegistrationSite, MendReport<CeremonyId>>
>()

/**
 * The per-session map under a module-private WeakMap, created on first use.
 *
 * @param options {object}
 * @param options.store {WeakMap}
 * @param options.session {Session}
 * @returns {Map}
 */
function mapFor<Value>({
  store,
  session
}: {
  store: WeakMap<Session, Map<RegistrationSite, Value>>
  session: Session
}): Map<RegistrationSite, Value> {
  let map = store.get(session)
  if (!map) {
    map = new Map()
    store.set(session, map)
  }
  return map
}

/**
 * One entry per reported invariant, all of one outcome.
 *
 * @param options {object}
 * @param options.registration {RegistrationSite}
 * @param options.outcome {'refused' | 'noop'}
 * @param options.reason {string}
 * @returns {MendReport}
 */
function uniformEntries({
  registration,
  outcome,
  reason
}: {
  registration: RegistrationSite
  outcome: 'refused' | 'noop'
  reason: string
}): MendReport<CeremonyId> {
  return registration.reports.map(invariant => ({
    invariant,
    outcome,
    detail: { reason }
  }))
}

/**
 * Whether a run's entries spend the session's budget for its invariants.
 *
 * @param entries {MendReport}
 * @returns {boolean}
 */
function spendsBudget(entries: MendReport<CeremonyId>): boolean {
  return entries.some(
    (entry: MendReportEntry<CeremonyId>) =>
      entry.outcome === 'failed' || entry.outcome === 'refused'
  )
}

/**
 * Runs one encounter registration on a live session. See the module header
 * for the steps.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.registration {Registration}   an `encounter` registration
 * @param [options.freshEvidence] {boolean}   the caller holds evidence no
 *   earlier run of this registration saw (a collection newly recorded as
 *   stranded), so a spent budget does not stand this run down. A run in
 *   flight is still joined
 * @returns {Promise<MendReport>}   this run's entries, one per reported
 *   invariant; never rejects
 */
export async function runEncounter({
  session,
  registration,
  freshEvidence = false
}: {
  session: Session
  registration: Registration<{ session: Session }, CeremonyId>
  freshEvidence?: boolean
}): Promise<MendReport<CeremonyId>> {
  const mends = mendReportAccumulator<CeremonyId>({ logger: log })
  try {
    // (1) The authority claim, the one resolver the chains use.
    if (!registry.admits({ site: registration, held: heldFor({ session }) })) {
      const entries = uniformEntries({
        registration,
        outcome: 'refused',
        reason: 'authority-not-held'
      })
      entries.forEach(entry => mends.report(entry))
      return entries
    }
    // (2) One run per session and invariant at a time. Registered before the
    // gate wait, so a caller joining while the run still waits there joins
    // it too.
    const flights = mapFor({ store: inFlight, session })
    const running = flights.get(registration)
    if (running) {
      return await running
    }
    const run = (async (): Promise<MendReport<CeremonyId>> => {
      // (3) Behind the login block's registry writers.
      await session.encounterGate
      if (isSessionDisposed({ session })) {
        return uniformEntries({
          registration,
          outcome: 'noop',
          reason: 'session-disposed'
        })
      }
      // (4) The budget.
      const budget = mapFor({ store: spent, session })
      const spentBy = budget.get(registration)
      if (spentBy && !freshEvidence) {
        log.debug('An encounter mend already failed in this session', {
          reports: [...registration.reports]
        })
        return spentBy
      }
      // (5) The converger, under the shared discipline.
      const { entries } = await runMenderRegistration({
        registry,
        registration,
        deps: { session },
        logger: log,
        mends
      })
      if (spendsBudget(entries)) {
        budget.set(registration, entries)
      } else {
        // A run past a spent budget that converged clears it.
        budget.delete(registration)
      }
      return entries
    })()
    flights.set(registration, run)
    try {
      return await run
    } finally {
      if (flights.get(registration) === run) {
        flights.delete(registration)
      }
    }
  } catch (err) {
    // Only a programming error reaches here (the registry refusing a site
    // it does not index); the page still gets a settled promise.
    log.warn('An encounter mend could not run', {
      reports: [...registration.reports],
      err
    })
    return registration.reports.map(invariant => ({
      invariant,
      outcome: 'failed' as const,
      errorName: 'EncounterRunError'
    }))
  }
}

/**
 * Waits for a run of the given invariant in flight on this session, whatever
 * its outcome. A ceremony that repairs the same state itself joins first, so
 * its own read sees what the encounter left. Never rejects.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.invariant {InvariantId}
 * @returns {Promise<void>}
 */
export async function joinEncounter({
  session,
  invariant
}: {
  session: Session
  invariant: InvariantId
}): Promise<void> {
  const flights = inFlight.get(session)
  if (!flights) {
    return
  }
  const joined = [...flights.entries()]
    .filter(([registration]) => registration.reports.includes(invariant))
    .map(([, run]) => run)
  await Promise.allSettled(joined)
}
