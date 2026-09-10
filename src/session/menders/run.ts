/**
 * The two login chains' one runner call. Each composition builds its deps,
 * whose chain picks the registration list, and gets back the two
 * promises a session carries: `registryReady`, settling when the
 * registry-writing registrations have reported, and `mends`, settling when
 * the whole block has.
 *
 * The discipline is wallet-core's: registration order is execution order, a
 * seed failure aborts the block, and a registration that throws warns with
 * the declared `warn` of every invariant it reports and the block carries
 * on. Neither promise rejects.
 */
import {
  heldAuthorities,
  runMenderBlock,
  type Authority,
  type ChainTrigger,
  type InvariantId,
  type LoginRoute,
  type MendReportAccumulator,
  type Registration
} from '@interop/wallet-core/menders'
import type { Session } from '@/types/auth'
import type { FreewalletCeremonyId } from '@/session/ceremonies'
import {
  accountCeremonyContext,
  sessionAuthorityKind,
  type AccountCeremonyContext
} from '@/session/accountCeremonyContext'
import { createLogger } from '@/lib/log'
import { freewalletMenderRegistry } from './index.js'
import {
  REMEMBERED_REGISTRATIONS,
  REMEMBERED_REGISTRY_REGISTRATIONS,
  REMEMBERED_SEED,
  TRANSIENT_REGISTRATIONS,
  type LoginMenderDeps
} from './registrations.js'

const log = createLogger('fw:session:registry')

/**
 * The account-ceremony context this block reads, resolved on first call and
 * kept until a registration drops it. The invalidator is the block's
 * re-resolution point: a registration that lands the authority a later one
 * needs drops the memo, so the later one resolves against the state the
 * first made available (`decisions/0027`). Today the pointer heal is the
 * one dropper, and no registration behind it reads the context, so the drop
 * is what keeps a registration added there correct rather than something
 * the present list depends on.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {object}   the accessor and its invalidator
 */
export function blockCeremonyContext({ session }: { session: Session }): {
  context: () => Promise<AccountCeremonyContext | null>
  refreshContext: () => void
} {
  let pending: Promise<AccountCeremonyContext | null> | undefined
  return {
    context: () => (pending ??= accountCeremonyContext({ session })),
    refreshContext: () => {
      pending = undefined
    }
  }
}

/**
 * The authorities this session holds, for the registry's `dueAt` filter.
 *
 * The kind comes from the session's own key material rather than from a
 * resolved account-ceremony context. Where a context resolves, the two agree
 * by construction: the resolution reads the same profile members and prefers
 * the same kind. Where it does not, the preconditions the resolution adds --
 * a promoted account pointer, a configured storage server with a remote
 * store -- are exactly the states this block's identity repairs converge,
 * and the shared registry passes are declared to run in those states anyway,
 * so filtering on them would stand those registrations down on the state
 * they exist to fix. Reading the session alone also keeps the block's start
 * synchronous, so no registration is entered before the login returns.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {ReadonlyArray<Authority>}
 */
function heldFor({ session }: { session: Session }): ReadonlyArray<Authority> {
  const kind = sessionAuthorityKind({ session })
  return heldAuthorities({ ...(kind ? { kind } : {}) })
}

/**
 * Starts one chain's block, stamping `session.registryReady` and
 * `session.mends` before it awaits anything, so a caller that returns the
 * session at once finds both.
 *
 * The two settle points are derived from the lists rather than named: the
 * ids the registry-writing registrations report are what `registryReady`
 * waits for, and the block's own completion settles both (a filtered-out
 * registration reports nothing, and the block always finishes).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.accumulator {MendReportAccumulator}   the report the
 *   routing entries already reported into
 * @param options.trigger {ChainTrigger}
 * @param options.route {LoginRoute}
 * @param options.deps {LoginMenderDeps}
 * @param options.registrations {ReadonlyArray<Registration>}   the block, in
 *   execution order
 * @param options.registryWriting {ReadonlyArray<Registration>}   the prefix
 *   of that list whose reports `registryReady` waits for
 * @param options.held {ReadonlyArray<Authority>}
 * @param [options.seed] {Registration}   the step whose failure aborts
 * @param [options.pendingReports] {ReadonlyArray<Promise<unknown>>}   the
 *   reports fired beside the block, awaited before `session.mends` settles
 *   so a report landing after the block still rides it. `registryReady`
 *   does not wait on them
 * @returns {void}
 */
function startMenderBlock({
  session,
  accumulator,
  trigger,
  route,
  deps,
  registrations,
  registryWriting,
  held,
  seed,
  pendingReports
}: {
  session: Session
  accumulator: MendReportAccumulator<FreewalletCeremonyId>
  trigger: ChainTrigger
  route: LoginRoute
  deps: LoginMenderDeps
  registrations: ReadonlyArray<
    Registration<LoginMenderDeps, FreewalletCeremonyId>
  >
  registryWriting: ReadonlyArray<
    Registration<LoginMenderDeps, FreewalletCeremonyId>
  >
  held: ReadonlyArray<Authority>
  seed?: Registration<LoginMenderDeps, FreewalletCeremonyId>
  pendingReports?: ReadonlyArray<Promise<unknown>>
}): void {
  // The awaited set is derived through `dueAt`, which filters by trigger,
  // while the runner's own override path does not: a registration listed
  // under the wrong trigger would run and never be awaited. It is a
  // programming error either way, so the block refuses to start.
  for (const registration of [
    ...(seed ? [seed] : []),
    ...registrations,
    ...registryWriting
  ]) {
    if (registration.trigger !== trigger) {
      throw new Error(
        `A mender registration listed in the ${trigger} block is registered ` +
          `under ${registration.trigger}; it reports ` +
          `${registration.reports.join(', ')}.`
      )
    }
  }
  const due = new Set(freewalletMenderRegistry.dueAt({ held, trigger, route }))
  const awaited = new Set<InvariantId>()
  for (const registration of [...(seed ? [seed] : []), ...registryWriting]) {
    if (due.has(registration)) {
      for (const id of registration.reports) {
        awaited.add(id)
      }
    }
  }
  let settleRegistry: () => void = () => undefined
  session.registryReady = new Promise<void>(resolve => {
    settleRegistry = resolve
  })
  session.mends = accumulator.settled
  if (awaited.size === 0) {
    settleRegistry()
  }
  void runMenderBlock({
    registry: freewalletMenderRegistry,
    trigger,
    held,
    route,
    deps,
    logger: log,
    registrations,
    ...(seed ? { seed } : {}),
    onOutcome: entry => {
      accumulator.report(entry)
      awaited.delete(entry.invariant)
      if (awaited.size === 0) {
        settleRegistry()
      }
    }
  })
    .catch(err => {
      // The runner rejects on a programming error alone (an undeclared
      // invariant), and neither promise may hang on one.
      log.warn('The login mender block could not run', { trigger, err })
    })
    .then(async () => {
      // The backstop for both: a seed failure ends the block with the
      // registry-writing entries unreported, and neither promise may hang.
      settleRegistry()
      if (pendingReports && pendingReports.length > 0) {
        await Promise.allSettled(pendingReports)
      }
      accumulator.settle()
    })
}

/**
 * Starts one login chain's block, selecting the registrations, the
 * registry-writing prefix, and the seed from the chain the deps name. The
 * remembered chain runs the provisioning seed, the six registry-writing
 * registrations, then the app-key sweep and the annex GC; the transient
 * chain runs the shared registry passes, then the acting credential's
 * management-zcap refresh, and has no seed, a transient session provisioning
 * nothing.
 *
 * @param options {object}
 * @param options.accumulator {MendReportAccumulator}
 * @param options.route {LoginRoute}
 * @param options.deps {LoginMenderDeps}   its `chain` member is what picks
 *   the lists, so the deps and the trigger cannot disagree
 * @param [options.pendingReports] {ReadonlyArray<Promise<unknown>>}   the
 *   reports the composition fired beside the block -- the transient
 *   composition's did:web projection mend -- awaited before `session.mends`
 *   settles. In the CHAPI popup the block itself runs empty and settles in
 *   the same tick, so without this the projection's entry would land after
 *   the report was assembled
 * @returns {void}   the block runs on `session.registryReady` and
 *   `session.mends`, both stamped before this returns
 */
export function startLoginMenderBlock({
  accumulator,
  route,
  deps,
  pendingReports
}: {
  accumulator: MendReportAccumulator<FreewalletCeremonyId>
  route: LoginRoute
  deps: LoginMenderDeps
  pendingReports?: ReadonlyArray<Promise<unknown>>
}): void {
  const { session } = deps
  const chain =
    deps.chain === 'remembered'
      ? {
          trigger: 'remembered-login-chain' as const,
          registrations: REMEMBERED_REGISTRATIONS,
          registryWriting: REMEMBERED_REGISTRY_REGISTRATIONS,
          seed: REMEMBERED_SEED
        }
      : {
          trigger: 'transient-login-chain' as const,
          registrations: TRANSIENT_REGISTRATIONS,
          registryWriting: TRANSIENT_REGISTRATIONS,
          seed: undefined
        }
  startMenderBlock({
    session,
    accumulator,
    trigger: chain.trigger,
    route,
    deps,
    registrations: chain.registrations,
    registryWriting: chain.registryWriting,
    held: heldFor({ session }),
    ...(chain.seed ? { seed: chain.seed } : {}),
    ...(pendingReports ? { pendingReports } : {})
  })
}
