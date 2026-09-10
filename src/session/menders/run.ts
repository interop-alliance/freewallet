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
 * The authorities this session holds, for the registry's admission test.
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
  const authority = sessionAuthorityKind({ session })
  return heldAuthorities({ ...(authority ? { kind: authority.kind } : {}) })
}

/**
 * Starts one login chain's block, selecting the registrations, the
 * registry-writing prefix, and the seed from the chain the deps name. The
 * remembered chain runs the provisioning seed, the six registry-writing
 * registrations, then the app-key sweep, the annex GC, and the keystore
 * report; the transient chain runs the shared registry passes, then the
 * acting credential's management-zcap refresh, and has no seed, a transient
 * session provisioning nothing.
 *
 * Both of the session's promises are stamped before anything is awaited, so
 * a caller that returns the session at once finds them. The two settle
 * points are derived from the lists rather than named: the ids the
 * registry-writing registrations report are what `registryReady` waits for,
 * skipping any the registry does not admit on this session's authorities and
 * route (an unadmitted registration reports nothing), and the block's own
 * completion settles both.
 *
 * A registration listed under the wrong trigger is a programming error the
 * runner refuses with a `TypeError`, which lands in the warn below and
 * settles both promises rather than tearing the login.
 *
 * @param options {object}
 * @param options.accumulator {MendReportAccumulator}   the report the
 *   routing entries already reported into
 * @param options.route {LoginRoute}
 * @param options.deps {LoginMenderDeps}   its `chain` member is what picks
 *   the lists, so the deps and the trigger cannot disagree
 * @param [options.pendingReports] {ReadonlyArray<Promise<unknown>>}   the
 *   reports the composition fired beside the block -- the transient
 *   composition's did:web projection mend -- awaited before `session.mends`
 *   settles. In the CHAPI popup the block itself runs empty and settles in
 *   the same tick, so without this the projection's entry would land after
 *   the report was assembled. `registryReady` does not wait on them
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
  const { trigger, registrations, registryWriting, seed } =
    deps.chain === 'remembered'
      ? {
          trigger: 'remembered-login-chain' as const,
          registrations: REMEMBERED_REGISTRATIONS,
          registryWriting: REMEMBERED_REGISTRY_REGISTRATIONS,
          seed: REMEMBERED_SEED as
            Registration<LoginMenderDeps, FreewalletCeremonyId> | undefined
        }
      : {
          trigger: 'transient-login-chain' as const,
          registrations: TRANSIENT_REGISTRATIONS,
          registryWriting: TRANSIENT_REGISTRATIONS,
          seed: undefined
        }
  const held = heldFor({ session })
  const awaited = new Set<InvariantId>()
  for (const registration of [...(seed ? [seed] : []), ...registryWriting]) {
    if (freewalletMenderRegistry.admits({ site: registration, held, route })) {
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
      // invariant, or a registration listed under another trigger), and
      // neither promise may hang on one.
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
