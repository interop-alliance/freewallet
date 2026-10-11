/**
 * The ceremony-tail report's consumer: the try, warn, and skip discipline
 * the login chains' runner holds, applied to the entries a ceremony reports
 * from its own call site.
 *
 * A ceremony-tail entry carries a report-only site and no converging
 * registration (`decisions/0023`). Its stage stays inside the ceremony's
 * sequenced code, where the cascade's dependency order needs it, and the
 * registry takes the report alone. No runner ever sees such an entry, so the
 * ceremony's own caller is what reports it, and the grading here is the
 * runner's: an entry the ceremony graded `failed` or `refused` logs the
 * declared `warn` of the invariant it names. The warning comes from the warn
 * table rather than from the assembled registry, which reaches the ceremony
 * modules that call this and would close an import cycle.
 *
 * The tail sites live here too, keyed by the ceremony that reports them, so
 * a ceremony can report a tail only once it has a site, and an entry naming
 * an invariant its site does not report is logged as a shape error, the way
 * the runner reports a registration's. A ceremony's own roster rotation and
 * collection cascade report no entry and register no site.
 *
 * Every entry, whatever its grade, also emits one `'ceremony mender'` event
 * naming the ceremony that just ran. The caller wraps a shared ceremony and
 * holds no emitter of its run, so the event carries no `run` id.
 */
import type { MendReport, RegistrationSite } from '@interop/wallet-core/menders'
import { menderEvent } from '@interop/wallet-core'
import type { CeremonyId } from '@interop/wallet-core'
import { createLogger } from '@/lib/log'
import { MENDER_WARNINGS } from './warnings.js'

const log = createLogger('fw:session:registry')

/**
 * The ceremony tails that report an entry, one site per reporting ceremony.
 * The registry indexes these beside the other report-only sites. Each names
 * the session kinds that reach its ceremony in `reachedBy`, as an encounter
 * site does, since the derived sets count a tail toward a credential-only
 * visit only when `transient` reaches it. The registry refuses a tail site
 * with no reach at construction, and the typecheck refuses it first.
 */
export const CEREMONY_TAIL_SITES = {
  // The client revocation's generation-delegation renewal, reported from
  // the cascade orchestrator's caller (`src/session/clients.ts`).
  'client-revocation': {
    trigger: 'ceremony-tail',
    reports: ['generation-delegation-is-current'],
    // Settings > Connected wallets runs the revocation on any session type.
    reachedBy: ['remembered', 'transient']
  },
  // The unlock-credential rotation's annex inventory strike, reported from
  // each rotation caller: `src/session/unlockMethods.ts`,
  // `src/session/accountSettings.ts`, `src/session/pendingRetirement.ts`,
  // and `src/session/standingEstablishment.ts`.
  'unlock-credential-rotation': {
    trigger: 'ceremony-tail',
    reports: ['retired-credential-leaves-no-annex-inventory'],
    // Every rotation caller runs on any session type.
    reachedBy: ['remembered', 'transient']
  }
} as const satisfies Partial<Record<CeremonyId, RegistrationSite>>

export type CeremonyTailId = keyof typeof CEREMONY_TAIL_SITES

/**
 * Reports one ceremony's tail mend entries. Never throws: a report is
 * diagnostics, and a ceremony that has already run its stages must not fail
 * on the way out.
 *
 * @param options {object}
 * @param options.ceremony {CeremonyTailId}   the ceremony that just ran, one
 *   with a tail site
 * @param options.mended {MendReport}   the entries the ceremony's outcome
 *   carries, in report order
 * @returns {void}
 */
export function reportCeremonyTail({
  ceremony,
  mended
}: {
  ceremony: CeremonyTailId
  mended: MendReport<CeremonyId>
}): void {
  const site = CEREMONY_TAIL_SITES[ceremony]
  for (const entry of mended) {
    const { invariant, outcome, detail, errorName, ceremonies } = entry
    const context = {
      invariant,
      trigger: 'ceremony-tail',
      outcome,
      ...(ceremonies ? { ceremonies: [...ceremonies] } : {}),
      ...(detail ? { detail } : {}),
      ...(errorName ? { errorName } : {})
    }
    if (!(site.reports as ReadonlyArray<string>).includes(invariant)) {
      log.warn(
        'A ceremony-tail entry names an invariant its site does not report',
        {
          ...context,
          ceremony,
          reports: [...site.reports]
        }
      )
    }
    if (outcome === 'failed' || outcome === 'refused') {
      log.warn(MENDER_WARNINGS[invariant], context)
    }
    menderEvent({ log, entry, ceremony })
  }
}
