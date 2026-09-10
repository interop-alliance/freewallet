/**
 * The ceremony-tail report's consumer: the try, warn, and skip discipline
 * the login chains' runner holds, applied to the entries a ceremony reports
 * from its own call site.
 *
 * A ceremony-tail entry carries no registration at all (`decisions/0023`):
 * its stage stays inside the ceremony's sequenced code, where the cascade's
 * dependency order needs it, and the registry takes the report only. No
 * runner ever sees such an entry, so the ceremony's own caller is what
 * reports it, and the grading here is the runner's: an entry the ceremony
 * graded `failed` or `refused` logs the declared `warn` of the invariant it
 * names, and every other grade logs at info. The warning comes from the
 * warn table rather than from the assembled registry, which reaches the
 * ceremony modules that call this and would close an import cycle.
 *
 * The outcome members stay on the ceremony's own outcome, so a later mender
 * event channel can consume the same entries without going through the log.
 */
import type { MendReport } from '@interop/wallet-core/menders'
import type { FreewalletCeremonyId } from '@/session/ceremonies'
import { createLogger } from '@/lib/log'
import { MENDER_WARNINGS } from './warnings.js'

const log = createLogger('fw:session:registry')

/**
 * Reports one ceremony's tail mend entries. Never throws: a report is
 * diagnostics, and a ceremony that has already run its stages must not fail
 * on the way out.
 *
 * @param options {object}
 * @param options.mended {MendReport}   the entries the ceremony's outcome
 *   carries, in report order
 * @returns {void}
 */
export function reportCeremonyTail({
  mended
}: {
  mended: MendReport<FreewalletCeremonyId>
}): void {
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
    if (outcome === 'failed' || outcome === 'refused') {
      log.warn(MENDER_WARNINGS[invariant], context)
    } else {
      log.info('A ceremony reported its tail mend entry', context)
    }
  }
}
