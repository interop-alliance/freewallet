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
 * names. The warning comes from the warn table rather than from the
 * assembled registry, which reaches the ceremony modules that call this and
 * would close an import cycle.
 *
 * Every entry, whatever its grade, also emits one `'ceremony mender'` event
 * naming the ceremony that just ran. The caller wraps a shared ceremony and
 * holds no emitter of its run, so the event carries no `run` id.
 */
import type { MendReport } from '@interop/wallet-core/menders'
import { menderEvent } from '@interop/wallet-core'
import type { CeremonyId } from '@interop/wallet-core'
import { createLogger } from '@/lib/log'
import { MENDER_WARNINGS } from './warnings.js'

const log = createLogger('fw:session:registry')

/**
 * Reports one ceremony's tail mend entries. Never throws: a report is
 * diagnostics, and a ceremony that has already run its stages must not fail
 * on the way out.
 *
 * @param options {object}
 * @param options.ceremony {CeremonyId}   the ceremony that just ran
 * @param options.mended {MendReport}   the entries the ceremony's outcome
 *   carries, in report order
 * @returns {void}
 */
export function reportCeremonyTail({
  ceremony,
  mended
}: {
  ceremony: CeremonyId
  mended: MendReport<CeremonyId>
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
    }
    menderEvent({ log, entry, ceremony })
  }
}
