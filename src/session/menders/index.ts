/**
 * The freewallet mender registry: the invariant declarations (data -- what
 * must hold between ceremonies), the registration lists (code -- what
 * converges a violated one, per trigger, in execution order), the gap
 * allowlist of the residues that stand un-mended, and the readers over them.
 *
 * The runner in `run.ts` is what executes a block; the registry itself
 * executes nothing and orders nothing beyond the lists' own order.
 *
 * The declarations' warn messages sit in `warnings.ts` and are deliberately
 * not re-exported here: a consumer that needs a message alone reads that
 * file directly, since reaching it through this module would pull in the
 * registrations and, behind them, the ceremony modules.
 */
import { menderRegistry } from '@interop/wallet-core/menders'

import type { FreewalletCeremonyId } from '../ceremonies.js'
import { MENDER_INVARIANTS } from './invariants.js'
import { MENDER_SITES, type LoginMenderDeps } from './registrations.js'

export { MENDER_GAPS } from './gaps.js'
export { MENDER_INVARIANTS } from './invariants.js'
export {
  MENDER_SITES,
  REMEMBERED_REGISTRATIONS,
  REMEMBERED_REGISTRY_REGISTRATIONS,
  REMEMBERED_SEED,
  REMEMBERED_TAIL_REGISTRATIONS,
  REPORTING_SITES,
  TRANSIENT_REGISTRATIONS
} from './registrations.js'
export type {
  LoginMenderDeps,
  RememberedMenderDeps,
  TransientMenderDeps
} from './registrations.js'

/**
 * The readers over this wallet's declarations and registration sites:
 * `all`, `byId`, `sites`, and `dueAt`.
 */
export const freewalletMenderRegistry = menderRegistry<
  (typeof MENDER_SITES)[number],
  LoginMenderDeps,
  FreewalletCeremonyId
>({
  declarations: MENDER_INVARIANTS,
  sites: MENDER_SITES
})
