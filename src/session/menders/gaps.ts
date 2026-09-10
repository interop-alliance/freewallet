/**
 * The gap allowlist: the residues this wallet accepts standing un-mended,
 * one row per `{ invariant, tornState }` pair, in the order ARCHITECTURE.md's
 * ceremony inventory lists them. One predicate can hold several torn states,
 * and each is its own row.
 *
 * `none` means no registration reports the invariant on any trigger, whether
 * because no converger is built, because the code that converges it is not
 * an addressable symbol, or because the declaration is a detector by design
 * (a detector is not a mender). `unreachable` means a registration reports it, on
 * triggers a credential-only visit on the affected account shape cannot
 * fire. The derivation over the declarations and the site index admits gaps
 * and retires none, so a row it no longer produces stands until a review
 * confirms the residue mended.
 */
import type { InvariantGap } from '@interop/wallet-core/menders'

/**
 * Every declared gap, in the row order above.
 */
export const MENDER_GAPS: ReadonlyArray<InvariantGap> = [
  // 1. This `none` is scoped to the client-less torn state, whose converger
  // is unbuilt. It stands beside the `unreachable` the derivation produces
  // for invariant 24 from its guarded routing site, the compound key keeping
  // the two apart.
  {
    invariant: 'recovery-spend-is-completed',
    tornState:
      "The transient recovery's roster-append repair on a client-less account.",
    standsOn: ['client-less'],
    item: 'FW-276',
    kind: 'none'
  },
  // 2. Lapsed on the 2026-09-09 trigger correction; stands until a review
  // confirms the residue mended.
  {
    invariant: 'collection-epochs-name-the-current-user-key',
    tornState: 'A user-key rotation torn mid-fan-out on a client-less account.',
    standsOn: ['client-less'],
    item: 'FW-219',
    kind: 'unreachable'
  },
  // 3
  {
    invariant: 'keystore-controller-is-the-account-did',
    tornState:
      "An establishment torn between the record re-bind and the promotion leaves the KMS keystore's controller on the ladder's bare did:key. The promotion is registered on the remembered login chain alone, which the affected account may never run.",
    standsOn: ['client-less'],
    item: 'FW-420',
    kind: 'unreachable'
  },
  // 4
  {
    invariant: 'every-document-key-agreement-entry-has-a-locatable-credential',
    tornState:
      'A recovery-code issuance torn after its document entry leaves a saved code that locates no account.',
    standsOn: ['client-less', 'enrolled'],
    item: 'FW-303',
    kind: 'none'
  },
  // 5
  {
    invariant: 'no-unlock-space-outlives-its-credential',
    tornState:
      "A sibling unlock Space an account deletion could not remove. The self-delete backstop does not close it: the sibling Space's own credential may never be used again, and an unspent recovery code is the sharp case.",
    standsOn: ['client-less', 'enrolled'],
    item: 'FW-401',
    kind: 'none'
  },
  // 6
  {
    invariant: 'no-keystore-outlives-its-account',
    tornState:
      'A keystore orphaned by an account deletion on a KMS deployment.',
    standsOn: ['client-less', 'enrolled'],
    item: 'FW-402',
    kind: 'none'
  },
  // 7
  {
    invariant: 'account-document-publishes-an-authentication-key',
    tornState:
      'A signup whose KMS stage failed publishes a document with no `authentication` relation.',
    standsOn: ['client-less', 'enrolled'],
    item: 'FW-417',
    kind: 'none'
  },
  // 8. Lapsed on the 2026-09-09 trigger correction; stands until a review
  // confirms the residue mended.
  {
    invariant: 'roster-wraps-exactly-the-document-key-set',
    tornState:
      'A ladder-branch disconnect of the last enrolled client, torn after its removal entry, leaves the roster wrapping the current key to the removed client.',
    standsOn: ['client-less'],
    item: 'FW-468',
    kind: 'unreachable'
  },
  // 9
  {
    invariant: 'no-unlock-space-outlives-its-credential',
    tornState:
      "The retired credentials' unlock Spaces on a recovery spend torn between the landed registry drop and the deletes.",
    standsOn: ['client-less', 'enrolled'],
    item: 'FW-469',
    kind: 'none'
  },
  // 10. Lapsed on the 2026-09-09 trigger correction; stands until a review
  // confirms the residue mended.
  {
    invariant: 'governed-log-heads-anchor-past-the-membership-change',
    tornState:
      "The collection descriptor logs behind a forget ceremony's removal entry.",
    standsOn: ['client-less'],
    item: 'FW-450',
    kind: 'none'
  },
  // 11
  {
    invariant: 'no-annex-generation-outlives-its-pointer',
    tornState:
      'The annex generation GC, which runs from the remembered-login chain only.',
    standsOn: ['client-less'],
    item: 'FW-365',
    kind: 'unreachable'
  },
  // 12
  {
    invariant: 'account-pointer-names-the-account-did',
    tornState:
      'A credential-anchored signup whose pointer backfill failed, leaving the unlock record on the signup-time did:key. The heal is registered on the remembered login chain alone, which a client-less account never runs.',
    standsOn: ['client-less'],
    item: 'FW-462',
    kind: 'unreachable'
  },
  // 13
  {
    invariant: 'app-keys-live-only-in-app-connections',
    tornState: 'Stranded app keys after a last-client transition.',
    standsOn: ['client-less'],
    item: 'FW-463',
    kind: 'unreachable'
  },
  // 14
  {
    invariant: 'standard-collections-are-provisioned',
    tornState:
      'A signup torn before provisioning on an account that runs no remembered login.',
    standsOn: ['client-less'],
    item: 'FW-464',
    kind: 'unreachable'
  },
  // 15
  {
    invariant: 'registry-records-the-establishing-credential',
    tornState:
      "An establishment torn between the record re-bind and the registry re-entry, the re-entry arm's trigger being the crashed tab's in-memory marker.",
    standsOn: ['client-less', 'enrolled'],
    item: 'FW-465',
    kind: 'none'
  },
  // 16
  {
    invariant: 'registry-passphrase-entry-names-the-standing-credential',
    tornState:
      'A pending passphrase entry written by a refusal after establishment, which the seedless repair cannot clear.',
    standsOn: ['client-less', 'enrolled'],
    item: 'FW-466',
    kind: 'none'
  },
  // 17
  {
    invariant: 'no-auxiliary-space-stands-unnamed',
    tornState:
      'An auxiliary Space stranded between its mint and its pointer entry by a crashed first visit.',
    standsOn: ['client-less', 'enrolled'],
    item: 'FW-467',
    kind: 'none'
  },
  // 18
  {
    invariant: 'this-browser-is-still-an-enrolled-client',
    tornState:
      'A forgotten or disconnected browser whose local wipe tore, on an account with no remembered login left to run the detector.',
    standsOn: ['client-less'],
    item: 'FW-470',
    kind: 'unreachable'
  },
  // 19. A detector is not a mender (decided 2026-09-09): the declaration
  // carries `holdsWhen` and no registration reports it, so the derivation
  // kinds it `none`. By design; the row tracks the decision, not a build.
  {
    invariant: 'document-lists-the-acting-credential',
    tornState:
      'A detector with no converger of its own: the ceremony that tore converges it on its own re-run, and the detector refuses the transient login meanwhile.',
    standsOn: ['client-less', 'enrolled'],
    item: 'FW-290',
    kind: 'none'
  },
  // 20. The second detector-only declaration, by design likewise.
  {
    invariant: 'saved-recovery-codes-locate-their-account',
    tornState:
      "A detector with no converger of its own: the user's own reissue is the mender, and the detector nudges rather than refuses.",
    standsOn: ['client-less', 'enrolled'],
    item: 'FW-290',
    kind: 'none'
  }
]
