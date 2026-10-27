/**
 * The gap allowlist: the residues this wallet accepts standing un-mended,
 * one row per `{ invariant, tornState }` pair. Row numbers are permanent
 * labels, so the array order is not the row-number order, and neither
 * follows ARCHITECTURE.md's open-gaps list, which groups the rows by class.
 * One predicate can hold several torn states, and each is its own row.
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
 * Every declared gap, each labeled by its permanent row number.
 */
export const MENDER_GAPS: ReadonlyArray<InvariantGap> = [
  // 1. This `none` is scoped to the ladder-anchored torn state, whose converger
  // is unbuilt. It stands beside the `unreachable` the derivation produces
  // for invariant 24 from its guarded routing site, the compound key keeping
  // the two apart.
  {
    invariant: 'recovery-spend-is-completed',
    tornState:
      "The transient recovery's roster-append repair on a credential-anchored account.",
    standsOn: ['ladder-anchored'],
    item: 'FW-276',
    kind: 'none'
  },
  // 2. Retired: the transient chain's collection fan-out completes a user-key
  // rotation torn mid-fan-out on a credential-anchored account. The number
  // stays, so the rows below keep theirs.
  // 3. Retired: the transient chain's tail promotes a keystore an
  // establishment left on the ladder's bare did:key. The number stays, so
  // the rows below keep theirs.
  // 4
  {
    invariant: 'every-document-key-agreement-entry-has-a-locatable-credential',
    tornState:
      'A recovery-code issuance torn after its document entry leaves a saved code that locates no account.',
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-303',
    kind: 'none'
  },
  // 5. The dead-pointer prompt at the credential's next login or spend is
  // the mender, so what stands is the credential never used again.
  {
    invariant: 'no-unlock-space-outlives-its-credential',
    tornState:
      "A sibling unlock Space an account deletion could not remove, whose credential is never used again. The dead-pointer prompt mends it only at that credential's next use, and an unspent recovery code is the sharp case.",
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-401',
    kind: 'none'
  },
  // 6
  {
    invariant: 'no-keystore-outlives-its-account',
    tornState:
      'A keystore orphaned by an account deletion on a KMS deployment.',
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-402',
    kind: 'none'
  },
  // 7
  {
    invariant: 'account-document-publishes-an-authentication-key',
    tornState:
      'A signup whose KMS stage failed publishes a document with no `authentication` relation.',
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-417',
    kind: 'none'
  },
  // 8. Derived: the standing converger is the remembered sweep, under
  // `enrolled`, and a ladder-kind ceremony's own roster append registers no
  // tail site.
  {
    invariant: 'roster-wraps-exactly-the-document-key-set',
    tornState:
      'A ladder-branch disconnect of the last enrolled client, torn after its removal entry, leaves the roster wrapping the current key to the removed client.',
    standsOn: ['ladder-anchored'],
    item: 'FW-468',
    kind: 'unreachable'
  },
  // 9
  {
    invariant: 'no-unlock-space-outlives-its-credential',
    tornState:
      "The retired credentials' unlock Spaces on a recovery spend torn between the landed registry drop and the deletes.",
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-469',
    kind: 'none'
  },
  // 24. A transient spend leaves no pending carrier, so its tail's one retry
  // is the last registry write that names these entries.
  {
    invariant: 'no-unlock-space-outlives-its-credential',
    tornState:
      "The retired credentials' registry entries and unlock Spaces on a transient recovery spend whose registry write and its one retry both failed.",
    standsOn: ['ladder-anchored'],
    item: 'FW-607',
    kind: 'none'
  },
  // 10. Retired: the transient chain's collection fan-out seals the
  // collection descriptor logs behind a forget ceremony's removal entry, on
  // both grades. The number stays, so the rows below keep theirs.
  // 21. The roster half row 10 never named, listed in row 10's place. Its
  // only seal is the remembered sweep's roster convergence, which no
  // credential-only visit fires. It keys invariant 37, the roster log's half
  // of invariant 2, and derives `unreachable` from that.
  {
    invariant: 'roster-log-head-anchors-past-the-membership-change',
    tornState:
      "The user key roster log behind an ordinary forget ceremony's removal entry.",
    standsOn: ['enrolled'],
    item: 'FW-450',
    kind: 'unreachable'
  },
  // 11
  {
    invariant: 'no-annex-generation-outlives-its-pointer',
    tornState:
      'The annex generation GC, which runs from the remembered-login chain only.',
    standsOn: ['ladder-anchored'],
    item: 'FW-365',
    kind: 'unreachable'
  },
  // 12
  {
    invariant: 'account-pointer-names-the-account-did',
    tornState:
      'A credential-anchored signup whose pointer backfill failed, leaving the unlock record on the signup-time did:key. The heal is registered on the remembered login chain alone, which a credential-anchored account never runs.',
    standsOn: ['ladder-anchored'],
    item: 'FW-462',
    kind: 'unreachable'
  },
  // 13. Retired 2026-10-01: invariant 20 (stranded app keys) left the
  // census with its sweep. The number stays, so the rows below keep theirs.
  // 14. The one converger needs a browser-local session, so invariant 33 is
  // declared `enrolled` until FW-464 builds the replica-less one. Two of the
  // three `inbox` states sit here too: the drain's own predicate excludes an
  // absent or refused inbox, and only the remembered login's re-walk of the
  // provision roster adds one. The third is row 26.
  {
    invariant: 'standard-collections-are-provisioned',
    tornState:
      'A signup torn before provisioning on an account that runs no remembered login. The same residue covers the `inbox` collection: an account created before `inbox` joined the provision roster, and an account whose user deleted `inbox`.',
    standsOn: ['ladder-anchored'],
    item: 'FW-464',
    kind: 'unreachable'
  },
  // 26. The re-walk's presence check reads an adopted untrusted `inbox` as
  // clean, so no trigger on either shape converges it. FW-669 builds the
  // converger.
  {
    invariant: 'standard-collections-are-provisioned',
    tornState:
      'An account that adopted an untrusted `inbox` (public, encrypted, or attributed), which the drain refuses and the provision re-walk reads as present.',
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-669',
    kind: 'none'
  },
  // 15
  {
    invariant: 'registry-records-the-establishing-credential',
    tornState:
      "An establishment torn between the record re-bind and the registry re-entry, the re-entry arm's trigger being the crashed tab's in-memory marker.",
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-465',
    kind: 'none'
  },
  // 16
  {
    invariant: 'registry-passphrase-entry-names-the-standing-credential',
    tornState:
      'A pending passphrase entry written by a refusal after establishment, which the seedless repair cannot clear.',
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-466',
    kind: 'none'
  },
  // 22. Retired: the `connections` writer sweep runs at the directory
  // listing read, an encounter site on both session kinds. The number stays,
  // so the rows below keep theirs.
  // 23
  {
    invariant: 'every-grantee-of-the-wallet-has-a-connection-entry',
    tornState:
      'A party holding a live grant the wallet delegated and no connections entry: one whose entry a deleted and re-created directory lost, or one that connected before the directory existed.',
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-569',
    kind: 'none'
  },
  // 17
  {
    invariant: 'no-auxiliary-space-stands-unnamed',
    tornState:
      'An auxiliary Space stranded between its mint and its pointer entry by a crashed first visit.',
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-467',
    kind: 'none'
  },
  // 18
  {
    invariant: 'this-browser-is-still-an-enrolled-client',
    tornState:
      'A forgotten or disconnected browser whose local wipe tore, on an account with no remembered login left to run the detector.',
    standsOn: ['ladder-anchored'],
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
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-290',
    kind: 'none'
  },
  // 20. The second detector-only declaration, by design likewise.
  {
    invariant: 'saved-recovery-codes-locate-their-account',
    tornState:
      "A detector with no converger of its own: the user's own reissue is the mender, and the detector nudges rather than refuses.",
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-290',
    kind: 'none'
  },
  // 25. The epoch cascade does not reach the pairwise seed on an agent's
  // connections entry. FW-647's seed rotation is the converger.
  {
    invariant: 'no-withdrawn-party-holds-a-live-pairwise-channel',
    tornState:
      'A party whose authority the account withdrew keeps every pairwise seed and channel capability it read from the directory: a revoked client, a retired credential, or a struck annex generation (every past transient visit included). It can post into an agent inbox as the wallet until that capability expires.',
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-647',
    kind: 'none'
  },
  // 26. The rotation's ceremony-tail site reports the invariant for the
  // strike and the named swap; this row is the torn state neither reached.
  // A restating swap carries every hash the superseded log holds, and the
  // account document records no annex commitment to attribute one by.
  {
    invariant: 'retired-credential-leaves-no-annex-inventory',
    tornState:
      "A retired credential's annex rung hash that neither a strike entry nor a named retirement swap removed rides every later restating swap. Nothing attributes the hash to the retired credential, so no swap can leave it out.",
    standsOn: ['ladder-anchored', 'enrolled'],
    item: 'FW-682',
    kind: 'none'
  }
]
