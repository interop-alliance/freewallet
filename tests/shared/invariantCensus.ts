/**
 * The invariant census: where each declared invariant of the mender registry
 * can be checked from outside a session. Every id in wallet-core's
 * `INVARIANT_IDS` is sorted into one of four kinds:
 *
 * - `stored`: checkable from what the server stores alone, read off the
 *   teaching server's FileSystem backend under its data root (the account
 *   log, the did:web projection, the user key roster, the collection
 *   descriptor logs, `key-map/keys.json`, the Space metadata objects, the
 *   annex Spaces and their `gen-` logs, and the `/kms` facet's keystores).
 * - `key-holder`: checkable only by a party holding the user key or the
 *   acting unlock credential: the sealed unlock-methods registry, the
 *   encrypted unlock record, the session's own standing members.
 * - `browser-local`: a predicate over one browser's own state (its
 *   client-key record), which the store does not hold.
 * - `unchecked`: not machine-checkable today, for the reason given.
 *
 * A `stored` row may name a `keyHolderHalf`: a part of the predicate only a
 * key holder can read. The auditor runs the stored half always and adds the
 * key holder's half when one is handed in.
 *
 * The census is data. The checks that implement each kind live in
 * `invariantAudit.ts` (stored) and in the harness's key-holder port
 * (`tests/harness/invariantAuditActor.ts`). This module imports nothing
 * under `src/`, so the Playwright process can load it.
 */
import type { InvariantId } from '@interop/wallet-core/menders'

/**
 * Where one invariant can be checked from.
 */
export type InvariantCheckKind =
  'stored' | 'key-holder' | 'browser-local' | 'unchecked'

/**
 * One census row: the kind, and why. For a `browser-local` or `unchecked`
 * row the reason is what the auditor reports for skipping it.
 */
export interface InvariantCensusRow {
  readonly kind: InvariantCheckKind
  readonly reason: string
  readonly keyHolderHalf?: string
}

/**
 * Every declared invariant's census row, keyed by id. Wallet-core's census
 * once carried a twentieth row (stranded app keys); it is retired and
 * absent from `INVARIANT_IDS`, so it has no row here.
 */
export const INVARIANT_CENSUS: Readonly<
  Record<InvariantId, InvariantCensusRow>
> = {
  // The comparison is the roster head's current epoch against the
  // document's keyAgreement entries, both stored. Shares wallet-core's
  // `userKeyRosterRecipientResolver` and `enrolledClientRosterRecipients`
  // with the converger.
  'roster-wraps-exactly-the-document-key-set': {
    kind: 'stored',
    reason:
      "The roster's current-epoch recipient kids and the account document's keyAgreement methods are both stored in the clear."
  },
  // Each governed log's head proof names its anchoring controller
  // version; the removal index is `latestAssertionRemovalIndex`.
  'governed-log-heads-anchor-past-the-membership-change': {
    kind: 'stored',
    reason:
      "A descriptor log head's proof names the account log version it anchors at, and the account log's assertionMethod history is stored."
  },
  // The epoch recipients name user key generations by did:key, and the
  // roster's epoch ids are those generations.
  'collection-epochs-name-the-current-user-key': {
    kind: 'stored',
    reason:
      "A collection epoch's recipient kids and the roster's current epoch id are both stored in the clear."
  },
  // The mender's detector is the registry read itself: a record that
  // does not open under the session's vault keys is the stale seal.
  'unlock-registry-opens-under-the-current-user-key': {
    kind: 'key-holder',
    reason:
      "Whether the registry opens is settled by decrypting it under the current user key's vault keys, the registry read's own stale-seal refusal."
  },
  // The registry is sealed, and the detector reads each passphrase
  // entry's unlock record through its management zcap.
  'registry-passphrase-entry-names-the-standing-credential': {
    kind: 'key-holder',
    reason:
      'The registry entries are sealed to the user key, and the detector reads each passphrase entry against its unlock record.'
  },
  'passkey-entry-carries-its-standing-configuration': {
    kind: 'key-holder',
    reason: 'The passkey entries live in the sealed registry.'
  },
  'registry-lists-the-passphrase-method': {
    kind: 'key-holder',
    reason:
      'The passphrase entry lives in the sealed registry; the document says whether a passphrase stands.'
  },
  // The delegations ride in the encrypted unlock record (and in the
  // session's standing members, read off it at login).
  'standing-delegations-verify-under-the-current-document': {
    kind: 'key-holder',
    reason:
      "The bridge delegation and its sibling ride inside the acting credential's encrypted unlock record."
  },
  // The committed rung is derived from the ladder seed, which only the
  // unlock record carries.
  'registry-records-the-committed-ladder-rung': {
    kind: 'key-holder',
    reason:
      "The recorded rung is a sealed registry field, and the committed rung is attributed from the credential's ladder seed."
  },
  'unlock-record-points-at-the-account-did': {
    kind: 'key-holder',
    reason:
      "The account pointer is a member of the acting credential's encrypted unlock record, which only that credential opens."
  },
  // Only the acting credential's record is reachable: each other
  // record opens under its own secret alone.
  'account-pointer-names-the-account-did': {
    kind: 'key-holder',
    reason:
      "Each unlock record's pointer is encrypted to that record's own credential; a key holder checks the acting credential's record."
  },
  // The Space metadata object stores its controller in the clear.
  'space-controller-is-the-account-did': {
    kind: 'stored',
    reason:
      "The Space metadata object's controller and the account log's DID are both stored in the clear."
  },
  'roster-and-collection-epochs-exist': {
    kind: 'stored',
    reason:
      "The roster and every encrypted collection's descriptor log are stored, with their current epochs in the clear.",
    keyHolderHalf:
      "Whether the acting credential can open the roster's current epoch: its roster kid is known to the key holder alone."
  },
  'registry-records-the-establishing-credential': {
    kind: 'key-holder',
    reason:
      "The acting credential's registry entry and its recorded delegations live in the sealed registry."
  },
  'annex-generation-is-reachable': {
    kind: 'stored',
    reason:
      "The document's #DelegatedClients pointer, the auxiliary Space, and the pointed generation's log are all stored.",
    keyHolderHalf:
      "Whether the acting credential's sibling delegation aims at the pointed Space: the sibling rides inside the encrypted unlock record."
  },
  // The delegation is embedded in the pointed generation's stored log;
  // the staleness rule is wallet-core's `standingZcapStale`.
  'generation-delegation-is-current': {
    kind: 'stored',
    reason:
      "The pointed generation's embedded delegation and the account document's capabilityDelegation keys are both stored."
  },
  'acting-credential-manage-zcap-is-current': {
    kind: 'key-holder',
    reason:
      "The management zcap is a member of the acting credential's sealed registry entry."
  },
  // The comparison is wallet-core's `ensureDidWebProjection`, run over a
  // read-only store.
  'did-web-projection-matches-the-log': {
    kind: 'stored',
    reason:
      'The served id/did.json and the account log are both stored in the clear.'
  },
  // The swap cadence and the collect rule are wallet-core's GC
  // predicates over the stored logs.
  'no-annex-generation-outlives-its-pointer': {
    kind: 'stored',
    reason:
      "The auxiliary Space's gen- collections, their logs, and the account log's pointer history are all stored."
  },
  'client-key-record-matches-the-pointed-account': {
    kind: 'browser-local',
    reason:
      "The client-key record lives in one browser's freewallet-session database, which the store does not hold."
  },
  'this-browser-is-still-an-enrolled-client': {
    kind: 'browser-local',
    reason:
      "The predicate is over one browser's client-key record, which the store does not hold."
  },
  'no-client-key-record-stays-pending': {
    kind: 'browser-local',
    reason:
      "A pending client-key record lives in one browser's freewallet-session database, which the store does not hold."
  },
  'recovery-spend-is-completed': {
    kind: 'browser-local',
    reason:
      "The spend's builtOnHead witness lives in the spending browser's pending client-key record, which the store does not hold. A transient spend leaves no pending record at all, so nothing names which stages it landed."
  },
  'retired-credential-leaves-no-annex-inventory': {
    kind: 'unchecked',
    reason:
      "A credential's annex rung hash derives from its ladder seed, which only that credential's unlock record carries; a retired credential's record goes with it, so no reader can attribute a left-over rung hash."
  },
  // The detector is the declaration's `holdsWhen`
  // (`documentListsCredential`), run by the key holder.
  'document-lists-the-acting-credential': {
    kind: 'key-holder',
    reason:
      "Which keyAgreement entry is the acting credential's is known only from that credential's key-agreement key."
  },
  // The keystore configuration is stored beside the Spaces.
  'keystore-controller-is-the-account-did': {
    kind: 'stored',
    reason:
      "The /kms facet stores each keystore's configuration, controller included, under the data root, and key-map/keys.json names the account's keystore."
  },
  'account-document-publishes-an-authentication-key': {
    kind: 'stored',
    reason: "The account document's authentication relation is stored."
  },
  // The detector is `findUnrecordedCredentials`.
  'every-document-key-agreement-entry-has-a-locatable-credential': {
    kind: 'key-holder',
    reason: 'The credentials the registry records are sealed in the registry.'
  },
  'no-unlock-space-outlives-its-credential': {
    kind: 'unchecked',
    reason:
      'An unlock Space carries no plaintext link to its account, and a retired credential leaves the registry, so nothing a reader can open names the unlock Spaces to look for.'
  },
  // A keystore's controller names the account Space in its did:webvh.
  'no-keystore-outlives-its-account': {
    kind: 'stored',
    reason:
      "The keystores are stored under the data root, and a promoted keystore's controller embeds the account Space id."
  },
  // The detector is the declaration's `holdsWhen`
  // (`checkRecoveryHealth`).
  'saved-recovery-codes-locate-their-account': {
    kind: 'key-holder',
    reason: 'The recovery-code entries live in the sealed registry.'
  },
  'standard-collections-are-provisioned': {
    kind: 'stored',
    reason:
      'Each collection is a stored directory, and an encrypted one stores its descriptor log beside it.'
  },
  'no-auxiliary-space-stands-unnamed': {
    kind: 'stored',
    reason:
      "Each auxiliary Space's metadata object stores its type and controller, and the account log stores every pointer entry."
  },
  'no-registered-writer-outlives-its-expiry': {
    kind: 'unchecked',
    reason:
      'The writers and their activity times live in encrypted connections entries; a key holder could read them, but no check over them is built.'
  },
  'every-party-with-authority-has-a-connection-entry': {
    kind: 'unchecked',
    reason:
      'A detector would walk the live grants and every collection roster against the encrypted connections directory; none is built (FW-569).'
  },
  // The roster log's half of
  // `governed-log-heads-anchor-past-the-membership-change`, with the same
  // removal index.
  'roster-log-head-anchors-past-the-membership-change': {
    kind: 'stored',
    reason:
      "The roster log head's proof names the account log version it anchors at, and the account log's assertionMethod history is stored."
  }
}

/**
 * The census ids of one kind, in census order.
 *
 * @param options {object}
 * @param options.kind {InvariantCheckKind}
 * @returns {InvariantId[]}
 */
export function censusIdsOfKind({
  kind
}: {
  kind: InvariantCheckKind
}): InvariantId[] {
  return (Object.keys(INVARIANT_CENSUS) as InvariantId[]).filter(
    id => INVARIANT_CENSUS[id].kind === kind
  )
}
