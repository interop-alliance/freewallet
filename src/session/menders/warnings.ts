/**
 * What a runner logs when the code converging an invariant throws: one
 * message per invariant id, in the census's order.
 *
 * The table lives apart from the declarations so that a consumer needing a
 * message alone -- the ceremony-tail reporter, which grades an entry the way
 * the login runner does -- reads it without pulling in the declarations'
 * detectors, and through them the ceremony modules that report tail entries.
 * The declarations in `invariants.ts` are the only other reader: each one's
 * `warn` member is its entry here.
 */
import type { InvariantId } from '@interop/wallet-core/menders'

export const MENDER_WARNINGS: Readonly<Record<InvariantId, string>> = {
  'roster-wraps-exactly-the-document-key-set':
    'The user key cascade-completion sweep failed',
  'governed-log-heads-anchor-past-the-membership-change':
    'The user key cascade-completion sweep failed',
  'collection-epochs-name-the-current-user-key':
    'The user key cascade-completion sweep failed',
  'unlock-registry-opens-under-the-current-user-key':
    'Could not repair the unlock-methods registry seal; the next login retries',
  'registry-passphrase-entry-names-the-standing-credential':
    'Could not finish the pending passphrase retirement; the next login retries',
  'passkey-entry-carries-its-standing-configuration':
    'Could not rebuild the bare passkey unlock-method entry; the next login retries',
  'registry-lists-the-passphrase-method':
    'Could not backfill the unlock-methods registry',
  'standing-delegations-verify-under-the-current-document':
    'Could not refresh the expiring standing delegations; the next login retries',
  'registry-records-the-committed-ladder-rung':
    'Could not refresh the recorded ladder rung after self-enrolling; a later disconnect attribution fails closed instead',
  'unlock-record-points-at-the-account-did':
    'Could not point the unlock record at the account did:webvh; the next visit retries',
  'account-pointer-names-the-account-did':
    'Could not backfill the did:webvh pointer and promote the controller; the next login retries',
  'space-controller-is-the-account-did':
    'Could not backfill the did:webvh pointer and promote the controller; the next login retries',
  'roster-and-collection-epochs-exist':
    'Could not converge the roster and the collection epochs; the next visit retries',
  'registry-records-the-establishing-credential':
    'Could not record the establishing credential in the registry; the next visit retries',
  'annex-generation-is-reachable':
    'Could not ready the annex generation; the next visit retries',
  'generation-delegation-is-current':
    'Could not heal the generation delegation; the next login retries',
  'acting-credential-manage-zcap-is-current':
    "Could not refresh the acting credential's management zcap; the next login retries",
  'did-web-projection-matches-the-log':
    'Could not refresh the did:web projection of the account log',
  'no-annex-generation-outlives-its-pointer': 'The annex GC sweep failed',
  'app-keys-live-only-in-app-connections': 'The stranded app-key sweep failed',
  'client-key-record-matches-the-pointed-account':
    'Could not wipe the stale client residue; the next login retries',
  'this-browser-is-still-an-enrolled-client':
    'Could not confirm this browser is still an enrolled client; the login refuses',
  'no-client-key-record-stays-pending':
    'Could not resolve the pending client-key record; the next login retries',
  'recovery-spend-is-completed':
    'Could not resume the pending recovery spend; the next login retries',
  'retired-credential-leaves-no-annex-inventory':
    "Could not retire the credential's annex inventory; a later ladder-branch ceremony converges it",
  'document-lists-the-acting-credential':
    'Could not read whether the account document lists the acting credential; the login refuses',
  'keystore-controller-is-the-account-did':
    'Could not promote the keystore controller to the account did:webvh; the next login retries',
  'account-document-publishes-an-authentication-key':
    'Could not publish an authentication verification method; no converger is built',
  'every-document-key-agreement-entry-has-a-locatable-credential':
    'Could not reconcile the document key-agreement entries with the registry; no converger is built',
  'no-unlock-space-outlives-its-credential':
    'Could not remove the unlock Space left by a retired credential; no converger is built',
  'no-keystore-outlives-its-account':
    'Could not remove the keystore left by a deleted account; no converger is built',
  'saved-recovery-codes-locate-their-account':
    'Could not check the saved recovery codes; the next login retries',
  'standard-collections-are-provisioned':
    'Could not provision the standard collections; the next login retries',
  'no-auxiliary-space-stands-unnamed':
    'Could not remove the unnamed auxiliary Space; no converger is built'
}
