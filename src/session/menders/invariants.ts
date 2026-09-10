/**
 * The freewallet invariant census: one declaration per predicate that must
 * hold between ceremonies, keyed by the invariant ids `@interop/wallet-core`
 * carries. Every declaration is data -- what holds, on which account shapes,
 * under whose authority, where it is checked today, which torn ceremonies
 * violate it, what a detector trusts, and what a runner logs when the code
 * reporting it throws. Every member is transcribed from the
 * approved design of this registry, and the ids are code-only: nothing
 * persists them.
 *
 * The table is data alone: the code that converges a violated predicate is
 * a registration (`registrations.ts`), and the runner logs the `warn` of
 * every invariant a throwing registration reports. Those messages live in
 * `warnings.ts`, which the ceremony-tail reporter reads on its own. The `Deps` parameter
 * stays `never` here, since a declaration's own `holdsWhen` detector takes
 * its concrete parameter object rather than a chain's dependency object;
 * the registrations carry the chain deps.
 */
import type { InvariantDeclaration } from '@interop/wallet-core/menders'

import type { FreewalletCeremonyId } from '../ceremonies.js'
import { findPendingPassphraseEntries } from '../credentialCoverage.js'
import { documentListsCredential } from '../pendingRetirement.js'
import { checkRecoveryHealth } from '../recovery.js'
import { MENDER_WARNINGS } from './warnings.js'

/**
 * Every invariant this wallet declares, in the design table's numeric order
 * (which is `INVARIANT_IDS` order), minus the warn copy: each declaration's
 * message is its entry in `MENDER_WARNINGS`, attached below rather than
 * restated here.
 */
const DECLARATIONS: ReadonlyArray<
  Omit<InvariantDeclaration<never, FreewalletCeremonyId>, 'warn'>
> = [
  // 1
  // converger: `convergeRosterToDocument` (`src/session/userKeySweep.ts`)
  // over wallet-core `/clients`' `convergeUserKeyRosterToAccount`.
  {
    id: 'roster-wraps-exactly-the-document-key-set',
    statement:
      "The user key roster's current epoch wraps the user key to exactly the key-agreement keys the account document lists: no recipient the document has stopped keying, and no keyed client left without a wrap.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'ceremony-tail'],
    ceremonies: [
      'client-revocation',
      'recovery-code-spend',
      'recovery-code-revocation',
      'unlock-credential-rotation',
      'forget-client',
      'last-client-transition',
      'self-enrollment',
      'client-enrollment',
      'recovery-code-issuance'
    ],
    // The comparison is the roster's verified log head against the verified
    // account document, both read under the visit's pins.
    evidence: ['verified-log']
  },
  // 2
  // converger: none of its own -- the roster half is the `seal()` backstop
  // inside invariant 1's converger, the collection half sits inside
  // invariant 3's (`cascadeCollectionsToUserKey`).
  {
    id: 'governed-log-heads-anchor-past-the-membership-change',
    statement:
      "A governed log's verified head (the roster's, and each encrypted collection's `meta/log`) is anchored at a controller version no earlier than the controller's latest assertion-key removal.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'ceremony-tail'],
    ceremonies: [
      'client-revocation',
      'forget-client',
      'last-client-transition',
      'unlock-credential-rotation',
      'recovery-code-revocation'
    ],
    // The anchored version of a governed log's verified head, read under the
    // visit's pins.
    evidence: ['verified-log']
  },
  // 3
  // converger: wallet-core's driver (`keys/userKeyCascade.ts`), called by
  // `cascadeCollectionsToUserKey` (`src/session/userKeyCascade.ts`).
  {
    id: 'collection-epochs-name-the-current-user-key',
    statement:
      "Every encrypted collection's current key epoch names the current user key generation.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'ceremony-tail'],
    ceremonies: [
      'client-revocation',
      'recovery-code-spend',
      'recovery-code-revocation',
      'unlock-credential-rotation',
      'forget-client',
      'last-client-transition',
      'self-enrollment',
      'client-enrollment',
      'recovery-code-issuance'
    ],
    // Each collection's epoch comes from its governing log's verified head;
    // the candidate set the cascade walks is seeded from the host-served
    // `isEncrypted` flag on the collection listing (design note 3).
    evidence: ['verified-log', 'host-listing']
  },
  // 4
  // converger: `repairStaleUnlockRegistrySeal`
  // (`src/session/registryReseal.ts`).
  {
    id: 'unlock-registry-opens-under-the-current-user-key',
    statement:
      "The unlock-methods registry record is sealed to the account's current user key generation.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'transient-login-chain'],
    ceremonies: [
      'client-revocation',
      'recovery-code-spend',
      'recovery-code-revocation',
      'unlock-credential-rotation',
      'forget-client',
      'last-client-transition'
    ],
    evidence: ['served-registry'],
    // The CHAPI popup stands this pass down: it writes no registry.
    when: (route: { popup: boolean }) => !route.popup
  },
  // 5
  // converger: `repairTornPassphraseRetirement`
  // (`src/session/pendingRetirement.ts`), including FW-454's establish-first
  // arm; detector: `findPendingPassphraseEntries`
  // (`src/session/credentialCoverage.ts`).
  {
    id: 'registry-passphrase-entry-names-the-standing-credential',
    statement:
      "The registry's passphrase entry names the credential the account document anchors, and no superseded passphrase credential is left standing behind it.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'transient-login-chain'],
    ceremonies: ['unlock-credential-rotation', 'credential-anchored-genesis'],
    evidence: ['served-registry'],
    // The CHAPI popup stands this pass down: it writes no registry.
    when: (route: { popup: boolean }) => !route.popup,
    async holdsWhen(
      deps: Parameters<typeof findPendingPassphraseEntries>[0]
    ): Promise<'holds' | 'violated' | 'undetermined'> {
      try {
        const pending = await findPendingPassphraseEntries(deps)
        return pending.length > 0 ? 'violated' : 'holds'
      } catch {
        return 'undetermined'
      }
    }
  },
  // 6
  // converger: `rebuildBarePasskeyEntry` (`src/session/pendingRetirement.ts`).
  {
    id: 'passkey-entry-carries-its-standing-configuration',
    statement:
      "Every passkey entry in the registry carries its credential's standing configuration rather than a bare shape.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'transient-login-chain'],
    ceremonies: ['unlock-credential-rotation'],
    evidence: ['served-registry'],
    // The CHAPI popup stands this pass down: it writes no registry.
    when: (route: { popup: boolean }) => !route.popup
  },
  // 7
  // converger: `backfillPassphraseUnlockMethod`
  // (`src/session/unlockMethods.ts`).
  {
    id: 'registry-lists-the-passphrase-method',
    statement:
      "The registry lists a passphrase entry whenever the account can be unlocked by one, with that credential's current fields.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'transient-login-chain'],
    ceremonies: [],
    evidence: ['served-registry'],
    // The CHAPI popup stands this pass down: it writes no registry.
    when: (route: { popup: boolean }) => !route.popup
  },
  // 8
  // converger: the remembered chain's standing-delegation refresh closure
  // (`delegateLogWrite`, `mintDelegatedClientsDelegation`,
  // `rebindStandingRecord`, then `refreshStandingDelegationFields`); the
  // transient half sits inside `ensureClientAnnexGenerationReady`
  // (`src/session/transientLogin.ts`). Neither is an addressable symbol.
  // Also runs in the remote-direct CHAPI popup.
  {
    id: 'standing-delegations-verify-under-the-current-document',
    statement:
      "The acting credential's bridge delegation and its `delegatedClients` sibling are unexpired, outside the renewal window, and signed by a key the verified account document still lists under `capabilityDelegation`.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'login-routing'],
    ceremonies: [
      'unlock-credential-rotation',
      'client-revocation',
      'recovery-code-revocation'
    ],
    evidence: ['served-registry', 'local-clock']
  },
  // 9
  // converger: the ladder-rung refresh closure (`attributeLadderRung`, then
  // `refreshStandingDelegationFields`, `src/session/initSession.ts`), not an
  // addressable symbol.
  // Also runs in the remote-direct CHAPI popup.
  {
    id: 'registry-records-the-committed-ladder-rung',
    statement:
      "The registry entry's recorded update key is the rung the credential's ladder has actually committed.",
    standsOn: ['enrolled'],
    authority: 'enrolled',
    triggers: ['remembered-login-chain'],
    ceremonies: ['self-enrollment'],
    // The recorded rung is a served registry field; the committed rung is
    // read off the account log under the visit's pins.
    evidence: ['served-registry', 'verified-log']
  },
  // 10
  // converger: `mendCredentialAnchoredAccount`'s establishment arm
  // (wallet-core `/clientAnnex`), driven by `healUnpromotedRememberedAccount`
  // (`src/session/initSession.ts`) and by the transient composition's
  // single-shot heal.
  {
    id: 'unlock-record-points-at-the-account-did',
    statement:
      "The acting credential's unlock record points at the account's did:webvh.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'ladder',
    triggers: ['login-routing'],
    ceremonies: ['credential-anchored-genesis'],
    evidence: ['served-unlock-record']
  },
  // 11
  // converger: `healAccountPointer` (`src/session/pointerHeal.ts`), over the
  // `persistAccountPointer` closure the keyring hit carries. Also runs in
  // the remote-direct CHAPI popup.
  {
    id: 'account-pointer-names-the-account-did',
    statement:
      "Every unlock record's persisted account pointer names the account's did:webvh rather than the signup-time did:key.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'enrolled',
    triggers: ['remembered-login-chain'],
    ceremonies: ['account-genesis', 'credential-anchored-genesis'],
    evidence: ['served-unlock-record']
  },
  // 12
  // converger: `ensurePromotedController` (`src/stores/storageManager.ts`),
  // reached by `healAccountPointer` on the remembered chain and by
  // `#provisionUserCollections` at signup; `mendCredentialAnchoredAccount`'s
  // promotion arm on the transient path.
  {
    id: 'space-controller-is-the-account-did',
    statement: "The data Space's controller is the account's did:webvh.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'login-routing'],
    ceremonies: ['account-genesis', 'credential-anchored-genesis'],
    // The controller comes back on the host's own answer for the Space. The
    // vocabulary carries no served-description value, and a Space read is
    // the closest of the host-served kinds.
    evidence: ['host-listing']
  },
  // 13
  // converger: `mendCredentialAnchoredAccount`'s roster-and-epochs arm
  // (wallet-core `/clientAnnex`).
  {
    id: 'roster-and-collection-epochs-exist',
    statement:
      'The account has a user key roster whose current epoch the acting credential can open, and every encrypted collection carries an epoch under it.',
    standsOn: ['client-less'],
    authority: 'ladder',
    triggers: ['login-routing'],
    ceremonies: ['credential-anchored-genesis'],
    // The roster's head and each collection's descriptor log head, read
    // under the visit's pins.
    evidence: ['verified-log']
  },
  // 14
  // converger: `mendCredentialAnchoredAccount`'s registry arm (wallet-core
  // `/clientAnnex`), gated on the in-memory `repairShaped` marker.
  {
    id: 'registry-records-the-establishing-credential',
    statement:
      'A credential whose establishment landed has its registry entry, with its delegations recorded.',
    standsOn: ['client-less'],
    authority: 'ladder',
    triggers: ['login-routing'],
    ceremonies: ['credential-anchored-genesis'],
    evidence: ['served-registry']
  },
  // 15
  // converger: `ensureClientAnnexGenerationReady`
  // (`src/session/transientLogin.ts`) over wallet-core's
  // `ensureCredentialClientAnnexGeneration`; not exported.
  {
    id: 'annex-generation-is-reachable',
    statement:
      "The account document points at a published annex generation in a live auxiliary Space, and the acting credential's sibling delegation aims at that Space.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'ladder',
    triggers: ['login-routing'],
    ceremonies: ['credential-anchored-genesis'],
    // The pointer comes off the verified account document; whether the
    // auxiliary Space is live is the host's own answer.
    evidence: ['verified-log', 'host-listing']
  },
  // 16
  // converger: `ensureGenerationDelegation` (`src/session/annexReach.ts`) on
  // the remembered chain; `ensureClientAnnexGenerationReady` on the transient
  // path; the revocation's `remintGenerationDelegation` closure; and the App
  // Connect grant path's `delegationStale` renewal.
  {
    id: 'generation-delegation-is-current',
    statement:
      "The pointed generation's embedded delegation is unexpired and signed by a key the verified account document still lists.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'login-routing', 'ceremony-tail'],
    ceremonies: ['client-revocation', 'unlock-credential-rotation'],
    // Expiry is the local clock against the embedded delegation; the signer
    // check reads the verified account document under the visit's pins.
    evidence: ['verified-log', 'local-clock'],
    // The CHAPI popup stands this pass down: it writes no registry.
    when: (route: { popup: boolean }) => !route.popup
  },
  // 17
  // converger: `refreshTransientManageCapability`
  // (`src/session/unlockMethods.ts`).
  {
    id: 'acting-credential-manage-zcap-is-current',
    statement:
      "The acting credential's registry entry carries an unexpired management zcap for its own unlock Space.",
    standsOn: ['client-less'],
    authority: 'ladder',
    triggers: ['transient-login-chain'],
    ceremonies: [],
    evidence: ['served-registry'],
    // The CHAPI popup stands this pass down: it writes no registry.
    when: (route: { popup: boolean }) => !route.popup
  },
  // 18
  // converger: `refreshDidWebProjection` (`src/session/annexReach.ts`),
  // called fire-and-forget from the transient composition.
  {
    id: 'did-web-projection-matches-the-log',
    statement:
      "The served `id/did.json` matches the account log's current document; any inventory-changing ceremony can violate it, which is prose rather than a list of ids.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['transient-login-chain'],
    ceremonies: [],
    evidence: ['served-projection']
  },
  // 19
  // converger: `sweepClientAnnexGenerations` (`src/session/clientAnnexGc.ts`)
  // over wallet-core's `runClientAnnexGc`.
  {
    id: 'no-annex-generation-outlives-its-pointer',
    statement:
      'Every non-pointed `gen-` collection is digested and deleted, and the pointed generation is inside its swap period.',
    standsOn: ['client-less', 'enrolled'],
    authority: 'enrolled',
    triggers: ['remembered-login-chain'],
    ceremonies: [],
    evidence: ['host-listing'],
    // The CHAPI popup stands this pass down: it writes no registry.
    when: (route: { popup: boolean }) => !route.popup
  },
  // 20
  // converger: `sweepStrandedAppKeys` (`src/session/appKeySweep.ts`).
  {
    id: 'app-keys-live-only-in-app-connections',
    statement:
      'No app-key credential remains in `private-credentials`, and no world-readable app-key copy stands with no private row behind it.',
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain'],
    ceremonies: [],
    evidence: ['served-body']
  },
  // 21
  // converger: `wipeStaleClientResidue` (`src/session/forget.ts`) plus the
  // one re-route on `StaleClientKeyRecordError`.
  {
    id: 'client-key-record-matches-the-pointed-account',
    statement:
      "This browser's client-key record is stamped with the account its unlock record now points at.",
    standsOn: ['enrolled'],
    authority: 'none',
    triggers: ['login-routing'],
    ceremonies: [],
    evidence: ['served-unlock-record', 'local-record']
  },
  // 22
  // converger: `assertClientStillEnrolled` (`src/session/forget.ts`), which
  // wipes and refuses with `BrowserForgottenError`.
  {
    id: 'this-browser-is-still-an-enrolled-client',
    statement:
      'A client-key record holding a user key names a verification method the verified account document still lists.',
    standsOn: ['client-less', 'enrolled'],
    authority: 'none',
    triggers: ['login-routing'],
    ceremonies: [
      'forget-client',
      'last-client-transition',
      'client-revocation'
    ],
    evidence: ['verified-log', 'local-record']
  },
  // 23
  // converger: `resumePendingEnrollment`
  // (`src/session/pendingEnrollment.ts`), through its discard arm and its
  // wipe arm.
  {
    id: 'no-client-key-record-stays-pending',
    statement:
      'No client-key record stays in the pending shape a persist-before-publish hook wrote.',
    standsOn: ['enrolled'],
    authority: 'enrolled',
    triggers: ['login-routing'],
    ceremonies: [
      'self-enrollment',
      'recovery-code-spend',
      'forget-client',
      'client-revocation'
    ],
    // The pending record is this browser's; the discard arm decides against
    // the served unlock record (design note 23).
    evidence: ['local-record', 'served-unlock-record']
  },
  // 24
  // converger: `resumeRecoverySpend` (`src/session/recovery.ts`), dispatched
  // inside `resumePendingEnrollment` and completed by a user click through
  // `session.recoverySpendPrompt`.
  {
    id: 'recovery-spend-is-completed',
    statement:
      "A spent recovery code's roster escrows, standing backfill, registry mutation, and record completion have all landed.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'enrolled',
    triggers: ['login-routing'],
    ceremonies: ['recovery-code-spend'],
    // The pending record carries the spend's `builtOnHead` witness; which
    // stages landed is read off the served record and registry.
    evidence: ['local-record', 'served-unlock-record', 'served-registry']
  },
  // 25
  // converger: the rotation's `retireClientAnnexInventoryStage`
  // (`src/session/credentialRotation.ts`), not exported, reached through the
  // `retireClientAnnexInventory` closure.
  {
    id: 'retired-credential-leaves-no-annex-inventory',
    statement:
      "A retired credential's annex rung hashes and ladder VMs are struck from the pointed generation.",
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['ceremony-tail'],
    ceremonies: ['unlock-credential-rotation'],
    // The inventory is read off the annex log's verified head.
    evidence: ['verified-log']
  },
  // 26
  // detector: `documentListsCredential` (`src/session/pendingRetirement.ts`),
  // which refuses the transient login with `credential-not-standing`.
  {
    id: 'document-lists-the-acting-credential',
    statement:
      "The account document lists this credential's `keyAgreement` inventory (a passphrase's commitment, a passkey's verbatim key).",
    standsOn: ['client-less', 'enrolled'],
    authority: 'none',
    triggers: ['login-routing'],
    ceremonies: ['credential-anchored-genesis', 'unlock-credential-rotation'],
    evidence: ['verified-log'],
    async holdsWhen(
      deps: Parameters<typeof documentListsCredential>[0]
    ): Promise<'holds' | 'violated' | 'undetermined'> {
      try {
        return (await documentListsCredential(deps)) ? 'holds' : 'violated'
      } catch {
        return 'undetermined'
      }
    }
  },
  // 27
  // converger: `promoteAccountKeystore` (`src/stores/storageManager.ts`),
  // fired by `ensurePromotedController` and reported by the remembered
  // block's tail registration, which awaits the promise the pointer heal
  // left on its deps (or, with no heal, the one provisioning fired). The
  // report sits in the tail so
  // `registryReady` does not wait on a KMS round trip. Its authority is the
  // account's rather than the ladder's, since the one registration that
  // reports it runs on the remembered chain.
  {
    id: 'keystore-controller-is-the-account-did',
    statement:
      "The WebKMS keystore's controller is the account's did:webvh rather than the ladder's bare did:key.",
    standsOn: ['client-less'],
    authority: 'account',
    triggers: ['remembered-login-chain'],
    ceremonies: ['credential-anchored-genesis'],
    // The keystore configuration the KMS serves, which the promotion reads
    // before it writes.
    evidence: ['served-body']
  },
  // 28
  // No converger.
  {
    id: 'account-document-publishes-an-authentication-key',
    statement:
      'The account document publishes an `authentication` verification method, so the account can present `web` and `webvh` identities.',
    standsOn: ['client-less', 'enrolled'],
    authority: 'ladder',
    triggers: [],
    ceremonies: ['credential-anchored-genesis', 'account-genesis'],
    evidence: ['verified-log']
  },
  // 29
  // No converger; two built detectors stand behind it,
  // `findUnrecordedStandingCredentials` (`src/session/credentialCoverage.ts`)
  // and `checkRecoveryHealth` (invariant 32).
  {
    id: 'every-document-key-agreement-entry-has-a-locatable-credential',
    statement:
      'Every `keyAgreement` entry in the account document belongs to a credential the unlock-methods registry names.',
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: [],
    ceremonies: ['recovery-code-issuance', 'unlock-credential-rotation'],
    evidence: ['verified-log', 'served-registry']
  },
  // 30
  // No converger.
  {
    id: 'no-unlock-space-outlives-its-credential',
    statement:
      'No unlock Space stands whose credential the account has retired or whose account is gone.',
    standsOn: ['client-less', 'enrolled'],
    authority: 'ladder',
    triggers: [],
    ceremonies: [
      'account-deletion',
      'recovery-code-spend',
      'unlock-credential-rotation'
    ],
    // A detector would compare the registry's live credentials against the
    // Spaces the host still serves.
    evidence: ['served-registry', 'host-listing']
  },
  // 31
  // No converger; a server-side reaper is not a wallet mender.
  {
    id: 'no-keystore-outlives-its-account',
    statement:
      'No WebKMS keystore stands for an account whose Space has been deleted.',
    standsOn: ['client-less', 'enrolled'],
    authority: 'ladder',
    triggers: [],
    ceremonies: ['account-deletion'],
    // A detector would probe the keystore the KMS serves, as invariant 27's
    // would.
    evidence: ['served-body']
  },
  // 32
  // detector: `checkRecoveryHealth` (`src/session/recovery.ts`), called from
  // `src/session/completeAppLogin.ts` on both compositions, which nudges the
  // user rather than refusing. Its site runs after the chain and awaits
  // `session.registryReady`, so the row is declared on both chain triggers
  // and registered at neither.
  {
    id: 'saved-recovery-codes-locate-their-account',
    statement:
      'Every recovery code the account has issued still locates a record the account can spend, and the count the user was given matches the count that stands.',
    standsOn: ['client-less', 'enrolled'],
    authority: 'none',
    triggers: ['remembered-login-chain', 'transient-login-chain'],
    ceremonies: [
      'recovery-code-issuance',
      'recovery-code-revocation',
      'unlock-credential-rotation'
    ],
    // The recovery entries come from the served registry; their standing is
    // settled against the verified account log.
    evidence: ['served-registry', 'verified-log'],
    async holdsWhen(
      deps: Parameters<typeof checkRecoveryHealth>[0]
    ): Promise<'holds' | 'violated' | 'undetermined'> {
      try {
        const flags = await checkRecoveryHealth(deps)
        return flags.length > 0 ? 'violated' : 'holds'
      } catch {
        return 'undetermined'
      }
    }
  },
  // 33
  // converger: `storage.ensureUserCollections`, a `StorageManager` method
  // fired as a `storageReady` sweep; it refuses an in-memory session, so the
  // transient trigger is impossible (design note 33).
  {
    id: 'standard-collections-are-provisioned',
    statement:
      'The account Space carries every standard collection the wallet writes to, each with its descriptor.',
    standsOn: ['client-less', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain'],
    ceremonies: ['account-genesis', 'credential-anchored-genesis'],
    evidence: ['host-listing']
  },
  // 34
  // No converger, and no deleter at all: the stranding happens before any
  // ceremony's pointer entry lands.
  {
    id: 'no-auxiliary-space-stands-unnamed',
    statement:
      'No `gen-` auxiliary Space stands that no account-log pointer entry names.',
    standsOn: ['client-less', 'enrolled'],
    authority: 'enrolled',
    triggers: [],
    ceremonies: [],
    // A detector would compare the account log's pointer entries with the
    // auxiliary Spaces the host still serves.
    evidence: ['verified-log', 'host-listing']
  }
]

/**
 * The declarations as the registry reads them: each one carrying the warn
 * string a runner logs when the code reporting it throws.
 */
export const MENDER_INVARIANTS: ReadonlyArray<
  InvariantDeclaration<never, FreewalletCeremonyId>
> = DECLARATIONS.map(declaration => ({
  ...declaration,
  warn: MENDER_WARNINGS[declaration.id]
}))
