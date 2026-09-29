# 0033: The app-key sweep revokes only on a seed-bound row

- Status: accepted
- Date: 2026-09-28
- Driving work: the adversarial review of the design that moves menders
  toward resolve-on-read, which proposed running the stranded app-key
  sweep from the credential listing. Extracted at that design's
  approval.
- Affects: freewallet (`src/session/appKeySweep.ts`,
  `src/lib/connectedApps.ts` `revokeAppAuthority`, and every trigger
  that runs the sweep: the remembered login chain today, an encounter
  site at the credential listing later).

## Context

The stranded app-key sweep finds app-key credentials outside the
`app-connections` collection. For each one it takes `origin` and
`subjectDid` from the credential body, rotates that DID out of its
collections' key epochs, revokes its recorded grants, and deletes the
row. The revocations and rotations cannot be undone.

The body is not proof of authorship. A malicious host can write a row
into `private-credentials`. The EDV cipher seals to the write epoch's
public key and needs no key-agreement secret, and
`StorageManager.addCredential`'s refusal of the marker type covers only
the wallet's own write path. The marker rule in `isStrandedAppKey`
matches on the type before any seed check. A host that plants one
marker-typed row naming a connected app's did:key, which it sees in the
zcaps that app invokes, picks which app the next sweep disconnects. The
row's deletion then removes the evidence.

A wallet-minted app key always carries a seed that re-derives its own
subject DID (`CapabilityAgent.fromSeed`, `keyName: 'app-key'`).

## Decision

No unattended sweep revokes grants or rotates recipients on a body whose
seed does not re-derive its subject (`appKeySeedBindsSubject`). A
marker-typed row that fails the binding is deleted with no revoke stage.
The same rule covers a served `public-credentials` body, where the
recorded grant history or a seed-bound private row is the source of
`origin` and `subjectDid`.

## Rejected Alternatives

- **Act on any row `isStrandedAppKey` matches.** This is the host-choice
  attack in Context. The marker type is data the host can write.
- **Refuse the row and leave it in place when the binding fails.** A
  forged row carries no key a legitimate app holds, so deleting it loses
  nothing. Leaving it would re-trigger the sweep on every run.

## Consequences

- The seed binding is a derivation per row, so a sweep over many rows
  costs one key derivation each.
- A legitimate app key whose seed was altered in storage fails the
  binding and is deleted without its grants being revoked. The grants
  then stay live until the app is disconnected by hand. Nothing
  legitimate produces such a row.
- The rule binds the sweep itself, so it holds on every trigger that
  runs it, the remembered chain and any later encounter site alike.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. Stored credential rows gain an authorship proof the host cannot
   forge, such as a signature by a key only the wallet holds, verified
   before the sweep reads the body. The seed binding would then be a
   second check rather than the only one.
2. App keys stop being self-issued from a seed, so the binding no
   longer characterizes a wallet-minted key.
