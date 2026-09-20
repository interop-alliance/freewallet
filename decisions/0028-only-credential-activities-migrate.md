# 0028: Only credential activities migrate across accounts

- Status: accepted
- Date: 2026-09-17
- Driving work: the design for migrating a backup bundle's content into
  a new account, whose adversarial re-review showed that carrying every
  `wallet-activity` row verbatim is unsafe.
- Affects: freewallet (the activity import function's type allowlist;
  the readers of `Login`, `Revoke`, and `CollectionShare` rows in
  `src/lib/connectedApps.ts`, `src/session/shares.ts`, and
  `src/stores/storageManager.ts`); dcw (its own sink applies the same
  allowlist); `@interop/wallet-backup` (the report counts the dropped
  rows).

## Context

`wallet-activity` holds two kinds of row. Credential activities
(`Create`, `Delete`, `Share`, `Unshare` on one credential) are records
of the content. The rest record authority events on the account:
`Login` rows carry the grants delegated to an app or agent, agent
`Revoke` rows carry the revoked capability ids, `CollectionShare` rows
carry the share zcap, plus `ClientRevoke`, `CollectionUnshare`,
`GenerationCollect`, and the account-genesis `Create`s. The listings and
the revoke paths act on the second kind: `listConnectedAgents` derives
agent rows from history alone and hides a live `Login` behind a later
`Revoke` for the same did:key; `#recordedGrantZcaps` and
`#recordedShareZcaps` harvest zcaps from history and POST them to the
revocation route.

The rows are unsigned and, in a bundle, are text the bundle author
chose. A migrated `Revoke` from the old account hides a genuine live
agent grant on the new one. A migrated share row is re-POSTed with the
old account's capability chain the moment the user re-shares with the
same reader. A filter on the grant's `invocationTarget` was designed
and falsified the same day: an agent `Revoke` carries no target, the
label join reads no zcap, and an author who knows the new Space id
writes a grant that passes.

## Decision

The activity import function admits the credential activities alone,
the rows `credentialActivityInfo` (`src/lib/historyActivity.ts`)
classifies. Every other activity type is dropped and counted in the
report beside the app-provisioned collections. No stored row gains a
marker member.

## Rejected Alternatives

- Verbatim rows plus a target filter in the consumers. Falsified: one
  row type has no target, two readers were missed, and the filter's
  input is bundle text.
- A marker member on migrated rows that every action reader honours. It
  works, including against a planted row, but it is a new permanent wire
  member and touches every reader; it is the shape to consider if the
  other types are ever carried across.
- Dropping the old activity entirely. The credential rows are the
  content's own history and are sealed under the same user key as the
  content.

## Consequences

- The History page on a migrated account shows the old credential
  history and none of the old logins or shares.
- The target check the harvesters lack is a gap without migration too,
  since any enrolled client writes history; it is tracked as a
  hardening on its own.
- Bringing the other types across waits on a discriminator that does
  not rest on bundle text: verified bundle provenance, or the marker
  member above.

## Revisit Criteria

1. Bundle provenance verifies end to end (a server signature over the
   export, checked offline), so a migrated row's origin is evidence
   rather than text.
2. The action readers stop deriving state from history rows at all (for
   instance, agent grants get a collection of their own); the hazard
   then moves with them.
