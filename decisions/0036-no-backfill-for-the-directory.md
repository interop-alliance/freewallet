# 0036: No backfill for the directory

- Status: accepted
- Date: 2026-10-01
- Driving work: the design of the `connections` directory, which had to
  say what happens to accounts, bundles, and keys that predate it.
  Extracted at that design's approval.
- Affects: freewallet (signup provisioning, the credential-anchored mend's
  collection set, the retired stranded app-key sweep, the content
  migration); dcw (its one-time provisioning gate); wallet-backup
  (the archive survey's roster set).

## Context

The directory joins the wallet Space provision roster, so a new account
gets it at signup on every path. An account created before the build
has no `connections` collection. Only a remembered login re-walks the
roster, and a credential-anchored account never runs one unless someone
opts into remembering a browser. On such an account every consent fails
closed at the entry write, and the mend's widened collection set warns on
every transient login.

Two older artifacts have the same shape. The archive survey classifies
every non-roster collection as an app collection to migrate, so once the
writer roster's id leaves the roster, an older bundle's empty
`registered-writers` migrates as an app collection, and after the app-key
collection's rename so does an older bundle's app-key collection with its
seeds. The stranded app-key sweep retired an app's authority by reading
its grants before deleting a key stranded in `private-credentials`, and
such a key predates the directory, so the sweep would revoke nothing.

## Decision

Nothing backfills the directory. Signup provisions it on every path, and
no mender provisions it on an account that lacks it. The content
migration survey is not changed, and the retired roster ids migrate as
whatever the survey classifies them. The stranded app-key sweep is
retired rather than given a history-reading grant path. A key that
predates the directory has no entry, so a sweep would revoke no grant
for it. Deleting the key would leave the app's zcaps live, and its
key-epoch membership in every collection its `generator` stamp does not
name. Such a key stays in place.

The rule extends to `inbox` (the cleartext audiences design, 2026-10-05).
It joins the provision roster after `connections`, signup provisions it
on every path, and nothing backfills it. An account that lacks it refuses
a connection request before consent with `noInbox`. An inbox the wallet
cannot trust, one that is public, carries an `encryption` descriptor, or
carries a `generator` stamp, is refused and counts as absent, and no
migration renames it. The three torn states, an older account with no
inbox, an account whose user deleted it, and an adopted untrusted inbox,
are declared under the provisioning invariant's gap row, with the
transient-session provisioning alternative below as the one build that
would close them.

## Rejected Alternatives

- **A transient session provisions missing roster collections.** It
  holds the user key and its generation delegation covers the Space, so
  it could. It would also close the existing torn-signup provisioning
  gap. Set aside as a build for a population the greenfield stance
  excludes; the signup path is the only one that must provision.
- **The credential-anchored mend's fan-out creates a missing
  collection.** Mixes tear-mending with provisioning, needs a second
  change in the roster-mint precondition, and does nothing for the
  mobile wallet.
- **A skip list of retired roster ids in wallet-backup or wallet-core.**
  A list maintained whenever a roster id retires, for bundles from
  before the build.
- **A history-reading grant path for the sweep alone.** A permanent
  exception to "the history log is audit trail only" (0034), keeping the
  lost-row gap on that branch for a population older than the one this
  record already excludes.
- **Keep the sweep with the directory as its one grant source.** It
  deletes a pre-directory key while revoking none of the app's grants.
  The app keeps its zcaps until they expire, with no Applications page
  row to revoke them from.

## Consequences

- Every account created before the build loses App Connect and
  interaction-URL grants until a remembered login happens to provision
  the directory. The mobile wallet's one-time provisioning gate stays.
- The mend's set widens with the build, and its warning on a pre-build
  account is accepted noise.
- A content migration of an older bundle can create an empty app
  collection named `registered-writers`, and after the rename an app
  collection holding the old account's app-key seeds. The storage
  facade's refusal of externally supplied app keys covers only
  `addCredential`, not the app-collection path.
- A stranded key that predates the directory stays in
  `private-credentials`, and so does any public copy of one. The key
  keeps both of that collection's exits open onto its seed, the public
  link and the share, and a public copy stays world-readable. The app
  behind it keeps its grants until they expire.
- A transient-only account cannot connect an agent until a remembered
  login has run once on it, and the `noInbox` copy says so. An existing
  agent entry has no pairwise seed and gains one at its next connection
  request.
- The invariant `app-keys-live-only-in-app-connections` is retired from
  the mender registry and from wallet-core's invariant-id census. The
  residue is no gap the registry tracks.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A deployment with pre-build accounts goes to real users, so the
   "until a remembered login" window is observed rather than assumed.
   The transient-session provisioning alternative is the build.
2. A bundle from a pre-rename account is migrated in practice and its
   seeds land in an app collection. The survey skip list is the build.

## Changelog

- 2026-10-01: Retired the stranded app-key sweep, because a pre-directory
  key has no grants in the directory to revoke. The Decision, a new
  Rejected Alternative, and the Consequences state what such a key now
  leaves in place.
- 2026-10-05: Extended from the directory to the `inbox` collection the
  cleartext audiences design adds to the roster. A refinement: the same
  rule applied to a second roster member, with its three torn states
  declared.
