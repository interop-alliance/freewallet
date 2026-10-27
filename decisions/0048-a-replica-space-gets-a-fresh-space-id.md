# 0048: A replica Space gets a fresh Space id

- Status: accepted
- Date: 2026-10-26
- Driving work: the design that lets every session kind, the transient
  default included, register a replica server and copy the account onto
  it. Extracted at that design's approval.
- Affects: freewallet (the replica registration ceremony's inert entry
  write and its pre-flight adoption of an existing item), wallet-core
  (`/connections`: the `replicas` item's `spaceId` and
  `registrationId`), portable-web-spaces-spec (the replication decision
  0013 amendment).

## Context

A replica Space on the replica server needs a Space id. The
registration record names the local Space (`toSpace`) and the source
Space (`fromSpace`) separately, so nothing in the protocol forces them
to match. Reusing the source Space's id would make a replica look like
the same Space on a second host. It is not: a registration can exclude
collections, and replication can be one-way or conditional.

A Space id used before it is persisted strands on a tear. A re-run with
a different fresh id then meets the replica server's mapping check,
which refuses a second registration of the same source Space.

## Decision

The account replica Space and the auxiliary replica Space each get a
fresh Space id, minted by the account Space's `mintSpaceId` convention:
32 random bytes, base64url with no padding. Each registration gets a
fresh registration id from the same mint, so a first registration does
not collide.

Both Space ids are recorded on the `replica-server` entry's `replicas`
items at the ceremony's inert first write, before either is used. A
re-run adopts an existing item that has no grant and no pointer,
keeping its Space ids.

The unlock Spaces are outside this rule and outside the registration.
Without them, a login against the replica cannot locate the account, so
the copy serves reads from both Spaces while the source server stands.

## Rejected Alternatives

- **The same Space id on both hosts.** Rejected on 2026-10-23. A
  replica is not Space-to-Space: collections can be excluded, and
  replication can be one-way or conditional. Do not reopen for the
  account Space or the auxiliary Space.

## Consequences

- The replica Space ids live only on the encrypted directory entry,
  which the user key unlocks. With the source server gone, nothing
  locates the copy until the unlock Spaces are copied too, which is
  later work.
- The pass and the Storage page find each replica Space through its
  `replicas` item, not through any id convention. The invariant
  `no-auxiliary-space-stands-unnamed` stays scoped to the source host.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A Space whose id is content-addressed is brought into replication.
   An unlock Space is located by `spaceId = base64url(SHA-256(unlock
   did:key))`, so its replica must keep the same id. That is a
   carve-out for content-addressed Spaces, recorded beside this rule,
   and it does not reopen the fresh id for the account and auxiliary
   Spaces.
