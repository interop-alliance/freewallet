# 0050: The copy is whole, and the replica-server set is disclosed to the account's storage hosts

- Status: accepted
- Date: 2026-10-26
- Driving work: the design that lets every session kind, the transient
  default included, register a replica server and copy the account onto
  it. Extracted at that design's approval.
- Affects: freewallet (the replica registration ceremony, which omits
  `collections` and registers the auxiliary Space; its pre-flight's
  client-annex profile check on the replica server), wallet-core
  (`/space`: the `grantable: false` collections, whose rule this record
  bounds), portable-web-spaces-spec (the replication decision 0013
  amendment, which records the annex copy as a new disclosure of the
  replica servers' DIDs).

## Context

A registration may name the collections it copies. When it names none,
the replica server copies every live non-reserved Collection. That
includes `key-map`, the user key's wrap-set roster, which wallet-core
marks `grantable: false` because, for a passphrase credential, it is an
offline guessing oracle. It also includes `unlock-methods`, and the
`connections` and `app-keys` ciphertext. The `grantable: false` rule
was written to keep these from a third party.

The ceremony also copies the auxiliary Space. Without it every annex and
transient invocation fails on the replica, and a transient session reads
from both Spaces while the source server stands. The annex document in
that Space carries a replica pointer for every replica server (decision
0045). The source account Space's served `replicas` member lists none
under one-way pull, and copies strip it. So no replica server learned
of the others before.

## Decision

The copy is whole. The wallet omits `collections`, so each replica
server copies every live Collection of the account Space, the
non-grantable ones included, and the whole auxiliary Space. The
`collections` member stays on the `replicas` item for later use cases
that copy specific collections only.

The `grantable: false` rule bounds a grantee, a party holding a scoped
capability on one collection. A replica server is a storage host, in
the same trust class as the source host, which already holds all of
these. The user picks a replica server with that trust. The pre-flight
requires the replica server to claim the client-annex profile, as the
source host must.

The disclosure is accepted. Once the auxiliary Space is copied, each
replica server reads every other replica server's DID from the annex
document. The source host reads them too. Its half is partly moot,
since it verifies every pull and so learns each `serverDid` that pulls.
The audience stays the capability-gated annex: the account's own
sessions, the source host, and the replica servers.

## Rejected Alternatives

- **Exclude the non-grantable collections by default.** It would leave
  a copy of ciphertext nobody can open once the source server is gone.
  A login against the replica needs `key-map` and `unlock-methods`
  there.
- **Leave the auxiliary Space out of the flow.** The account copy is
  then useless to a credential-anchored account, since every chain a
  transient session presents runs through the annex.
- **A blinded pointer**, an HMAC of the `serverDid`. It would protect
  only against the other replica servers, since the source host needs
  the key to check the replica-pull predicate.
- **A per-server filtered annex copy.** Removing other servers' entries
  from one server's copy breaks the log's chain hash.

## Consequences

- Each replica server holds the `key-map` roster, so for a passphrase
  credential each one is an offline guessing oracle, as the source host
  is. A passphrase's entropy bounds every replica server as it bounds
  the source host.
- Each replica server receives ciphertext for every encrypted
  collection, and plaintext for `public-credentials`, `inbox`, `id`,
  `key-map`, `unlock-methods`, and every plaintext requester or
  audience collection.
- The `connections` directory reaches each replica server as
  ciphertext. That copy is inert (decisions 0034 and 0035).
- Replica servers learn each other's DIDs, a disclosure the replication
  decision did not cover before.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A use case calls for a replica server trusted less than a storage
   host, such as a mirror of public collections. That calls for a
   selective `collections` list, as a separate registration shape.
2. A mechanism lets the source host check the replica-pull predicate
   against a pointer the replica servers cannot read, without breaking
   the annex log's chain hash.
