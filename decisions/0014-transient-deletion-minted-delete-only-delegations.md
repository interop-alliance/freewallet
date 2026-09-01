# 0014: Deletion authority reaches a transient session as minted DELETE-only delegations

- Status: accepted
- Date: 2026-09-01
- Driving work: the FW-400 design gate (account deletion from a
  transient session). Extracted at that design's approval, from its
  rejected-alternatives section.
- Affects: freewallet (`deleteAccount` and the deletion walk),
  `@interop/wallet-core` (`/clientAnnex` capability mints, `/keyring`),
  was-teaching-server (the client-annex clause's admission predicate),
  wallet-attached-storage-spec (the container rule's exceptions),
  app-connect-spec (`decisions/0002` and `decisions/0003`).

## Context

The default session type is transient, and a transient session holds no
key the account document lists under `capabilityInvocation`: the
per-visit annex VM lives in the annex document, the ladder VM is
delegation-only, and no enrolled client exists. Account deletion must
still remove every Space the account owns -- the account Space, the
auxiliary annex Space(s), and each unlock Space -- or the leftovers
stand as the existence oracles the unlock-Space work removed. The
question this record settles is how destruction authority reaches that
session at all.

## Decision

Deletion authority is minted at the ceremony, never held standing and
never rooted. Per Space, immediately before its own DELETE, the ladder
VM (signing under its document verification-method id) delegates one
capability:

- `invocationTarget` exactly the Space's bare URL -- the parent's
  target unchanged when the parent is a registry entry's
  `manageCapability`, the root's own Space URL when the parent is the
  Space's synthesized root;
- `allowedAction` exactly `['DELETE']`;
- `expires` ten minutes;
- `controller` (and invoker) the ladder VM's own bare did:key on a
  transient session, re-derived from the ladder seed, which resolves
  from its own bytes and so survives every phase of the walk; the
  account did:webvh on a remembered session, the delegator naming
  itself.

Nothing is persisted and nothing is revoked: on success the Space it
names is gone, and on a torn run it lapses by TTL. The server admits
the chain through the client-annex clause's target-and-verb predicate
(app-connect-spec `decisions/0003`, third predicate; the reference
server's own record sits in its `decisions/`) and the WAS container
rule's exact-target single-verb DELETE exception. The ladder VM never
becomes a root invoker of anything.

This capability is distinguishable from wallet-core `decisions/0013`'s
rejected "sign a transient session's grants with the ladder VM,
root-parented", which stays rejected: one verb rather than a grant
vocabulary, no onward grantee (so no per-hop expiry bound to manage),
and a ten-minute life -- and it is admitted by exactly the clause
narrowing that record said such a grant falls outside.

## Rejected Alternatives

- **A server rule admitting a `capabilityDelegation` member as a
  direct root invoker of a Space DELETE.** It hands every
  delegation-capable key in every account document on the deployment a
  destructive root primitive, written into a cross-wallet authorization
  profile, where the design needed one credential's ladder VM to reach
  one account's Spaces. It sits outside the client-annex clause, whose
  inspector skips the chain's root, so the one place the ecosystem
  bounds ladder authority would have nothing to say about it. And it
  needs server code before the ceremony can run, where the delegation
  shape needs none. Two variants fall with it: keying the rule on the
  method's subject (withholds the annex deletes a transient run needs)
  and pairing membership with a registry-liveness check (the server
  holds no registry).
- **An account-log entry adding the ladder VM to
  `capabilityInvocation`.** It breaks the relation-asymmetry
  recognition of the ladder VM (wallet-core `decisions/0004`), which
  about a dozen sites across wallet-core and the server consume: the
  entry would silently reclassify the VM as an enrolled client in
  client listings, the server's clause, and the log controller's
  inventory. A run torn between the entry and the DELETE leaves an
  unrecognizable key standing with no mender. Its one unique benefit
  (a retired credential cannot append it) is already delivered by the
  retirement gate (wallet-core's record).
- **An unconstrained clause predicate for ladder-signed DELETE
  delegations.** With no bound on target or verb, the delegation is a
  whole-Space primitive: a bare Space URL is a prefix, so it reached
  `did.jsonl`, the user-key roster, every resource, and `/policy`, and
  the granted key could sub-delegate onward unexamined. The chosen
  mechanism is the same delegation bounded at both ends.
- **A loud ephemeral enrolled client.** Legal and server-change-free,
  but it writes two world-readable log entries whose sole purpose is
  to carry an invoking key discarded the instant the Space dies.
  Loudness buys nothing for a destructive ceremony, and a torn run
  leaves a live invoking method whose key died with the tab. Rejected
  for deletion specifically.
- **A server-side delete-time cascade on the account Space.** A new
  Space DELETE semantic the spec would have to state normatively: one
  request destroying Spaces it never named, with no way to report
  which Space failed. A periodic orphan-reaping sweep stays a separate
  server nice-to-have.
- **A deletion delegation controlled by the annex DID or minted from
  the annex Space.** Deadlocks: the invoker's DID document lives in a
  Space the walk deletes, and the server busts its resolved-document
  cache on Space DELETE, so once the annex Space is gone no request
  signed as `<annexDid>#<vm>` verifies again. The rejection covers any
  shape whose invoker resolves out of a Space the walk deletes, which
  is why the delegatee is a bare did:key.
- **Re-pointing the auxiliary Space's controller, or a delegated
  bare-URL PUT.** Both need the controller-rewrite capability the
  items-subtree exclusion exists to withhold from the ladder.
- **Orphaning the auxiliary Space, the keystore, and the sibling
  unlock Spaces to a server GC.** Rejected by the product requirement.
  No such GC exists, a did:key-controlled unlock Space never stops
  resolving so no controller-liveness sweep could reap it, and the
  residue is the existence oracle the design exists to remove.
- **Refusing the whole deletion when a sibling's management zcap has
  lapsed.** An unspent recovery code older than a year would make the
  account permanently undeletable. The lapsed sibling is reported as a
  named residue instead, and the backstop (the credential's own next
  use) is its mender.

## Consequences

- Every ladder VM the account document lists can destroy the account,
  because DELETE is inside what it may delegate. That trade is
  accepted and bounded: the population is the ladder VMs rather than
  every `capabilityDelegation` member on the deployment, and the
  retirement gate (wallet-core's record) closes the retired-credential
  population. On a client-less account the standing VMs are bounded
  only by their credentials' entropy.
- The capabilities are grant authority exercised with no log entry, so
  `decisions/0002` (loudness) carries an amendment with this stated
  scope; a deletion destroys the log any record would live in.
- The ceremony waits on the server clause predicate landing, and the
  container rule's enforcement pass must carry the two exceptions or
  every Space DELETE the ceremony sends is refused.
- A DELETE-only capability on a bare Space URL still prefix-covers
  DELETE of the Space's contents for its ten minutes; it cannot reach
  the Space Description PUT, the controller-rewrite escalation.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A ceremony other than deletion needs the ladder VM to reach an
   unsafe container method. Extend the clause with a new enumerated
   target-and-verb shape; never with a root-invoker rule.
2. The clause predicate or the container rule's exceptions change
   upstream (app-connect-spec `decisions/0003`, the WAS authorization
   profile) in a way that removes the admission this mechanism rides.
