# 0019: No deliberateness gate on Space export or import from a transient session

- Status: accepted
- Date: 2026-09-03
- Driving work: the browser wallet's design for running the
  account-management ceremonies from a credential-only transient
  session. Extracted at that design's approval, from its export and
  import section and its rejected alternatives.
- Affects: freewallet (`src/stores/wasRemoteStore.ts`'s export and
  import calls, the Storage page's two buttons, the deleted session-kind
  refusal), was-teaching-server (the client-annex clause, relied on
  unchanged), app-connect-spec `decisions/0003` (that clause's admission
  predicates, relied on unchanged).

## Context

The default session is transient. It holds no key the account document
lists under `capabilityInvocation`, and every request it makes is
invoked by the annex VM under the generation delegation. Both Storage
buttons, Space export and Space import, refused on that session kind.

An earlier public-computer design had proposed a deliberateness gate for
export. The idea was to make a bulk read of a whole Space cost something
visible. A confirm step, or a loud log entry standing in for one, would
have been the gate. This record settles whether either operation needs
one now that the session-kind refusal is deleted.

## Decision

Neither Space export nor Space import carries a deliberateness gate from
a transient session. No confirm step, no loud enroll entry, no
session-kind refusal. The existing gate is deleted and nothing replaces
it. Do not reopen.

Export is one POST to the Space's export path, made through the bound
generation delegation. The server's client-annex clause admits it under
the first predicate, which covers any path under the Space's items
subtree. The request touches nothing. The transient login's own annex
entry already precedes every read that delegation admits.
`decisions/0002`'s 2026-08-28 amendment already records that the annex
append is not a per-read backstop. A confirm step the user did not ask
for is no control against a session-stealer who can click it.

Import is one POST to the Space's import path. The server's import plan
writes the Space-level access policy, every collection description with
its encryption descriptor, the collection and resource policies,
arbitrary resources, and Space-scoped revocation records, all
create-if-absent. The design review first read that as a controller-tier
write admitted by a string-prefix accident. It is not. The first
predicate admits any path under the Space URL with any WAS verb. It
excludes only the bare-Space-URL operations, which are the Space
Description PUT that rewrites the controller and the Space DELETE, plus
keystores. A transient session can therefore already make every write
import bundles, one request at a time, under the same generation
delegation. Import is a batch of admitted writes and adds no reach. The
bound that matters is the bare-Space-URL exclusion, and import does not
cross it.

## Rejected Alternatives

- **The step-up ceremony's entries as a loudness gate for a bulk read.**
  The earlier public-computer design's export row. It buys a
  world-readable record of an act whose reads the annex entry already
  precedes, at the cost of two permanent account-log entries. It also
  constrains the honest owner rather than a credential thief, who can
  self-enroll and export from an enrolled client instead.
- **Excluding the import route server-side.** A regression against the
  goal the whole design serves, which is that a transient session
  performs every ceremony. It would also carve one route out of a
  predicate that admits the same writes piecewise, so the exclusion
  would state a bound the clause does not otherwise hold.
- **A wallet-only import gate.** A confirm step or a session-kind
  refusal in the wallet's own UI is a control any was-client caller
  bypasses, since the capability the session already holds admits the
  request directly.

## Consequences

- No server change and no spec change. The clause's predicates, the
  export route, and the import route are unchanged.
- The silent-write trade is the clause's stated one. A transient
  visit's annex entry says a per-visit key exists and may act inside
  the items subtree. It does not say what that key later reads or
  writes there, and export and import are two more instances of that
  standing trade rather than a new one.
- A session-stealer at an unlocked terminal can export the whole Space
  or import a bundle into it with nothing in any log naming the act.
  That is accepted, on the reasoning above, and bounded by the same
  remedy the rest of the credential-anchored design names, which is
  credential rotation.
- The Storage buttons render and work on both session kinds, so no copy
  explains a refusal that no longer exists.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A per-read audit record becomes available, so that a bulk read could
   be logged rather than gated. The server's event channel is the
   candidate. Logging is the change to make then; a confirm step is
   not.
2. The client-annex clause's first predicate changes what it admits, in
   particular the bare-Space-URL exclusion that bounds import today.
