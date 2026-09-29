# 0031: An encounter site counts by its declared reach

- Status: accepted
- Date: 2026-09-28
- Driving work: the design that moves menders from login-scheduled
  sweeps toward resolve-on-read. It adds a mender trigger for sites that
  converge a violated invariant where an ordinary read or write meets
  it. Extracted at that design's approval.
- Affects: `@interop/wallet-core/menders` (the `encounter` trigger value,
  the `RegistrationSite` encounter arm, `transientReachableInvariants`,
  and `menderRegistry`'s construction checks); freewallet
  (`src/session/menders/`); dcw, whose registry adopts the same types.

## Context

The mender registry derives its gap list from reach. An invariant is a
gap when no converger a transient visit can fire reports it. For the two
login chains, reach is read through the held-authority set. A
`login-routing` site counts unless the client-key-record probe guards
it.

An encounter site runs inside a live session, on whatever page renders
the read that meets the violation. Two facts decide whether a transient
visit reaches it: whether a transient session renders that page, and
whether it holds the authority the converger needs. The two differ in
practice. One call can converge an invariant that only a transient
session reaches beside one that both kinds reach. A page a transient
session never renders can carry a claim a transient session would
satisfy.

wallet-core 0.84.0 shipped the trigger as `read-path` with an
unconditional rule: every such site counted as transient-reachable.
0.85.0 renamed it `encounter` with the rule unchanged. No consumer
declared a site under it before this decision.

## Decision

The trigger value is `encounter`. Every encounter site declares
`reachedBy`, the session kinds that render its read (`'remembered'`,
`'transient'`). One site carries one `reachedBy`. A call converging two
invariants with different reach is declared as two sites.

`transientReachableInvariants` counts an encounter site only when both
hold:

- `reachedBy` includes `'transient'`;
- `heldAuthorities({ kind: 'ladder' })` includes the reported
  declaration's `authority`.

The types enforce the member. `RegistrationSite`'s general arm excludes
`encounter`, so a site without `reachedBy` does not type-check.
`menderRegistry` construction throws a `TypeError` for an encounter site
with no `reachedBy`, and for a declaration listing `encounter` in its
`triggers` with no site reporting it.

## Rejected Alternatives

- **Count every encounter site unconditionally**, as 0.84.0 shipped. A
  site on a page only a remembered session renders would count as
  transient-reachable, and a real gap would leave the gap list. The gap
  list exists to catch that case.
- **Derive reach from the declaration's authority alone**, with no new
  member. Authority says whether a transient session could converge the
  state. It does not say whether a transient session ever renders the
  page, so the same hidden gap follows.
- **Keep `read-path` beside a new `encounter` value.** Two triggers
  would name one idea, and the unconditional rule would stay in the
  vocabulary.

## Consequences

- Each encounter site's author states a fact about the call site, and
  nothing checks it against the page. A wrong `reachedBy` produces a
  wrong gap list. Review of each site is the check.
- The rule trusts each declaration's `authority`. A declaration whose
  claimed authority is wider than what converges it on a transient
  session makes any transient encounter site on it count wrongly. Such
  a declaration is corrected before a site is added on it.
- Renaming `read-path` was a breaking change in `@interop/wallet-core`
  0.85.0. The reach rule and `reachedBy` are a second breaking change,
  in the release that carries the registry changes.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The registry gains a way to observe which session kinds render a
   site, such as a route table the derivation can read. `reachedBy`
   then becomes derivable and the member can go.
2. A third session kind appears (the guest and no-WAS sessions resolve
   no account-ceremony kind today). `reachedBy`'s vocabulary then needs
   the new value before any site claims it.
