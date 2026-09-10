# 0022: Registration order is the mender registry's ordering

- Status: accepted
- Date: 2026-09-09
- Driving work: the design for a shared mender registry -- the table of
  invariants that must hold between ceremonies, plus the code that
  converges a violated one. Extracted at that design's approval, from
  its rejected alternatives.
- Affects: `@interop/wallet-core` (the registry module the design places
  there: the `Registration` type and the `dueAt` reader); freewallet
  (`src/session/initSession.ts`'s login chain and
  `src/session/registryPasses.ts`'s shared bundle, which become
  registrations); dcw (its one registration on the sync start path).

## Context

The remembered login chain runs about ten stages in a fixed order. That
order is load-bearing. At least six cross-entry constraints ride it:

- the sweep seed runs first;
- the re-seal runs ahead of the rest of the shared bundle;
- the torn-retirement repair runs before the ladder-rung refresh, which
  is wallet-core `decisions/0017`'s torn-retirement-first rule;
- the registry backfill runs after the identity repairs;
- the manage-zcap refresh runs last;
- the pointer heal precedes the two refreshes that early-return while
  the account pointer is not yet a did:webvh.

Six constraints are still one total order, and one unit test already
pins it.

Some stages also hand values to the stages behind them. The roster
converger returns the user key and the descriptor the collection cascade
needs. The shared bundle's re-seal consumes a roster read produced by
the chain seed.

## Decision

Registration order is execution order. The registry is the declaration
table plus one registration list per chain trigger.
`dueAt({ held, trigger })` returns that trigger's registrations in list
order. There is no dependency graph, no before/after edge, and no
priority number.

A value that travels between invariants travels inside one registration.
The three many-to-one clusters in the remembered chain each become one
registration reporting several entries, and `converge` returns one
report entry per id in `reports`, in that order. No carry-forward member
is added to the declaration. dcw's single registration takes the same
shape.

Do not reopen except under the criteria below.

## Rejected Alternatives

- **Per-entry before/after edges, or priority numbers.** The constraint
  list is small and already resolves to one total order. A graph adds
  cycle handling and hides the order behind a resolution step, and the
  order pin would assert the resolved order anyway. The cost lands on
  every reader of the list to buy flexibility nothing asks for.
- **A typed carry-forward member on the declaration.** It is a data
  channel between entries, and the no-dependency-graph rule would go
  with it. One registration reporting several entries carries the same
  values with no new member.
- **Splitting each cluster into registrations that re-read what they
  need.** Extra host reads on the login path, for values the preceding
  stage returned. It also duplicates the read discipline that decides
  when a roster read counts.

## Consequences

- Nine registrations cover the thirteen chain-triggered invariants. A
  report reader sees several entries from one call, and the sub-steps
  inside a cluster are not separately schedulable.
- One total order has to serve both wallets. A wallet whose ordering
  must differ cannot be expressed at all.
- When a cluster's `converge` throws, the runner warns for every id in
  `reports` and continues. The unconverged members of that cluster are
  reported through the warn path rather than converged.
- The roster read that travels from the chain seed into the shared
  bundle stays a fact about how the chain is built. It is invisible in
  the declaration table, so a reader of the table alone does not see it.
- One relation between entries is a suppression rather than an ordering:
  the credential-anchored mend arms suppress the document-inventory
  entry. The list does not express it, and it stays a prose rule.
- The order pin test is the enforcement. Adding a registration without
  extending that test loses the guarantee silently.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A wallet needs two entries whose relative order must differ from
   another wallet's. The registry has then outgrown a single total
   order, and per-wallet lists are the first thing to try before any
   graph.
2. A registration's position has to be decided at runtime from account
   state rather than at declaration time. An order that varies per
   session is not a list.
