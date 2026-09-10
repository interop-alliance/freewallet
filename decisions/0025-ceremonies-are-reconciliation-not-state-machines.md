# 0025: Ceremonies are reconciliation, not state machines

- Status: accepted
- Date: 2026-09-09
- Driving work: the design for a shared mender registry -- the table of
  invariants that must hold between ceremonies, plus the code that
  converges a violated one. The framing question came up when that
  design was re-keyed from ceremony ids to invariants.
- Affects: `@interop/wallet-core` (the registry module the design places
  there, and the ceremony bodies its ARCHITECTURE.md describes);
  freewallet (`src/session/initSession.ts`'s login chain and
  `src/session/registryPasses.ts`, whose stages are convergers); dcw
  (its one registration, a converging sweep).

## Context

A registry of menders invites the finite-state-machine reading: a
ceremony is a machine, a torn run stopped at some state, and a mender
advances it from there. That reading does not describe this codebase.

wallet-core's ARCHITECTURE.md states the model. Every stage detects its
own completion from durable state, and there are no checkpoint resources
anywhere. wallet-core
`decisions/0010-post-pivot-derivability-rule.md` states the other half:
past a ceremony's pivot, every write is re-derivable from the pivot
entry plus durable state, so any authorized party can roll it forward.

A machine needs a remembered position. The only durable position here is
the log.

## Decision

A ceremony is not modelled as a machine whose position a mender
advances. A mender re-derives what must hold and converges it. Registry
entries therefore name predicates over stored state rather than states
of a run, which is what `decisions/0024` records as the key.

Do not reopen. This is the same door wallet-core
`decisions/0011-establish-mend-entry-point-split.md` closed, and
`decisions/0023-no-saga-engine-in-the-mender-registry.md` keeps closed
on the execution side.

## Rejected Alternatives

- **The finite-state-machine framing**, with a per-ceremony state
  enumeration and menders as transitions. It needs a remembered
  position, and nothing remembers one. Reconstructing the position from
  the log would produce a value already sufficient to converge directly,
  so the machine buys nothing.
- **Recording a ceremony's position in a resource, so a mender could
  resume it.** It contradicts the derivability rule, adds a permanent
  wire artifact, and puts a second source of truth beside the log. A
  stale or forged position record would then decide what a mender does.

## Consequences

- Every mender must detect its own work from durable state alone. A
  converger that cannot is a design defect, rather than evidence that a
  checkpoint is missing.
- Convergence is the correctness property, so two visits converging at
  once are handled by the compare-and-swap at each write rather than by
  a remembered run position.
- Diagnostics lose a question. Nobody can ask how far a torn run got.
  The answer comes from reading the log and the predicates, which is
  more work than reading a status field would be.
- The registry cannot report progress through a ceremony. It reports
  which predicates hold, which is a different and smaller claim.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A ceremony gains a stage whose completion cannot be detected from
   durable state, and no re-derivation of it exists. wallet-core
   `decisions/0010` then moves first, and the checkpoint's wire shape is
   its own gated decision rather than a detail of this one.
