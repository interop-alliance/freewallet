# 0023: The mender registry does not run ceremony stages

- Status: accepted
- Date: 2026-09-09
- Driving work: the design for a shared mender registry -- the table of
  invariants that must hold between ceremonies, plus the code that
  converges a violated one. Extracted at that design's approval, from
  its rejected alternatives.
- Affects: `@interop/wallet-core` (the registry module the design places
  there, and the ceremony bodies it describes rather than drives);
  freewallet (`src/session/initSession.ts`'s login chain and
  `src/session/registryPasses.ts`); dcw, whose one registration adopts
  the same runner.

## Context

A registry that knows every mender is one step away from being asked to
run every ceremony. The pivot audit checked that step and found the saga
pattern does not transfer. The server holds no locks, and loudness makes
a log append irreversible, so two-phase commit and compensation are both
unavailable here.

wallet-core `decisions/0011-establish-mend-entry-point-split.md` already
closed the same door for the ceremony with the richest tear taxonomy. It
split establishment from mending into two named entry points rather than
one mode-forked orchestrator.

## Decision

The registry never executes a ceremony's stages. Ceremonies stay
explicit sequenced code in wallet-core and in the wallet. The registry
describes them from outside: which invariants a torn run can violate,
where the predicate is checked, which authority converges it, and what
the run reported.

Two limits follow directly. The credential-anchored heal arms register
as invariants whose convergers delegate to wallet-core's mend entry
point, rather than rebuilding an arm here. A ceremony-tail entry carries
no registration at all, so no caller can fire the revocation's re-mint
or the rotation's annex retirement outside the cascade order.

Do not reopen.

## Rejected Alternatives

- **A generic saga engine driving stages, with compensating actions.**
  Compensation needs reversible steps, and an append to a world-readable
  log is not reversible. The pattern needs a remembered position as
  well, which nothing here holds.
- **Building the credential-anchored heal arms inside the registry.**
  That is a second seam beside the entry point wallet-core
  `decisions/0011` owns, and it is the parallel copy that split exists
  to prevent.
- **Pulling the ceremony-tail work into the runner**, so the
  revocation's re-mint and the rotation's annex retirement run in one
  place. Their position inside the sequenced code is load-bearing; the
  cascade's dependency order rests on it. The registry takes their
  report only.

## Consequences

- The registry's value is reporting, coverage, and audit. Declaring an
  invariant makes nothing run. A wallet still writes the converger and
  registers it.
- Each ceremony keeps its own stage order and its own tear story. There
  is no central place that describes cross-stage ordering, and the six
  cross-entry constraints in the login chain stay in registration order
  (`decisions/0022`).
- A caller asking `dueAt` for the ceremony-tail trigger gets back
  nothing it can fire. That is deliberate, and it costs the reader one
  lookup to learn why the list is empty.
- Downstream code may rely on this: a ceremony stage runs only from that
  ceremony's own body.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A ceremony gains a durable record of its own position, so a runner
   could resume it where it stopped rather than converge it. That
   contradicts wallet-core
   `decisions/0010-post-pivot-derivability-rule.md`, so that record
   moves first, and the checkpoint's wire shape is its own gated
   decision.
2. Two wallets ship divergent stage orders for one shared ceremony, and
   the divergence traces to the sequenced code rather than to the
   parameters a branch supplies. The answer is then one shared ceremony
   body, not a runner that orders stages.
