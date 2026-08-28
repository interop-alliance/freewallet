# 0010: A remembered login is not a mender trigger

- Status: accepted
- Date: 2026-08-27
- Driving work: the 2026-08-27 framing audit run after the default
  transient session landed (FW-203, FW-265, FW-316). It found the same
  argument in several gated designs: a residue is left unmended because
  "the next login" or "some login" will finish it.
- Affects: freewallet's design gate, the tear-mending taxonomy in
  ARCHITECTURE.md's Glossary, and every gated design that states a
  residue. Re-derivation was owed by FW-354, FW-290, FW-177, FW-356,
  FW-343, and FW-218, whose mender arguments were written under the old
  reading; FW-364 discharged all six on 2026-08-27. No wire contract.
- Title: renamed 2026-08-28 from `durable login` to `remembered login`,
  with every citation updated in the same pass. The record number is the
  stable identity; the wording now reads on the settled axes of
  `decisions/0011-durable-names-server-storage-only.md`.

## Context

The transient, credential-anchored session is the default entry on a
non-remembered browser, and the credential-anchored establishment is
every WAS signup. The account shape that produces is client-less and
ladder-anchored. Remembering a browser is a deliberate opt-in, not a
stage an account passes through.

The repo's standing sweeps all live on one promise chain,
`session.registryReady`: the cascade-completion sweep, the re-seal
repair, the torn-retirement repair, the bare-passkey rebuild, the
registry backfill, the standing-delegation and ladder-rung refreshes,
the pointer heal, and the annex GC sweep. That chain is built only by a
remembered login. A transient login has two standing passes of its own:
the generation-readiness stage every visit runs, and the mend entry
point its heal branch runs.

So "the next login mends it" carries two different meanings. On a
remembered browser it is a real bound, roughly one session away. On the
default account it is not a bound: the remembered-login chain may never
run once in the account's life, and the residue is permanent. The same
slippage priced hazards as low severity ("the window is one login
cycle", "self-healing") when the window does not close.

## Decision

A mender whose only trigger is a remembered login does not count as a
mender.

A gated design names the trigger for each residue it leaves, and that
trigger must be one a credential-only visit can fire:

- a converging re-run of the ceremony, from the entry a user reaches it
  by;
- a pass on the transient login's own path (today the
  generation-readiness stage, or the mend entry point);
- a repair waiting at an entry the credential alone reaches.

A residue whose only trigger is the remembered-login chain is an open
gap. It is recorded as one in the design and in ARCHITECTURE.md's
Ceremony inventory, and it gets its own work item. It is not coverage.

Two consequences for prose follow. A sweep on `registryReady` is called
a remembered-login sweep wherever it is offered as a mender. And a
severity argument may not rest on a remembered login recurring.

The rule does not require every mender to be duplicated on the
transient path. It requires the remembered-login-only ones to be
counted as gaps.

Scope. The rule bites where the torn state can stand on an account with
no enrolled client, or where a transient visit can reach the ceremony
that leaves it. A ceremony only a remembered session can run (the
Settings ceremonies, client revocation, update-key rotation) may name a
remembered-login trigger as its mender, because the account holding
that torn state holds an enrolled client by construction. State which
case applies rather than leaving it to the reader.

## Rejected Alternatives

- Keep the remembered login as a mender and note the client-less
  account as a per-design exception. This is what the audited docs did.
  The exception is the majority case, so the reading inverts: the stated
  bound holds for the minority and fails silently for everyone else.
- Require a transient trigger for every mender before a gated item may
  land. Too strong. Some menders need authority a transient visit does
  not hold (an update key, a step-up ceremony's subject), and the rule
  would block work whose remembered-login-only mender is honest and
  stated as a gap.
- Skip the rule and solve it once with a general transient-login mender
  chain (FW-320). Worth building, but not a substitute. The rule is
  what makes each design state its trigger, it applies while that item
  is unbuilt, and it is the input that tells the item which passes need
  generalizing.

## Consequences

- A gated design's mender enumeration gains a statement per residue:
  which session types fire this.
- Standing arguments in existing designs become invalid and are
  re-derived: FW-354's un-awaited second phase and its "each
  credential's own next remembered login mends it"; FW-290's "a transient
  session skips the governed login-time sweeps" invariant and its gap
  classes; FW-177's annex GC, orphan discovery, and generation cleanup,
  all triggered at "the first remembered login"; FW-356's mender for a
  VM-less standing credential; FW-343's "self-healing" bridge; FW-218's
  cost bound. DONE 2026-08-27 (FW-364, archived): all six passed, two
  residues were promoted into ARCHITECTURE.md's open-gaps paragraph,
  FW-365 was filed for the annex-GC growth the pass measured, and
  FW-343's severity moved to `high` while FW-218's premise was checked
  and did not hold.
- ARCHITECTURE.md's Ceremony inventory open-gaps paragraph grows as
  remembered-login-only menders are reclassified.
- Some items get more severe, because a bound they claimed does not
  exist on the default account shape.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The transient login gains a standing pass with the remembered-login
   chain's reach (FW-320's generalization). "Remembered login" and "any
   login" then name the same trigger for the passes it covers, and the
   rule narrows to whatever stays remembered-login-only.
2. Remembering a browser becomes the default entry again, or
   measurement shows most accounts run a remembered login often enough
   for it to be a real bound.
