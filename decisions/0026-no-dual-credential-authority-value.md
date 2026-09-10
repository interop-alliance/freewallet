# 0026: No `dual-credential` authority value

- Status: accepted
- Date: 2026-09-09
- Driving work: the design for a shared mender registry -- the table of
  invariants that must hold between ceremonies, plus the code that
  converges a violated one. Each declaration names the authority its
  converger needs, and this record settles that value set.
- Affects: `@interop/wallet-core` (the registry module the design places
  there, and its `AUTHORITIES` union); freewallet
  (`src/session/accountCeremonyContext.ts`, which resolves the kind, and
  the recovery re-run entered from `/recover`); dcw, whose one
  registration declares `enrolled`.

## Context

A registry declaration names the authority its converger needs. The
authority axis is the account-ceremony context, which resolves one of
two kinds. Under the enrolled kind this client's did:webvh update keys
sign, and every request root-invokes. Under the ladder kind a rung of
the credential's ladder signs through the record's bridge delegation.

One entry looked like it needed two credentials at once. The recovery
re-run at `/recover` holds a spent recovery code plus the successor
passphrase. A fifth authority value was drafted for it.

The approach that value existed for is rejected twice in this repo.
`decisions/0013-no-step-up-ceremony-as-annex-mender.md` rejected it for
the annex mender, and
`decisions/0020-no-step-up-ceremony-for-account-ceremonies.md` rejected
it for the class of account ceremonies. The step-up work item it came
from was dropped on 2026-09-03, superseded by the credential-anchored
ceremony branches.

## Decision

The authority union is exactly four values, and no more:

- `none` -- no account authority. Local cleanup, reads, and writes the
  visit's own generation delegation already covers.
- `account` -- either kind converges it, possibly by different code
  under each.
- `enrolled` -- only the enrolled kind converges it.
- `ladder` -- only the ladder kind converges it.

A declaration names one of them. Singular, because a converger that
needed two authorities at once would be the step-up this repo has
rejected twice.

The recovery re-run declares `ladder`. A recovery code is itself a
standing credential with a ladder of its own (wallet-core
`decisions/0020-recovery-code-is-a-standing-credential-with-a-ladder.md`),
so the converging authority is a ladder kind. The successor passphrase
supplies key material rather than authority.

Do not reopen.

## Rejected Alternatives

- **A `dual-credential` value for the recovery re-run.** One entry does
  not carry a fifth value that every other declaration then has to be
  read against. The modelling was also wrong: the second credential
  contributes material to the run, and the signing authority is the
  spent code's ladder.
- **Declaring a set of authorities per entry instead of one.** The four
  shared registry passes are the pressure for it, since either kind
  converges them. A set is what makes a step-up look reasonable, because
  an entry naming two authorities reads as an entry that may acquire the
  second one. The `account` value carries those passes instead, which is
  why it is in the union.

## Consequences

- A converger that must hold two independently derived signing
  authorities at once cannot be declared. Proposing one is a design
  question before it is a type change.
- The recovery re-run's report says `ladder`, which understates that the
  visit typed two credentials. A reader wanting that fact goes to the
  recovery topic doc.
- The `account` value is a judgment call recorded as such. It says
  "either kind" rather than naming a key, so a reader cannot tell from
  the declaration alone which code path ran.
- The four values are code-only. Persisting one anywhere is a separate
  decision.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A converger appears that must hold two independently derived signing
   authorities at once, and the proposal states what a user holding only
   one of them does. A proposal without that answer is not a reopening,
   which is the same bar `decisions/0020` sets.
2. The account-ceremony context grows a third kind. The union then needs
   a value for it, and this record is re-read rather than extended in
   passing.
