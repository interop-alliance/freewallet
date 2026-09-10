# 0024: The mender registry is keyed by invariant

- Status: accepted
- Date: 2026-09-09
- Driving work: the design for a shared mender registry -- the table of
  invariants that must hold between ceremonies, plus the code that
  converges a violated one. An earlier draft of that design keyed the
  table by ceremony id, and the re-key is what this record settles.
- Affects: `@interop/wallet-core` (the registry module the design places
  there: `InvariantId`, `InvariantDeclaration`, `Registration`, and the
  report types); freewallet (the invariant table, and the convergers in
  `src/session/initSession.ts`'s login chain and
  `src/session/registryPasses.ts`); dcw (three declarations plus one
  registration).

## Context

The first draft keyed the registry by ceremony id, on the reading that a
mender finishes a torn ceremony. The table it produced does not support
that reading. Eight of its twenty rows carried no ceremony at all. One
row carried four. The shared four-pass bundle in
`src/session/registryPasses.ts` runs on both login compositions
regardless of which ceremony tore. The key would have been absent,
ambiguous, or irrelevant for more than half the table.

What a mender does is make a statement about stored state true again.
The roster sweep makes "the current epoch wraps to exactly the
document's key set" true. The re-seal repair makes "the registry entry
opens under the current user key" true. Which ceremony tore is a
diagnosis of the violation rather than the thing being fixed.

There is a rot argument too. The previous draft keyed rows by code
location, and half of its line citations were wrong twelve days later.

## Decision

The registry's unit is an invariant: a predicate over the account's
server-held state, or for a few entries over this browser's local state,
that must hold between ceremonies. A ceremony may violate it while it
runs. Once no ceremony is running, a violation is a torn state, and
converging it is mending.

`InvariantId` is the key. It is a closed union of stable kebab-case ids,
code-only under the design's public-surface rule. The ceremony ids whose
torn runs can violate the predicate are a `ceremonies` attribute on the
declaration, and that attribute may be empty. Several invariants are
violated by ordinary drift, such as an expiring delegation, rather than
by any ceremony.

The ceremony view is the transpose of the table, read off the
`ceremonies` attribute. A consumer that wants per-ceremony grouping
filters the report by that attribute.

Do not reopen.

## Rejected Alternatives

- **Keying by `CeremonyId`.** Rejected on the evidence above: absent for
  eight rows of twenty, ambiguous for the row naming four ceremonies,
  and irrelevant for the shared bundle. Several convergers mend no
  single ceremony, and one torn ceremony run can violate several
  invariants at once, so a ceremony-keyed map represents neither side
  without invention.
- **One report keyed by `CeremonyId` alone**, the literal reading of the
  acceptance criterion. A filter over the invariant-keyed report
  satisfies that criterion without making the key carry a value most
  rows do not have.
- **Keying by code location, the module and symbol that mends.** It rots
  fastest of the three. Moving a converger between modules would rename
  the key, and the previous draft's citation decay is the measurement.

## Consequences

- Renaming a converger, or moving it between modules, renames nothing.
  The id names the predicate.
- The id set is a closed union, so adding an invariant is a type change
  both wallets compile against. That is the point, and it is also
  friction for a wallet that wants a private entry.
- The ids stay code-only. Writing one into a stored record, a log entry,
  or any wire payload is a separate decision, not licensed here.
- The ceremony view is a design goal rather than a fact today. It is
  hand-written, and the approval review found it disagreeing with the
  `ceremonies` cells it claims to transpose. It can drift until it is
  generated.
- A reader who starts from a ceremony pays one indirection to reach the
  predicates its torn run can violate.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A report consumer appears that must group by ceremony and cannot do
   it by filtering the `ceremonies` attribute.
