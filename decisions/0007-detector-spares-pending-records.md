# 0007: The forgotten-browser detector spares pending records

- Status: accepted
- Date: 2026-08-24
- Driving work: the FW-317 / FW-280 design pass
  (`_spec/designs/FW-317-successor-persist-before-publish.md`).
- Affects: freewallet (`src/session/forget.ts`'s
  `assertClientStillEnrolled`, `src/session/initSession.ts`'s login
  routing); dcw when its counterpart adopts the pending shape.

## Context

The persist-before-publish reorder (decision 0006) creates a
deliberate torn state: a client-key record persisted before the add
entry, for a client the account document does not list yet. The
forgotten-browser detector's shipped contract -- any client-key record
present while the cleanly verified document does not list the client
finishes the wipe as "access removed" -- would destroy that record,
the only holder of the resume's key set.

## Decision

The detector's trigger narrows to ENROLLED-shape records (the shared
four-member test: `userKey`, `webvhUpdateKeys`, `controller`,
`pointerDid` all present). A pending-shape record (`userKey` absent)
routes to the resume instead. Extending the wipe to pending records is
rejected as do-not-reopen: the detector exists to finish a removal the
document ATTESTS, and a pending record whose verification method was
never published attests the opposite.

Two carve-outs are part of the decision, not exceptions to it:

- A pending record whose VM the verified log history shows
  published-then-removed IS the removal case; the resume hands exactly
  that branch back to the detector's wipe. Without it, a seeded
  re-run would silently reverse a deliberate revocation.
- The resume's own discard of a provably worthless pending record (no
  standing authority on the credential, or the account already lists
  a different client bound under it) is not this rejection's subject:
  it runs only on verified inputs, only as the last branch, and it is
  what keeps such a browser from wedging (durable refused, transient
  unreachable).

## Rejected Alternatives

- Wipe pending records in the detector too. Rejected as
  do-not-reopen: the wipe converts a mendable tear back into a
  re-mint -- for self-enrollment that recreates the phantom-client
  class the reorder removes, and for the spend it destroys a
  successor credential's local half.

## Consequences

- Login routing is three-way (enrolled -> detector + ordinary login;
  pending -> resume; absent -> self-enroll gate), and the pending arm
  is fail-closed: a pending record never reaches ordinary session
  construction outside the resume, because downstream construction is
  fail-open for a userKey-less record.
- Every resume branch is decided from the verified log history; a
  transport failure or continuity refusal surfaces the existing
  storage-unreachable state and touches nothing -- the wipe and the
  discard are reachable only from verified inputs.
- One accepted residue: a freewallet build predating the narrowing (a
  stale tab, a rolled-back deploy, an older CHAPI popup document)
  still runs the un-narrowed detector against a pending record. Old
  code cannot be taught the carve-out; bounded by deploy hygiene.

## Revisit Criteria

None while the resume and its published-then-removed branch exist. If
the resume is ever removed, the detector's trigger must be revisited
in the same change.
