# 0009: A popup denied Storage Access falls back to the transient session

- Status: accepted
- Date: 2026-08-26
- Driving work: FW-203 (the popup and CHAPI transient session). The
  popup follows the browser's ratchet state -- remembered reaches the
  durable client through the Storage Access API -- and the open case
  was a remembered browser whose popup cannot actually reach the
  first-party client-key record.
- Affects: freewallet's CHAPI popup pages and their session routing.
  No wire contract; the response shapes involved are already fixed by
  app-connect-spec's decision 0004 (transient DIDAuth uses the bare
  did:key) and freewallet's decision 0003 (per-visit membership lives
  in the annex).

## Context

The CHAPI popup runs in a partitioned third-party iframe under the
mediator origin, so it cannot see the top-level origin's IndexedDB,
where the durable client-key record lives. The only bridge is the
Storage Access API, and the extended `types` argument that can hand an
iframe unpartitioned IndexedDB is Chromium-only. The classic form
unpartitions cookies alone. So "denied" means two different things by
engine: on Chromium it is an actual user or policy refusal of a
request the engine supports; on Safari and Firefox it is the permanent
steady state of every remembered popup, because no request for
unpartitioned IndexedDB exists to grant.

## Decision

A remembered browser whose popup cannot reach the durable client-key
record -- Storage Access denied, or the engine offering no
unpartitioned-IndexedDB request at all -- falls back to the transient
session, exactly as a non-remembered browser routes. One uniform
fallback covers every engine; no per-engine refusal arm exists.

The cost accepted with it: such popup visits enroll a per-visit
transient key into the client annex even though a durable client
stands on the same browser. That is judged acceptable because the
overlap is expected to be rare (a browser that is a remembered
freewallet client AND logs into was-react apps through the popup), and
because the entries land in the generation-GC'd annex log rather than
the permanent account log (decision 0003), so the litter is bounded
and collected.

## Rejected Alternatives

- Refuse with copy pointing at the main app (open the wallet in a
  top-level tab). Clean identity story, but on Safari and Firefox it
  disables the CHAPI popup for every remembered user -- the dominant
  engines' steady state would be a refusal screen.
- A per-engine split: transient fallback on Safari and Firefox, but a
  refusal on Chromium, where a denial is a genuine exception. Rejected
  as complexity without a beneficiary; the transient session serves
  the Chromium-denial visitor just as well, and one code path is
  easier to test and to state in consent copy.

## Consequences

- On Safari and Firefox, a remembered browser's popup visits routinely
  run transient sessions; the durable client sits unused in the popup
  context. The App Connect response's holder on those visits is the
  visit's bare did:key, not the durable client's key (the shape
  decision 0004 already fixes for transient sessions).
- Per-visit annex enrollments accrue from popup logins on such
  browsers, bounded by the annex generation GC cycle.
- The transient fallback requires the account to satisfy the transient
  composition's preconditions (a standing unlock credential, a
  reachable generation or sibling delegation); where those refuse, the
  popup surfaces the transient refusal copy rather than a durable
  login.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. Safari or Firefox ship an unpartitioned-IndexedDB grant (the
   extended `types` argument or an equivalent), making "denied" an
   exceptional event on every engine rather than a steady state.
2. Measurement shows the remembered-browser popup overlap is common
   enough that the annex churn or the transient path's latency is a
   real cost.
