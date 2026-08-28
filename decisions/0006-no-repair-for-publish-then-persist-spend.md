# 0006: The remembered spend reorders; no repair substitutes for the persist

- Status: accepted
- Date: 2026-08-24
- Driving work: the FW-317 / FW-280 design pass
  (`_spec/designs/FW-317-successor-persist-before-publish.md`), over
  findings F1 and F3 of `_spec/pivot-placement-audit.md`.
- Affects: freewallet (`src/session/recovery.ts`, the remembered
  spend's tail), `@interop/wallet-core` (`recovery/recoveryWebvh.ts`
  gains the required `onCommitted` hook); dcw inherits the pattern with
  its counterpart item.

## Context

The remembered recovery spend published its add-and-retire entry (the
pivot: the spent code's inventory leaves the document) while the new
client's seeds and the replacement code's record existed only in tab
memory. On the typical recovery account (no other enrolled client) a
tab death in that window bricked the account: the re-typed code
refuses as spent, the replacement code locates nothing, and the
document's only client is a phantom. The window spanned the whole
collection cascade, the longest network stage in the system, on the
flow whose purpose is regaining the account.

## Decision

The ceremony is reordered onto the transient recovery's
persist-before-publish seam: a required hook, fired after the
reveal-and-commit entry and before the add-and-retire entry, durably
persists every successor artifact whose only holder would otherwise be
tab memory once the pivot lands. The alternative -- keeping
publish-then-persist and building a repair for the stranded state --
is rejected as do-not-reopen.

## Rejected Alternatives

- Keep publish-then-persist and build a repair for the stranded state.
  Rejected as do-not-reopen: past the pivot the successor seeds exist
  only in tab memory, and a repair by definition works from durable
  state alone -- it cannot re-derive what was never written, so the
  "repair" is account loss plus support copy. This rejects repair as
  the whole answer only; narrower post-persist repairs over
  re-derivable state (the design's resume, the login sweep) are the
  ordinary tear-mending toolkit and unaffected.
- Move the roster escrows or the mandatory rotation pre-entry.
  Structurally impossible: they are HTTP invocations signed as the new
  client's verification method, which the current-key-set rule refuses
  until the entry publishes it; signing them with the spent code's
  authority instead would widen the code's bridge beyond
  PUT-on-`did.jsonl`, breaking the narrow-bridge loudness bound. The
  consequence -- the pivot-to-first-escrow band -- is closed instead
  by persisting the spent code's unwrap key inside the hook, sealed
  under the new passphrase's unlock layer and deleted at the record
  completion (the design's question 7).

## Consequences

- The add-and-retire entry remains the pivot, and everything after it
  is re-derivable from the pivot entry plus durable state (wallet-core
  decision 0010 satisfied for this ceremony once built).
- A new torn state exists by design -- a client-key record for a
  client the document does not list -- and it must stay legible and
  fail-closed everywhere it can surface (the pending shape, the
  three-way login routing, the narrowed forgotten-browser detector;
  decision 0007).
- The hook is a required parameter on the changed wallet-core
  surfaces; an optional hook would silently preserve the phantom
  window for any caller that omits it.

## Revisit Criteria

None. A future ceremony may choose a different pivot, but a pivot that
publishes a successor's identity before the successor's key material
is durable is a defect under decision 0010, not a design option.
