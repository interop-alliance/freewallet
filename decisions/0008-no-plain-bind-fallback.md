# 0008: No plain-bind fallback where a standing establishment fails

- Status: accepted
- Date: 2026-08-25
- Driving work: the FW-315 design pass
  (`_spec/designs/FW-315-standing-before-space.md`, section 6), over
  class C of `_spec/transient-refusal-considerations.md`.
- Affects: freewallet (`src/session/signup.ts`,
  `src/session/accountSettings.ts`, `src/session/recovery.ts`,
  `src/session/standingUnlock.ts`); dcw's unlock catch-up inherits the
  policy.

## Context

Five flows bound an unlock credential plain (no ladder seed) and
upgraded it to standing best-effort afterwards: the durable passphrase
signup, the passkey signup, `addAccountPasskey`, the durable recovery
spend's tail, and `changePassphrase`. A swallowed establishment failure
left a plain pointer record. With the browser's client-key record gone
that state is bricked: no ladder seed to heal from, no did:webvh to
recover, and the signup probe answers `userExists: true`, so the
credential is burned too. The failure surfaces only at a fresh
browser's refused transient login, long after the cause.

## Decision

On a WAS deployment, no ceremony leaves an unlock record plain on a
transient-reachable account. Every producer either writes the
standing-layout record (the signups, folded into the
credential-anchored genesis) or fails-or-reports when the establishment
fails (the add, change, and recovery-tail ceremonies). A plain-bind
fallback anywhere a standing establishment fails is rejected as
do-not-reopen.

## Rejected Alternatives

- Keep a plain-bind fallback and warn. It converts a visible failure
  into a record only a fresh browser's refused login ever reveals, with
  the credential burned by then. The rejection covers ALL
  plain-bind-and-hope sites: the signup and add ceremonies, the durable
  recovery tail, and `changePassphrase`.
- Write user-facing copy for the `no-standing` refusal and keep the
  reason. The state is unreachable once its producers are gone; copy
  for an unreachable state is dead text (the considerations doc's
  invariant 3). The field population of already-shipped plain records
  is handled by the existing `transientUnavailable` mapping, not new
  copy.

## Consequences

- The signups run the credential-anchored establishment for every WAS
  account (the FW-315 design's option A); the plain bind survives only
  on no-WAS deployments, where no unlock Space exists and nothing can
  be standing.
- The recovery tail and `changePassphrase` report a failed
  establishment truthfully (the credential IS live, the standing
  upgrade or old-credential retirement is pending) through their own
  outcome members, since their re-binds cannot roll back.
- `no-standing` leaves `TransientLoginUnavailableReason` once every
  producer is closed and the field population is accounted for.

## Revisit Criteria

None while transient login is a supported entry.
