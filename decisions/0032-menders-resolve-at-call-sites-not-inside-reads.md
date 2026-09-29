# 0032: Menders resolve at app call sites, not inside shared reads

- Status: accepted
- Date: 2026-09-28
- Driving work: the design that moves menders from login-scheduled
  sweeps toward resolve-on-read, so a reader that meets a violated
  invariant converges it when its session holds the authority.
  Extracted at that design's approval, from its rejected alternatives.
- Affects: `@interop/wallet-core` (the read functions in `/keys`,
  `/clients`, `/descriptors`, `/clientAnnex`, which stay read-only);
  freewallet (`src/session/menders/encounter.ts` and the sites that call
  it); dcw.

## Context

A torn state that arises mid-visit, or that the visit's own login chain
cannot converge, used to wait for the next login of the right kind. On
a credential-anchored account that login may never happen
(`decisions/0010-remembered-login-is-not-a-mender-trigger.md`).
Resolve-on-read moves the trigger to the point where a read meets the
violation.

That point exists at two layers. The shared read functions in
`@interop/wallet-core` see the evidence first: the roster read, the
descriptor read, the annex read. The app call sites around them hold the
session, its account-ceremony context, and the page.

## Decision

Convergence runs at app call sites, through freewallet's encounter
runner. The shared read functions stay read-only. They may detect a
violation and report it, as was-client's self-refreshing cipher detects
an unknown epoch, but they heal only the reader's own cache. The login
chain stays as the fallback trigger, and nothing moves off it.

Do not reopen.

## Rejected Alternatives

- **Resolve inside the wallet-core read functions**, so a roster or
  descriptor read heals durable state itself. The reads would need
  signing authority threaded in. dcw and freewallet hold different
  authorities at the same read. A read that writes also breaks the
  read-then-decide shape every converger relies on.
- **A periodic timer sweep in the live session.** It runs with no
  encounter, so it re-creates the login chain on a clock, and it gains
  no authority the chain lacks.
- **Duplicate the remembered chain on the transient path.** The rows it
  would add are the ones whose converging authority a ladder signer
  lacks, so it would register convergers that cannot run. This is
  `decisions/0010`'s rejected transient-sweep alternative in another
  form.

## Consequences

- Each encounter site is app code: it wires its read's detection to a
  registration and handles the outcome on its page. A second wallet
  wires its own sites.
- The encounter runner owns the ordering discipline once. It waits for
  the chain's registry-writing registrations to settle, single-flights
  per session and invariant, and spends a per-session budget. The shared
  single-registration runner it calls is exported from
  `@interop/wallet-core/menders`, so the try, warn, and skip discipline
  is not copied.
- Encounters widen triggers, not authority. A state whose converging
  authority a transient session lacks stays a gap however often a
  transient session reads it.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. Both wallets hold the same authority at a given shared read, so a
   converger inside it would not need per-wallet authority threaded in.
2. The server gains a primitive that converges a torn state on its own
   (a same-Space batch, a leased create), which moves that state's
   convergence off the client entirely.
