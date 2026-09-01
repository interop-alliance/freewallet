# 0015: Unlock Spaces keep their own did:key controllers

- Status: accepted
- Date: 2026-09-01
- Driving work: the FW-400 design gate (account deletion from a
  transient session), whose v3 promoted every unlock Space's controller
  to the account did:webvh and whose v4 withdrew that structure the
  same day. Extracted at the design's approval.
- Affects: freewallet (`src/session/keyring.ts`, the deletion walk),
  `@interop/wallet-core` (`/keyring`, `ensureUnlockSpace`),
  was-teaching-server (unlock-Space authorization), dcw (the
  root-invoked keyring record fetch).

## Context

Account deletion has to reach every unlock Space the account's methods
own, and each unlock Space is controlled by its own unlock did:key,
which no account-held key can root-invoke. One uniform controller --
every Space of the account resolving out of one document -- looked like
the obvious fix, and it was the design's first answer.

## Decision

An unlock Space's controller stays its own unlock did:key. The account
reaches a sibling unlock Space only through the `manageCapability` that
did:key delegates at every standing bind: controller the account
did:webvh, target the bare unlock Space URL, `allowedAction`
`['GET','PUT','DELETE']`, one-year expiry. Deletion signs a DELETE-only
child of that capability (`decisions/0014`).

No new wire member links the account to its unlock Spaces in either
direction. Enumeration is registry-driven; an unlock Space the registry
cannot name is detected where possible, reported as a residue, and
mended by its own credential's next use (the backstop: a credential
whose account is gone deletes its own unlock Space).

## Rejected Alternatives

- **Promoting every unlock Space's controller to the account
  did:webvh.** One uniform rule, four blocking costs, all consequences
  of moving the controller: `ensureUnlockSpace` demotes or fails on
  every re-bind, since it PUTs `controller: <unlock did:key>`
  unconditionally; an unpromoted sibling makes deletion refuse forever
  with no credential-only mender; the credential's own record read
  loses its root invocation, forcing a world-readable record that
  publishes an offline verifier for a passphrase guess; and every
  unlock Space appears in the account's own Space listing. It also
  requires re-establishing every existing account.
- **A new Space Description member pointing at the account.** A new
  permanent wire member for one ceremony's reach.
- **An account-document member listing the unlock Space ids.** Worse: a
  world-readable list of `hash(unlock did:key)` addresses is an offline
  verifier for a passphrase guess, exactly what the hash-commitment
  rule exists to prevent.

## Consequences

- dcw's root-invoked keyring record fetch is unaffected; nothing about
  the record's read path changes.
- A management zcap lives one year and only its own unlock identity can
  re-delegate it, so a credential never used again lets its zcap lapse.
  A lapsed sibling is a reported residue, not a refusal
  (`decisions/0014`), and the transient login now mints and refreshes
  the acting credential's own zcap so the default account shape stops
  lapsing wholesale.
- A did:key-controlled Space never stops resolving, so no server
  controller-liveness sweep can ever reap an orphaned unlock Space; the
  backstop is the only mender, and a credential never used again leaves
  its Space standing for the life of the deployment.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A need other than deletion requires uniform controller resolution
   across an account's Spaces, and each of the four blocking costs
   above has a concrete answer first.
2. The keyring record's read path stops depending on root invocation by
   the unlock identity (for example, a redesigned record that is safe
   world-readable), removing the demotion and oracle costs.
