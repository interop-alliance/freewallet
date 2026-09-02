# 0002: No silent grant authority for unlock credentials

- Status: accepted
- Date: 2026-08-19
- Driving work: the public-computer login redesign for the browser
  wallet (default persist-nothing login; per-visit transient clients in
  a disposable companion did:webvh) -- the same design effort whose
  first implementation decision 0001 records. The design needed a
  mechanism by which a session holding only the unlock credential can
  approve app grants from an untrusted terminal, and surveyed widening
  the credential's latent authority to do it.
- Affects: freewallet (the login and App Connect popup flows),
  `@interop/wallet-core` (the unlock record's bridge delegation and the
  ladder machinery), was-teaching-server (the authorization clause that
  makes the adopted alternative's loudness load-bearing).

## Context

Every unlock method is a standing credential whose record the storage
host holds. Against a phished credential, or a host running an offline
KDF grind on that record, the design stance is detect-and-remediate:
takeover is visible in a hash-chained log and remediable by rotation,
not prevented. That stance holds only if every exercise of
credential-derived authority must first extend an auditable log (the
account log or the companion log). The credential's one standing bridge
into the zcap profile is deliberately narrow: it can PUT the log, and
nothing else.

## Decision

An unlock credential's latent authority is never widened into grant
authority that leaves no record. Any authority a credential-derived key
exercises must first extend a hash-chained, auditable log before it can
read or grant anything. Concretely: the bridge delegation stays
log-targeted, and transient-session app grants chain through a
delegation to a companion DID whose log records the visit -- a rule the
server's chain-verification clause enforces rather than trusts.

## Rejected Alternatives

- Delegation-bridge grant authority: a pre-minted standing delegation,
  carried in the unlock record, broad enough for a credential-derived
  key to sub-delegate app capabilities directly -- with no membership
  record anywhere. A phished credential (or a successful offline grind
  of the record) would then exercise grant authority with no
  world-visible trace. The adopted companion mechanism is exactly this
  idea with the loud record put back and made load-bearing by the
  server.
- A roaming public-terminal client: one standing keypair custodied in
  the unlock record, enrolled once, reused across terminals. Worse on
  every axis: standing silent signing authority; one shared identity
  across all terminals, so no per-visit revocation granularity and full
  cross-visit linkability; and a successful offline grind would yield
  silent standing authority where today it yields only a loud
  self-enrollment.

## Consequences

- Transient sessions pay a real per-visit cost: a companion log entry
  (and, when none exists, a generation mint) before any grant can be
  approved. The dominant public-terminal workflow carries that latency.
- The server must enforce the loudness rule in chain verification; on a
  server without that clause the rejected shape is not refused, so the
  wallet publishes ladder authority only on hosts that advertise the
  enforcing profile.
- Downstream code may rely on the invariant: there is no code path by
  which a key derived from an unlock credential grants or reads
  anything without a prior log entry.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A mechanism exists that makes the silent path impossible by
   construction rather than by policy (for example, grant issuance
   cryptographically bound to a log append, so an unlogged grant cannot
   verify anywhere).
2. The detect-and-remediate loudness stance is itself redesigned
   account-wide, with a replacement story for phished-credential
   detection.

If revisited, the replacement must state what a phished credential's
holder can do silently, and how the owner would ever learn of it.

## Amendment (2026-08-28)

The Revisit Criteria's closing requirement -- that a replacement state
what a phished credential's holder can do silently, and how the owner
would ever learn of it -- is answered PARTIALLY by the FW-356 design
doc, section 5.6, approved 2026-08-28.

What that section answers is the first half, restated against the state
FW-359 left. A ladder verification method still carries no
`capabilityInvocation`, so it cannot act alone, and its delegation to
the annex DID still costs an annex-log entry to exercise. But the
per-visit annex key it delegates to now publishes under
`capabilityDelegation`, so that key can sub-delegate onward to any
grantee, offline, leaving no entry anywhere. The annex append is
therefore not the loudness backstop this record treated it as. One
smaller exception was found in the same pass: the server's
delegated-clients disjunct admits a `GET` directly, so a ladder key can
self-delegate and read the annex bookkeeping with nothing appended. So
this record's Consequences claim that "there is no code path by which a
key derived from an unlock credential grants or reads anything without a
prior log entry" is not exactly true, and the reach of what a phished
holder can delegate is bounded by a wallet-side convention rather than
by the server until was-teaching-server WAS-67 lands.

The second half, which surface shows the owner it happened, is not
answered here. Client listings key on `capabilityInvocation`, so
standing ladder verification methods render nowhere, and the annex log's
per-visit entries are surfaced by nothing and are deleted at the next
garbage collection. That half is FW-358's.

The decision itself is unchanged.

## Amendment (2026-09-01)

FW-400 (account deletion from a transient session, approved 2026-09-01)
is a second, deliberate amendment rather than a case this record's
existing text covers. Deleting an account or its auxiliary annex Space
needs a Space-root DELETE the transient session's per-visit key cannot
reach, so the ceremony mints a DELETE-only capability, delegated to and
invoked by the ladder VM's own bare did:key, immediately before each
DELETE it sends (`decisions/0014`). That capability is grant authority
the ladder VM exercises with no log entry: the ceremony writes no
account-log entry for it and claims no loud record.

This is an amendment with a stated scope, not a retreat from the
decision. The scope is exactly one capability shape (a single-verb,
target-exact DELETE on a Space's own URL) minted only by the deletion
ceremony. The reason no entry is owed is structural rather than a
convenience: the account-Space DELETE destroys the very log any such
entry would live in, and leaves no reader behind to remediate from it.
Everything the ceremony deletes before the account Space -- the
auxiliary annex Space, the sibling unlock Spaces -- still destroys
Spaces while the account log survives and stays unmarked, so an
abandoned run in that window is a co-credential eviction with no
record: every other standing credential and every recovery code can
lose its unlock Space with nothing in the log to say so. The consent
surface this design adds (a fresh re-derivation of the credential at
its own confirm, and a second confirm scoped to what the discovery
phase found) stands in for the log entry that this scope does without.

Stated plainly, as the design does: every ladder VM the account
document lists may destroy the account, because DELETE is inside what
it may delegate. That population is bounded to the ladder VMs rather
than to every `capabilityDelegation` member on the deployment, and the
credential-retirement gate (wallet-core's decision) closes the one part
of that population loudness had no other answer for: a retired
credential's ladder VM left standing by an unattributed strike. It does
not reach a client-less account's other standing ladder VMs, each a
whole-account kill switch bounded only by its own credential's entropy.
