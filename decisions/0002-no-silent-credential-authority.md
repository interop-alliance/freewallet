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
