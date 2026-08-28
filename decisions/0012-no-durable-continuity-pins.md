# 0012: No durable continuity pins

- Status: accepted
- Date: 2026-08-27
- Driving work: the domain-modeling pass that produced
  `decisions/0011-durable-names-server-storage-only.md`. Reframing an
  enrolled client as a cache exposed that all four continuity pins are
  browser-local, so the default session holds none of them across visits
  and the refusals they back were documented as unconditional.
- Affects: `src/lib/sessionKey.ts`, `src/session/persistence.ts`,
  `src/session/wipe.ts`, and the threat-model prose in ARCHITECTURE.md.
  Retires FW-345 and FW-371; voids the predicate FW-261 added. No wire
  contract, and no change to any shared package's API.

## Context

A continuity pin is remembered evidence of what this client last saw,
checked against what the host now serves. It catches an attack in which
every signature verifies: a signature proves authenticity and cannot prove
that an authentic artifact is the current one. Freewallet kept four -- the
account-log and roster-log chain heads (one keyed store, two slots), the
roster epoch, and the unlock record's freshness stamp.

All four live in the `freewallet-session` database, so they are a
remembered browser's state. The default entry is the transient login,
which builds `memoryResourceLogPinStore()` and an in-memory epoch map and
reads no freshness pin at all. So the majority session is
trust-on-first-use at every visit, and the second visit knows nothing the
first one learned. The code said so honestly in a docstring
(`src/session/keyring.ts:1234-1237`); ARCHITECTURE.md's threat-model
sections described the refusals without qualification.

The gap is not an implementation oversight. A pin is a witness set of size
one whose witness is you, and that is the one configuration that cannot
serve a first-time observer. Nothing about wiring fixes it. An
architecture whose default visitor has no history needs a party to ask
other than the host, which is what witnesses are for -- the notion
did:webvh took from KERI, and which KERI reuses across cases rather than
re-deriving per use.

That mechanism already exists in-house and unused.
`@interop/did-method-webvh/src/witness.ts` implements proof creation,
entry signing, parameter validation, approval counting, and proof
fetching, and `resolveDIDFromLog` accepts `witnessProofs`. Freewallet
references none of it. `@interop/vh-resource-log` has no witness notion
yet, so the roster and annex logs would need the Resource Log Profile to
gain one before witnesses covered them.

The threat pins defend is a storage host serving a valid PREFIX of a real
log. A prefix carries the genuine genesis, so the same SCID and DID:
`expectedDid` passes, entry proofs pass, chain verification passes. The
concrete harm is that a rotation's recipient resolver reads the stale
document and re-wraps the fresh user key to a client the account has
revoked. That needs host malice plus a previously-revoked client
colluding. On a greenfield ecosystem proving out hypotheses, it is not
near the top of the threat list, and against a passphrase account the same
malicious host can grind the credential offline anyway -- a bound
ARCHITECTURE.md already states.

## Decision

Freewallet keeps no durable continuity pins. Every session builds the
in-memory pin stores the transient session already builds.

The rule, in one sentence: continuity is checked within a session and not
across sessions. Cross-session continuity is a witnessing problem owned by
the log layer.

Per-visit pins still do real work, so they stay in memory rather than
being removed from the call sites. One login makes many log reads -- a
transient visit resolves the annex log three times, plus the account log
and the roster -- and an in-memory pin catches a host serving inconsistent
versions across them. What is given up is memory across visits, which only
ever existed on a remembered browser.

Unchanged: the `ResourceLogPinStore` port, the continuity and integrity
refusal classes, and all chain and entry-proof verification, all of which
live in `@interop/vh-resource-log` and wallet-core. This is freewallet
choosing one implementation for both persistence strategies, not an API
change, so DCW's own choice is untouched. Also unchanged is the
Space-to-DID mapping, which sits near the pins in the wipe enumeration and
is not one: the pre-promotion heal login needs it to state an
`expectedDid`.

Two bounds become stated rather than defended, and ARCHITECTURE.md says so
where each was previously claimed as a refusal:

- A host serving a log prefix is not detected. A rotation run against such
  a view can re-wrap the fresh user key to a revoked client.
- A replayed unlock record is not detected. A login can land in an account
  the user has moved off, which is visible and reversible by logging in
  again once the host serves the current record.

## Rejected Alternatives

- Keep all four. They protect the minority path against the threat ranked
  lowest, and they carried real cost beyond their own code: a doc-accuracy
  debt that described a remembered browser's guarantees as everyone's, two
  open work items (FW-345, FW-371), and a predicate item (FW-261).
- Keep the account-log chain-head slot alone, dropping the other three.
  The cheapest non-zero option, and the one covering the case with real
  harm. Rejected on pricing: the cost is in having any browser-local pin
  at all -- the session-database store, the forward-only compare-and-set,
  the slot keying, a wipe stage, and a strategy family that differs
  between variants. Keeping one of four sheds little of it.
- Move a pin to a home the storage host cannot forge, such as the unlock
  record's credential-authenticated core. Circular: the record is
  host-served too, so it can be replayed, and nothing in it can attest to
  its own currency.
- Build witnessing now. It is the right successor and the wrong moment.
  It needs a witness notion in the Resource Log Profile before it covers
  the roster and annex logs, and it needs witnesses reachable
  independently of the storage host to mean anything -- proofs fetched
  from the same origin as the log arrive consistent with the prefix.
- Keep the pins and narrow the documented claims instead. It leaves the
  machinery, and it preserves a mechanism that would be replaced rather
  than extended when witnessing lands. Maintaining it is maintaining a
  placeholder.

## Consequences

- Removed from `src/lib/sessionKey.ts`: the eleven exported pin functions
  (the freshness trio, the epoch family and `epochPinWriteAllowed`, the
  durable `sessionLogPinStore` and its deleters).
- Removed elsewhere: the `freshnessPinFloor` parameter threaded through
  signup and the credential-anchored genesis, the epoch-pin and log-pin
  stages of the wipe enumeration, and the divergence between the two
  persistence strategies' pin members.
- Remembered and transient sessions gain identical continuity properties.
  Every "which session types does this guard" qualification in
  ARCHITECTURE.md stops being needed, including the four added on
  2026-08-27 alongside `decisions/0011`.
- The refusal classes stay reachable and still fire within a session, so
  the login page's continuity copy stays.
- FW-345 is void: there is no epoch pin left to wire into the transient
  roster read. FW-371 is answered: the bound is stated rather than closed.
  FW-261's `epochPinWriteAllowed` goes with the epoch pin; the item is
  already archived and is not rewritten.
- `decisions/0011`'s Browser-local entry loses the pins from its
  enumeration.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. Witnessing becomes usable end to end: the wallet consumes did:webvh's
   witness proofs, the Resource Log Profile gains an equivalent for the
   roster and annex logs, and witnesses are reachable independently of the
   storage host. The successor named here would then be real, and this
   decision narrows to whatever witnessing does not cover -- the unlock
   record's freshness among it, since that record is not log-governed.
2. The threat model changes: a deployment treats the storage host as
   untrusted by default, or an incident makes prefix-serving concrete
   rather than theoretical.
3. Passkey-only accounts become the common case. The "a malicious host can
   grind the credential anyway" argument holds for a passphrase and fails
   for a high-entropy PRF output, so a passkey-dominant deployment has a
   materially different exposure.
