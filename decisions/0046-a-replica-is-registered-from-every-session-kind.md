# 0046: A replica is registered from every session kind, under a pointer-gated ladder pull

- Status: accepted
- Date: 2026-10-26
- Driving work: the design that lets every session kind, the transient
  default included, register a replica server and copy the account onto
  it. Extracted at that design's approval.
- Affects: freewallet (the replica registration ceremony and its
  pre-flight, the replica pass's renewal, the Storage page), wallet-core
  (`/clientAnnex`: the ladder-signed pull mint; the ceremony id; the
  `hostConformance.ts` header's predicate count), app-connect-spec
  (decision 0003: clause A's sixth predicate and the replica server's
  replicas-route predicate), was-teaching-server (the sixth predicate,
  covering both Spaces; the controller check's new branch; the replicas
  route's delegated invocation; the in-place capability replacement on
  a registration; the `0.1` version comments in
  `src/config.default.ts`; its `decisions/0002`), storage-core and
  was-client (the replication IRI constant, and capability replacement
  on `Space`), portable-web-spaces-spec (the replication decision 0013
  amendment: the pull may be ladder-signed under the annex pointer).

## Context

As shipped, two server checks admitted only what an enrolled client can
supply. The source server admits a pull delegation signed by a
`capabilityDelegation` method, and the ladder clause bounds what a
ladder VM may sign to five shapes, none with a server DID as grantee.
The replica server's registration check admits a replica Space whose
did:key controller the account document lists under
`capabilityInvocation`. So only a remembered session on an account with
an enrolled client could register a replica.

The default account is credential-anchored, and every visit to it is a
transient session. A transient session is a full session. Its only
long-lived delegation signer is the ladder VM, and decision 0002 forbids
the ladder authority that leaves no record.

## Decision

Every session kind registers a replica: a remembered session, a
transient session on a credential-anchored account, and a transient
session on an account that also has enrolled clients. One ceremony
covers all three, and one pass mends it. The kinds differ only in who
signs the pull delegation.

The pull delegation has one shape on every kind:

- `invocationTarget`: the Space's canonical trailing-slash container
  URL, or its `*` subtree form once the explicit subtree scope ships.
- `controller`: the replica server's `serverDid`.
- `allowedAction`: `['GET']`.
- `parentCapability`: the Space's root.
- `expires`: 365 days (`STANDING_ZCAP_TTL_MS`), renewed inside the
  30-day window (`ZCAP_RENEWAL_WINDOW_MS`).

On the enrolled kind this client's VM signs it. The ladder clause does
not bound an enrolled VM, so the pointer does not gate this pull. The
pointer is still written, as the record and for the pass's anomaly
check.

On the ladder kind the acting credential's ladder VM signs it. A sixth
ladder-clause predicate admits it only while the pointed annex document
carries a replica pointer (decision 0045) whose endpoint equals the
delegation's sole `controller`. The predicate covers both Spaces the
ceremony copies: the account Space, and the auxiliary Space the account
document's `DelegatedClients` entry names. Removing the pointer ends
that server's ladder-signed pull of the account Space. It does not yet
end the pull of the auxiliary Space. The clause's predicates are
alternatives, and predicate 2 branch two still admits a GET of the
auxiliary Space to any grantee, with no pointer check. Until a later
design narrows that branch, revocation at the auxiliary Space is that
pull's only stop. The narrowing is what makes the auxiliary pull
pointer-gated in fact. This is accepted. The predicate's text is owned
by app-connect-spec decision 0003, clause A, and is not restated here.

A renewal and a re-start replace the pull capability in place on the
replica server. The registration keeps its id, its pull loop, and its
checkpoint, and the mapping never lapses. The replica server validates
the new capability as it validates a registration's. A first
registration alone records a pending registration id before its POST.

After promotion, a credential-anchored account maintains the
registration through a delegated grant on the replica Space's replicas
route. That shape, and its bound, are recorded in decision 0002's
2026-10-26 amendment.

## Rejected Alternatives

- **Enrolled-only: refuse a credential-anchored account with copy.**
  What the servers admitted before. It denies replication to the default
  account, and its only fix routes the user to a remembered client,
  which the standing rule rejects. Do not reopen.
- **A sixth predicate with no pointer.** Any ladder-signed GET on the
  account Space to a server DID, with no record. A phished credential
  could copy the whole account to a server of the thief's choosing, and
  decrypt the copy with the user key the same credential unwraps. The
  existing silent read shapes reach one Resource or the annex. This one
  would reach everything. Do not reopen while loudness is the model.
- **The annex VM under the generation delegation.** Loud through the
  visit's annex entry, and probably admitted with no server change. It
  loses on lifetime. The grant's `expires` is bounded by the generation
  delegation's, a ladder-signed generation delegation dies at the next
  swap's pointer move, and the per-visit VM stops resolving when its
  generation is collected. The copy would lapse at every swap, with no
  restate that could save it.
- **The auxiliary pull on predicate 2 branch two.** That branch already
  admits a whole-auxiliary-Space GET. It has no pointer gate and no
  grantee bound, and its mint writes no log entry, so the auxiliary pull
  would be silent and would survive the pointer's removal. The wallet
  writes its grant to the sixth predicate instead. The branch still
  admits that grant until it is narrowed, so the auxiliary pull
  survives the pointer's removal in fact for now.
- **Add-then-remove for a replacement.** A new registration beside the
  old one, then the old one removed. Loop state is per registration id,
  so every renewal and re-start would start from an empty checkpoint
  and re-read the source, and a tear between the two left two
  registrations to reconcile.

## Consequences

- Four server changes must land before the ladder half ships: the
  controller check's new branch, the sixth predicate, the replicas
  route's delegated invocation, and the pause with the in-place
  replacement.
- The client-annex profile and the replication version both stay
  `0.1`, since replication has not shipped. A pre-release source server
  that predates the sixth predicate is upgraded rather than detected.
  The pre-flight checks the profile's presence at `0.1`.
- A ladder-signed pull dies at its credential's retirement, at its
  revocation at the source, and at `expires`. A pull of the account
  Space also dies at the pointer's removal or a missed restate. A pull
  of the auxiliary Space does not, until branch two is narrowed. An enrolled-signed pull dies at that
  client's revocation or forget, at its revocation, and at `expires`.
  Withdrawn signers are decision 0051's.
- The ladder clause's locked property gains a clause: "or a read of the
  account Space by a server the account's pointed annex document
  names".
- The list of shapes a ladder VM may sign without an annex entry grows
  to six. The sixth is the first gated on a record rather than on shape
  alone. A later design may generalize that form, so further standing
  grants reuse it instead of adding predicates.
- Predicate 2 branch two still lets a standing credential's holder mint
  a whole-auxiliary-Space GET to any grantee with no entry. That is
  pre-existing server behavior. This record no longer relies on it, and
  its bound is separate work. Until that bound lands, the same branch
  admits the wallet's own auxiliary pull with no pointer, so the
  auxiliary pull is not pointer-gated in fact.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The ladder clause gains a general record-gated form for standing
   grants. The sixth predicate then becomes one instance of it.
2. A credential-anchored account gains a long-lived delegation signer
   other than the ladder VM, which could sign the pull grant without a
   ladder-clause predicate.
3. Predicate 2 branch two is narrowed, for example by a grantee bound.
   The auxiliary pull then dies at the pointer's removal, and the
   statements of this record's auxiliary-pull gap are dropped.

If revisited, enrolled-only replication and a pull predicate with no
record both stay rejected.
