# 0047: The replica Space is created under the pairwise bootstrap key and promoted after the first pull

- Status: accepted
- Date: 2026-10-26
- Driving work: the design that lets every session kind, the transient
  default included, register a replica server and copy the account onto
  it. Extracted at that design's approval.
- Affects: freewallet (the replica registration ceremony's create,
  register, and promote stages; the replica pass's promotion; the
  Glossary's pairwise did:key entry), wallet-core (`/connections`: the
  `replica-server` entry's `seed` and `seedTag`, and the
  `connectionDidKey` derivation), was-teaching-server (the registration
  controller check's new branch, with the cross-Space controller
  resolution for the auxiliary Space), portable-web-spaces-spec (the
  replication decision 0013 amendment: the new check branch).

## Context

The replica server creates a Space only under a did:key. Its
registration check then admits a replica Space whose controller equals
the source Space's, or is a did:key the account document lists under
`capabilityInvocation`. A credential-anchored account has no such key.
The account did:webvh resolves on the replica server only once its log
has been copied, which takes the first pull. Whatever key creates the
replica Space holds root over it until then.

The key has to be one any session can derive, whichever credential it
entered on. A torn run must be finishable by a later visit on a
different credential. The replica server refuses a second registration
of the same source Space that shares a Collection with the first, so a
replica stranded under a key nobody holds blocks every later
registration of the account on that server.

## Decision

The replica Space's bootstrap controller is a did:key K derived from
the `replica-server` connection entry's `seed` and `seedTag` through
`connectionDidKey`, the pairwise did:key derivation. Every session that
reads the directory derives K. The codec writes a seed once and
retirement keeps it, so a re-registration on a retired entry reuses
the same K.

K creates the account replica Space and the auxiliary replica Space,
each at its recorded fresh id (decision 0048) and with its source
Space's own type set. K registers each. After the first pull, when the
`id` Collection reads synced, K promotes each Space to the account
did:webvh with Update Space. From then on K controls nothing, and it
gets the masked 404 on the replica Space. A resume reads promotion
through the account authority: the enrolled root, or the ladder's
delegated replicas-route grant.

The replica server's controller check gains a branch that admits K. The
local Space's controller is a did:key. The source Space's controller is
a did:webvh the server can resolve, either through the pull
capability's read of the hosted log, or from a local copy another
registration maps. The latter is the auxiliary Space's case, whose
controller's log lives in the account Space. The registration's
capability has the chain `[root, capability]`, and its proof's
verification method is listed in that document under
`capabilityDelegation`.

The branch does not read the annex pointer, since the replica server
cannot reach the annex before the auxiliary Space is copied. The gate
sits at the source server instead. The replica server reads the source
Space through the capability during registration, and the source
server refuses a ladder-signed pull with no pointer.

## Rejected Alternatives

- **The ladder's bare did:key as the bootstrap controller**, with the
  check admitting a `capabilityDelegation` key. It has precedent in
  genesis, and was the runner-up. It is per credential. A replica left
  unpromoted by a torn run could be finished only by a visit on that
  credential. If the credential retires first, the replica Space is
  stranded and blocks every later registration of the account on that
  server.
- **A key the annex document lists.** The annex DID resolves on the
  replica server only once the auxiliary Space is copied, which needs
  its own registration first. The listed keys are per visit, and a
  per-visit key would hold root over a Space, controller rewrite
  included.
- **The ladder's bare did:key with promotion at once.** Promotion waits
  on the first pull, so "at once" does not remove the stranding case,
  and it needs the same server change.
- **Never promote, so K controls the replica for its whole life.**
  Maintenance would need no delegated route. But every holder of the
  user key, a revoked client included, would be the silent root over
  the copy for as long as it exists. A disaster-recovery login would
  have to promote anyway.

## Consequences

- Between the create and the promotion, K is root over the replica
  Space, and any holder of the user key can derive K from the
  directory, a revoked client that read the entry included. Such a
  holder can read the copy and delete it, and cannot touch the source
  server. A healthy run closes the window within seconds. A torn run
  keeps it open until a pass promotes. This is an accepted gap beside
  `no-withdrawn-party-holds-a-live-pairwise-channel`, kind `none`. K
  rotation rides the pairwise seed rotation when that is built.
- In a tear between recording the pull capability and posting the
  registration, a directory reader can register that capability under
  its own did:key first. It then wins the mapping check and strands the
  wallet's registration. Such a reader already holds the user key and
  K, so its reach is the same party's. The server item may close it by
  binding the local did:key to a K recorded with the capability.
- The pairwise did:key is no longer only the wallet's key toward an
  agent. The Glossary entry widens to name the replica Space's
  bootstrap controller, and its "signs nothing in the owner's Space"
  clause is revised.
- A replica Space whose controller is neither K nor the account DID is
  reported by the pass.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The replica server can create a Space directly under a did:webvh
   controller it resolves from the source server, so no bootstrap key
   is needed.
2. The replica server can verify the annex pointer at registration, so
   the check could bind the creating key to a key the pointer's
   ceremony recorded.
