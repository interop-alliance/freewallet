# 0040: One posts collection per audience; the server gate is deferred

- Status: accepted
- Date: 2026-10-05
- Driving work: the design of cleartext audiences for social software.
  The gate question had been open since the server read-path research
  of late September; decided at the design's approval.
- Affects: freewallet (the audience collection layout, the grants it
  delegates, the agent's per-audience grants), wallet-core
  (`/audiences`), was-react (one reader per audience collection),
  app-connect-spec (a connection request names each audience by its
  container URL), every social app built on the profile (the stable
  post id), and was-teaching-server and the WAS spec on a pivot only.

## Context

Record 0039 requires that a reader reach only its own audience's posts.
Two mechanisms satisfy it. Partitioning (G3): one plaintext collection
per audience, so a post's audience is the collection it sits in and
membership is a read zcap on that collection. A server gate (G2): all
posts in one collection, each stamped with its audience, and the server
withholds a stamped Resource from a caller unless a membership Resource
for that caller exists in the audience's collection, with listings, the
`changes` feed, and the blinded-index query filtered the same way.

The gate layers an identity-keyed access check over a valid capability.
Nowhere in the WAS spec today does a valid capability reach less
depending on who invokes it. Its one concrete gain is a stable URL when
a post changes audience, and how often users do that is unknown. The
design is speculative enough that the quicker path to user feedback
wins.

## Decision

The cleartext layer builds partitioning. An audience is a plaintext
collection in the owner's Space, provisioned with
`AUDIENCE_PROVISION_ATTRIBUTES`. Membership is a GET and HEAD zcap whose
`invocationTarget` is the collection's container URL with the `*`
subtree marker, minted by `delegateAudienceGrant` for a small audience
and re-delegated by the subscription agent for a large one. Removal is a
zcap revocation. Nothing marks a collection as an audience on the wire.
A public audience is a collection under `PublicCanRead`.

Three rules bind every app on the profile, so that a later pivot to the
gate is one data migration and no app change:

1. A post that changes audience moves: created in the target collection
   first, then deleted from the source.
2. An app keeps a stable post id of its own inside the post body and
   resolves and de-duplicates posts by it. The Resource URL is not a
   stable identity.
3. A member in several audiences reads one collection per audience and
   merges by the stable post id.

The gate is deferred, not rejected. The gate note
(`FW-478-audience-gate.md` in the planning directory) stands as its
design: the stamp, the membership-by-existence rule, the 404 answer, the
filtered read paths, and the spec text. A later session must not file
the gate as a new idea.

## Rejected Alternatives

- **The server gate now (G2).** A new access-check class in the
  authorization profile, a stamp column and sidecar on both server
  backends, a membership cache, conformance coverage for every filtered
  surface, and spec text, all paid before any deployment has shown that
  posts change audience often enough to need a stable URL.
- **An audience list as a caveat on the member's zcap.** The server
  evaluates no caveats today, and membership would live in two places,
  so a membership change re-issues every affected zcap.
- **A policy type.** A policy cannot deny a valid capability.
- **Accepting one shared collection.** Record 0039.

## Consequences

- A post's URL changes when its audience does. Readers may briefly see
  a moved post twice, never zero times, since creation precedes the
  delete.
- Apps carry the stable id and the merge. The cost sits in the app
  layer, where it stays correct under the gate.
- The owner's clients and the agent hold and delegate one grant per
  audience collection. A Space-wide read grant is not a shape here.
- No server or spec work for the cleartext layer beyond WASS-58's `*`
  marker, which is a separate decision of the authorization profile.
- The key layer (sealed posts) has no equally cheap pivot: a plaintext
  audience cannot convert once it holds posts, and the same-scope rule
  binds the grant's target. Moving to it means new audience collections,
  a fresh consent from every agent, and every child grant re-issued.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A deployment observes that posts change audience often enough that
   the moving URL, or the double-read window, is a reported problem.
2. The WAS spec adopts a per-caller filter under its authorization
   profile for some other reason, so the gate's novel element is no
   longer novel.

If revisited, build the gate from the gate note as the pivot, with the
three app rules kept, so the migration is the one data move the note
describes.
