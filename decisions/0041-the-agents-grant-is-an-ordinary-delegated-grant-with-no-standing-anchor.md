# 0041: The agent's grant is an ordinary delegated grant with no standing anchor

- Status: accepted
- Date: 2026-10-05
- Driving work: the design of cleartext audiences, where an always-on
  subscription agent re-delegates read access to large audiences on the
  owner's behalf. Extracted at that design's approval.
- Affects: freewallet (the interaction-URL consent that mints the
  agent's grants, the renewal pass, the ceremony dialogs' agent tick,
  the Notifications page), wallet-core (`/clientAnnex` and `/clients`,
  which hold the authorities the grant rides), app-connect-spec (the
  agent connect section), the agent (its inbox-read cadence).

## Context

A zcap is a signed document, and issuing one costs a signature, so the
pull axis scales when something always-on signs on the owner's behalf.
The agent needs authority on the owner's Space that it can narrow and
pass on. Every authority a wallet session holds is bounded: an enrolled
client's root authority ends when the client is revoked, and a
transient session's generation delegation ends at annex GC or when its
ladder signer leaves the account document, which a passphrase change,
a backup-credential removal, or a recovery spend does at once. Nothing
in the account is permanent except the account DID itself, and the
server's current-key-set rule makes every delegation chain verify
against the document as it stands now.

## Decision

The agent receives one GET and HEAD zcap per audience collection it
serves, targeting that collection's container URL with the `*` marker,
the same shape as a share grant, minted at an interaction-URL consent
onto a `kind: 'agent'` connection entry. It carries the share lifetime.
Nothing marks it delegable; any controller may delegate a narrower
child, and the server enforces attenuation, chain depth, and per-link
revocation. A subscriber receives a child from the agent.

The grant rides the minting session's own authority and nothing else.
On a transient session that is the annex generation delegation, so the
grant expires no later than the delegation does. On a remembered
session it is signed by the client's key and dies with that client. No
standing anchor exists for an agent: no root-anchored delegation, no
key of the agent's in the account document, no ladder-signed grant.

The consequence is accepted and stated to the owner: every subscriber
child falls when the parent does. Annex GC, a client revocation, and
each ladder-kind credential ceremony cut every subscriber of the
affected grants at once. The wallet's renewal pass re-mints an in-place
renewal before expiry, and after a consented cut the owner ticks which
agents to reconnect at the ceremony dialog (record 0043). The outage is
the agent's inbox-read cadence, at most an hour, plus its re-issue and
each subscriber's fetch. Annex GC makes this a routine cut about four
times a year per owner.

## Rejected Alternatives

- **One Space-wide read grant, narrowed per audience by the agent.**
  The agent could read every collection, and collections sit flat, so
  no target prefix covers only the audiences.
- **The agent's key under the account document's
  `capabilityDelegation`.** A root-anchored delegation with no parent
  and no expiry chain, which makes the agent part of the identity and
  its removal a document edit.
- **The agent's key under `assertionMethod`.** Account-wide append
  authority over every descriptor log (wallet-core's key-layer record).
- **The agent as an annex VM.** Space-wide reach, and it would make the
  agent a wallet client, with a client's authority and a client's
  revocation.
- **A ladder-signed root-anchored grant to the agent.** A server clause
  and a spec change, and a ladder exercise with no record in any log,
  which fails loudness. The server's client-annex clause admits a
  ladder-signed collection delegation only to the annex DID.
- **A two-phase swap at annex GC**, installing and pushing the new grant
  at one login and revoking the old after a grace period, so subscribers
  hold two children across the cut. Parked as a later item: it reopens
  GC's stage order and the fail-open window for the grace.

## Consequences

- The passphrase-change cut, the client-revocation cut, and the GC cut
  are features of the authority model, not bugs. The owner is told at
  the ceremony, and the renewal pass heals the GC cut at the next login
  with no human step.
- The agent must read its inbox at least hourly while it holds any live
  grant from the owner, and must adopt a renewed grant by zcap id.
- A grant whose signer was withdrawn is never renewed silently (record
  0043), so a consented cut always needs the owner's tick.
- The agent's reach is bounded by the share lifetime and the parent's
  expiry, and every child inherits the tighter of the two.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The authorization profile gains a delegation whose parent is the
   account DID itself with an expiry the owner controls, so an agent
   could hold a grant that survives GC without being part of the
   identity.
2. A deployment reports that the four-times-a-year GC cut, with the
   hourly cadence, is a visible outage for subscribers.

If revisited for the second reason, the two-phase swap at GC is the
parked remedy and does not change this record's rule.
