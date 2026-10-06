# 0043: A grant signed by withdrawn authority is renewed only on the owner's tick

- Status: accepted
- Date: 2026-10-05
- Driving work: the design of cleartext audiences, whose renewal pass
  re-mints a subscription agent's grants before they lapse. The review
  found that an unconditional renewal would restore authority a client
  revocation had withdrawn. Extracted at that design's approval.
- Affects: freewallet (the renewal pass and its proof check, the
  dialogs of client revocation, the forget, the last-client transition,
  and the ladder-kind credential ceremonies, the post-ceremony
  encounter, the Notifications page, the `declined` marker on an agent
  entry), wallet-core (`markDeclined`, `recordGrants` clearing the
  marker), dcw (the same pass).

## Context

The renewal pass turns a recorded grant into a fresh delegation under
the session's current authority, with no prompt, because the owner
already consented to that scope. A recorded grant and a planted one are
the same object: a stolen enrolled browser can write an unretired agent
entry at its own did:key with a seed, a channel, and root delegations it
signs itself. After the owner revokes that client, its grants are dead
and therefore due. A renewal that accepts any grant the account document
ever listed re-mints them under current authority, and the revocation no
longer cuts the attacker. Only the owner can tell a genuine grant from a
planted one, and nothing in the stored state can.

A grant also dies when its parent is replaced while its signer stays
listed: annex GC, the in-place renewal, a client revocation's generation
swap for grants a remaining key signed. Those deaths carry no such
ambiguity.

## Decision

Silent renewal covers only a grant whose parent was replaced while its
signer is still listed in the account document. A grant whose chain died
because the authority that signed it was withdrawn is outside silent
renewal. Withdrawn authority is a revoked or forgotten client's key, the
departing client of a last-client transition, and a ladder VM struck by a
passphrase change, a backup-credential removal, or a recovery spend.

For such a grant the owner decides. Before a client revocation, the
last-client transition, or a ladder-kind credential rotation runs, its
dialog lists the connected agents whose grants the withdrawn key or
ladder VM signed, read from the entries (each proof names its signer, and
an annex-anchored grant's parent names its minter). The owner ticks which
agents to keep. Once the ceremony resolves, the wallet re-mints the
ticked agents' in-scope grants under the current authority, records each
as a fresh consent with its Grant activity, and queues the push. An
unticked agent stays dead, listed for revocation, and its entry gains the
`declined` marker.

Two ceremonies cannot take the tick in their own visit, the ordinary
forget and a recovery spend. For those, and for any agent an encounter
could not restore, the Notifications page offers each such agent later
for a one-tick restore as a fresh consent, or a decline that writes the
marker. The page reads its offers from the entries alone: an unretired
agent entry with no `declined` marker, holding a channel, whose in-scope
grants are all past `expires` or signed by withdrawn authority. A
declined agent is not offered again until a fresh consent, Restore on
its detail page or an approved new connection request, clears the
marker.

The proof check that sorts a dead grant into one kind or the other reads
no log history. It is limited to what the account signer check can
settle from the grant's own chain and the document as it stands, and a
grant it cannot settle is renewed by nobody, so it falls to the owner's
tick.

## Rejected Alternatives

- **Renew after a client revocation as well.** Cannot tell a genuine
  grant from a planted one, so the revocation stops cutting the
  attacker. Do not re-propose this; it is the whole reason for the
  record.
- **No renewal for withdrawn authority, with a fresh connection request
  from the agent as the only way back.** The dead inbox grant leaves the
  agent no in-band route to ask, so the owner would have to find the
  agent's own surface for every passphrase change.
- **Renewing at the ceremony without a tick**, listing the agents for
  information only. The same planted-grant hole, moved one screen later.
- **Reading the listing history** (the log, or the annex document) to
  decide the kind. The annex VMs a GC deleted are gone, the account log
  tells who was listed but not who planted what, and the check would
  need a log walk at every login.

## Consequences

- Every consented cut (record 0041) needs the owner's tick to reconnect
  an agent, and the outcome copy says which agents' subscribers are
  being reconnected and which the encounter could not restore.
- Each restored grant is a fresh consent, with its own Grant activity,
  so History shows every reconnection.
- The `declined` marker is a permanent member of an agent's entry and
  suppresses the offer until a fresh consent. A decline is a decision
  about the entry's grants as they stood; grants minted later arrive
  only through a consent that clears it.
- An attacker who planted an entry through a stolen client is cut at
  that client's revocation and stays cut unless the owner ticks the
  planted agent by name.
- The proof check's narrowness means a grant under a parent the check
  cannot settle is offered to the owner rather than renewed, which may
  ask the owner about a genuine grant. That is the cost accepted.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The account's stored state gains an authorship proof the host and a
   revoked client cannot forge, verified before a grant is read, so a
   planted entry can be told from a genuine one without the owner
   (record 0038's own revisit hook).
2. The connections directory gains a per-entry consent record signed by
   a key a revoked client never held, which would let the pass verify
   that the owner consented to the entry's scope.

If revisited, silent renewal after a client revocation still needs its
own record; the tick stays the default for the ladder-kind ceremonies,
whose struck VM is the owner's own credential.
