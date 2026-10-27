# 0049: Stop pauses a replica, and account deletion leaves replicas

- Status: accepted
- Date: 2026-10-26
- Driving work: the design that lets every session kind, the transient
  default included, register a replica server and copy the account onto
  it. Extracted at that design's approval.
- Affects: freewallet (the Storage page's Stop, Re-start, and Delete
  replica actions and their ceremonies; the replica pass's decision
  table; the account deletion dialog and its replica phase in
  `src/session/accountSettings.ts`), wallet-core (`/connections`: the
  `stoppedAt`, `restartedAt`, and `lostAt` members of a `replicas`
  item; the ceremony ids), was-teaching-server (the `pausedAt` member on
  the registration record, written and cleared by PUT; `status`
  reporting paused; a paused registration keeping its mapping),
  storage-core and was-client (the paused state, the `pausedAt` member,
  pause and resume on `Space`), portable-web-spaces-spec (the
  replication decision 0013 amendment, against its "no PUT in v1" and
  "only the removal of its registration stops a loop").

## Context

A replica server copies the account Space and the auxiliary Space. The
user needs a way to end the pull. Setting up a replica, letting it
sync, and then stopping it is a way to take a backup snapshot. Moving
an account to another server is a separate ceremony, with replication
as its transport. It copies the account, deletes the original, and
works from the copy.

Ending a pull by removing the registration does not work after
promotion. The replica server refuses to remove the last registration
that maps a promoted Space's did:webvh controller, and a replicated DID
resolves only through a registration. Leaving the loop running instead
has it back off on 404 forever once the source refuses it.

## Decision

Stop ends the pull and keeps the copy. In order:

1. Mark each of the server's `replicas` items with `stoppedAt`, in one
   compare-and-swap on the entry. This is the intent and the pivot.
2. Pause the registration on the replica server, by writing its
   `pausedAt` member with PUT. The mapping stands, so the snapshot's
   controller keeps resolving.
3. Drop the replica pointer from the annex document.
4. Revoke every recorded pull grant on the entry, whoever signed it,
   each at the Space it is rooted in, and remove each from `grants`
   once its revocation lands.

The entry is not retired. A stopped item is not restated and not
renewed. The pass finishes a torn Stop from its first unfinished step.

Re-start writes `restartedAt` on the item first, and clears `declined`
when set, in one compare-and-swap. It then re-mints and records the
pull grant, restates the pointer, replaces the paused registration's
capability in place, clears `pausedAt`, clears `stoppedAt`, and clears
`restartedAt` last.

Delete replica is its own action. It acts on the pair of replica Spaces
on one server: Stop the pair in Stop's order, delete the auxiliary
replica Space, delete the account replica Space, remove both items, and
retire the entry when no item is left. A delete that meets a 404 counts
as done. There is no deletion marker. The user's re-run converges a
torn Delete, and the pass does not delete a Space unprompted.

A replica Space that vanished without the user's Delete is marked
`lostAt` when a probe under the account authority meets a 404. Nothing
is removed automatically, and the user's action on a lost item is
Delete.

`stoppedAt`, `restartedAt`, and `lostAt` are ISO 8601 UTC times on the
item, absent meaning unset, like `pausedAt` on the registration record.

Account deletion leaves replicas by default. Its dialog lists each
replica server, live and stopped, with an opt-in tick, default off,
covering that server's pair. A ticked pair is deleted ahead of the
account Space, in Delete replica's order, and a failed ticked delete
refuses the account deletion before its pivot. An unticked live replica
is paused in the same phase, and a failed pause does not stop the
deletion. A stopped replica is left as it is.

## Rejected Alternatives

- **Stop deletes the copy.** Rejected on 2026-10-24: "Stop should not
  automatically delete the copy. If the user wants the replica deleted,
  they can just call a DELETE on the space separately. Setting up a
  replica, letting it sync, and then stopping, thus creating a backup
  snapshot, is a valid usecase." Do not reopen.
- **Account deletion deletes every replica**, by the shared wipe's
  destroy-everything principle. Rejected on 2026-10-25. The migration
  use case is the move ceremony's, so a delete-all-replicas phase would
  be built and tested only to be disabled once that ceremony ships. Do
  not reopen.
- **Stop deregisters.** The delete guard refuses it after promotion,
  and where it succeeded the snapshot's controller would stop resolving.
- **A state enum on the item** (`live`, `stopping`, `stopped`,
  `restarting`, `lost`). Time markers say when as well as what, mirror
  the entry's `declined`, and need no transition table.
- **A deletion marker.** It would let the pass finish a torn Delete,
  which means deleting a Space with no user action in that visit.

## Consequences

- A stopped snapshot keeps a frozen copy of the account log. A client
  key revoked at the source after the stop still verifies there, and a
  ladder VM retired after the stop keeps its clause-admitted reach
  there. Deleting the snapshot is the only remedy.
- After account deletion no party can delete a surviving replica, on
  any account shape. The ladder seeds die with their unlock Spaces, and
  the deletion's local wipe removes a remembered browser's client-key
  record. The deletion dialog's tick is the only path. The user chose to
  keep the replica, so this is a stated consequence, not a gap.
- A tear between the two deletes leaves a stopped pair the pass cannot
  tell from a snapshot. The Storage page's probe marks the gone Space
  lost and offers Delete.
- The pause is a server change that contradicts the replication
  decision's "no PUT in v1" and "only the removal of its registration
  stops a loop". That decision is amended.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The replica server can resolve a promoted Space's controller without
   a registration, so Stop could deregister instead of pausing.

If revisited, Stop keeps the copy and account deletion keeps the
opt-in tick. Only the mechanism of the pause is open.
