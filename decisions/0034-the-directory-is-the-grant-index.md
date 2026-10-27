# 0034: The directory is the grant index

- Status: accepted
- Date: 2026-10-01
- Driving work: the design of the `connections` directory, one record
  per known party, which replaced the history log as the record of
  which grants a party holds. Extracted at that design's approval.
- Affects: freewallet (`src/lib/walletRequest/respond.ts`'s
  `beforeProvision` hook, `src/lib/connectedApps.ts`,
  `src/session/applications.ts`, `src/session/shares.ts`,
  `src/session/revocation.ts`, the Applications page, the shares dialog,
  Settings > Connected wallets, the admitted-recipient resolver in
  `src/stores/storageManager.ts`, the replica registration ceremony and
  the replica pass); dcw (the same listings and revocations).

## Context

Revocation of an app, an agent, or a share walked the `wallet-activity`
log for Grant rows and re-derived the party's grants from them. A row
lost to a history clear, a sync conflict, or a misbound envelope took the
revocation hook with it, and the key-epoch rotation that reads the same
rows could evict a party or keep one it should drop. The log is a
replicated, append-only audit trail, and ordering a Grant against a
later Revoke needed a clock-floor workaround.

## Decision

Every grant the wallet delegates is recorded on the grantee's directory
entry, in `grants`, at consent: after the delegations are signed, before
any grantee is escrowed into a key epoch, and before any presentation
leaves the wallet. A failed entry write fails the request closed.
Revocation of an app, an agent, or a share, and the admitted-recipient
resolver, read the entry's `grants` and the key-epoch rosters, and never
the history log. The `wallet-activity` Grant, Revoke, CollectionShare,
and ClientRevoke rows stay as audit trail, read by the History page and
by nothing that decides.

Settings > Connected wallets keeps the verified account document as its
membership source, since the current-key-set rule makes the document the
authority on who is a client. It reads only names and labels from the
directory.

Consent is not the only recording site (the cleartext audiences design,
2026-10-05). The renewal pass records a re-minted agent grant on the
entry in one compare-and-swap with its pending push, and
`delegateAudienceGrant`'s caller records a member grant on the member's
entry. The replica registration records each pull grant on the
`replica-server` entry before the registration delivers it to the
replica server. Each writes a Grant activity after the entry write, so
the audit trail shows every auto-renewal, every audience membership,
and every replica pull grant. A grant
the owner restores at a ceremony dialog or on the Notifications page is
recorded as a fresh consent with its own Grant activity. The order is
the same at every site: the entry first, the activity after, nothing
deciding reads the activity.

## Rejected Alternatives

- **Keep the history log as the index.** The status quo and the lost-row
  gap.
- **Both: the directory with a history fallback when an entry is
  missing.** Keeps the lost-row gap on the fallback branch and makes
  "audit trail only" false. The one consumer that wanted it, the
  stranded app-key sweep, is retired instead.
- **Membership of Connected wallets from the directory.** The listing
  would show a client the document no longer lists, or hide one it does.

## Consequences

- Persist-before-publish moves to the entry write; the Grant row is
  written after it, inside the same hook.
- The ordering helpers that floored a Revoke's stamp past its Grant are
  deleted; retirement replaces ordering.
- A party that connected before the directory existed has grants and
  epoch entries and no row. No backfill is run (0036). The invariant
  "every party with authority has an unretired entry" is declared as a
  gap nothing converges yet.
- A user who deletes the directory from the Storage page loses every
  party's revocation index; which collections that action may delete is
  decided separately.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The storage host offers a server-side grant index the wallet can read
   under its own authority, making a wallet-side record redundant.
2. The directory is replicated (0035 reopened), so a replica merge rule
   has to decide which grants survive a conflict. A server-to-server
   copy of the `connections` ciphertext to a replica server does not
   meet this criterion. The directory still has one writer, the wallet,
   and one grant index, on the source Space. The replica server holds
   an inert copy that no reader on the source consults.

## Changelog

- 2026-10-05: Named the two recording sites outside consent, the renewal
  pass and the audience member grant, each writing its Grant activity
  after the entry write. A refinement of "at consent"; the rule and its
  order are unchanged.
- 2026-10-26: Named the replica registration as a recording site, and
  stated that a server-to-server copy of the directory to a replica
  server does not meet revisit criterion 2. The rule is unchanged.
