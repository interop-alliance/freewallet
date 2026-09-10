# 0027: Held authority comes from the account-ceremony context

- Status: accepted
- Date: 2026-09-09
- Driving work: the design for a shared mender registry -- the table of
  invariants that must hold between ceremonies, plus the code that
  converges a violated one. The runner filters chain-triggered
  registrations by the authority the session holds, and this record
  settles where that set comes from.
- Affects: freewallet (`src/session/accountCeremonyContext.ts` as the
  one resolver, `src/session/initSession.ts`'s login chain and
  `src/session/registryPasses.ts` as the two chain triggers, and
  `src/session/transientLogin.ts`, whose hand-assembled authority moves
  onto the seam); `@interop/wallet-core` (the registry module the design
  places there, and its `dueAt` reader); dcw, whose one registration is
  filtered by the same set.

## Context

`src/session/accountCeremonyContext.ts` already resolves one of two
kinds from a live session. The enrolled kind signs account-log entries
with this client's did:webvh update keys, appends the roster with its
key agent, and root-invokes. The ladder kind signs with a rung of the
credential's ladder through the record's bridge delegation, appends with
the ladder VM, and invokes as the per-visit annex VM under the
generation delegation. A guest, a no-WAS session, and a transient
session whose record carries no standing members resolve to neither.

An earlier draft of the registry added a second computation beside that
seam, to work out what a session holds. Three facts about the call sites
constrain it. Twelve of the twenty-eight entries fire at login-routing
sites that run before a `Session` object exists. The identity repairs
are circular under a filter, because the context resolves nothing until
the account pointer names the did:webvh, and those entries are what make
it name it. On a no-WAS session a filter would remove four passes that
run today.

## Decision

There is one resolver. The registry adds no second computation of held
authority.

The held set derives from that one resolution. It is `{ none }`, plus
`{ account, context.kind }` when a context resolves. A remembered
session holds `{ none, account, enrolled }`. A transient session on a
standing credential holds `{ none, account, ladder }`. A guest or a
no-WAS session holds `{ none }`.

`held` and `dueAt` apply to the two chain triggers alone. At every other
entry a declaration's `authority` is a claim made at declaration time,
evaluated by the entry's own call site. The twelve login-routing entries
therefore run as they do today, and the identity repairs are not
filtered out by the pointer state they exist to fix. The held set is
re-resolved once the pointer heal has landed.

`accountCeremonyContext` is not widened. A remembered session on a
standing credential could sign as the ladder as well, but the seam
resolves the enrolled kind and reports one. Every entry in the table
today is satisfied by that resolution.

One correction rides this decision. A second computation exists in
`src/session/transientLogin.ts` today, which hand-assembles the
authority the mend runs under rather than reading the seam. Moving it
onto the seam is a prerequisite of the build. The rule is that the
registry adds no third computation.

## Amendment, 2026-09-09 (the build; accepted by Dmitri the same day)

The held set derives from the session's own key material rather than from
a resolved context, and the rule "one resolver, no second computation"
stands: `sessionAuthorityKind` sits in `accountCeremonyContext.ts` beside
the resolver, reads the same profile members it reads, and prefers the same
kind, so wherever a context resolves the two agree.

The decision as first written could not be implemented as it stands. It says
a no-WAS session holds `{ none }`, and it also says a filter that removes
the four shared registry passes on such a session is wrong -- but those four
are chain-triggered, which is exactly where the filter applies. The same
contradiction covers the pointer heal: it is chain-triggered, and the
context resolves nothing until the pointer it heals names the did:webvh, so
a held set read off the resolution alone stands the heal down on the state
it exists to fix. Re-resolving after the heal does not help, the heal being
what is filtered.

What the resolution adds beyond the key material is a configured storage
server with a remote store and a promoted account pointer. Those are account
states rather than authorities, and they are what the chain's identity
repairs converge, so the held set does not read them. The consequence stated
below stands otherwise, and the re-resolution point stands as well: the
block's context memo is dropped when the pointer heal lands, so a
registration behind it reads the post-heal resolution.

## Rejected Alternatives

- **A parallel held-authority computation beside the seam**, the earlier
  draft's `heldAuthorityContexts`. There is nothing left for it to
  compute. The seam settles the kind, and the held set is that kind plus
  `none` plus `account`.
- **Boolean capability flags on the session.** Rejected by
  `decisions/0001-no-memory-overlay-storage-fork.md`'s rule that a write
  site consults no flag. The authority follows from types the login
  already fixed.
- **Filtering every entry through the held set, login-routing entries
  included.** There is no session at those sites to resolve from. It is
  also circular for the identity repairs, and on a no-WAS session it
  would remove four passes that run correctly today.
- **Widening the seam so a remembered session on a standing credential
  reports both kinds.** Nothing needs it. The seam is widened on the day
  an entry needs the ladder specifically from a remembered session.

## Consequences

- One member is evaluated two ways. It is a runtime filter at the two
  chain triggers and a declaration-time claim everywhere else. A reader
  must check an entry's trigger before reading its `authority`. That
  inconsistency is accepted, because twelve entries run before a session
  exists.
- A wrong claim at a login-routing entry is unenforced by the runner. It
  surfaces in review, or when that entry fails at its own call site.
- The held set mutates during the chain, and there is exactly one
  re-resolution point: after the pointer heal lands. An entry that
  changes the set again later needs its own re-resolution, and nothing
  detects that omission automatically.
- Downstream code may rely on this: what a session may converge follows
  from the keys it holds, not from a flag and not from a second
  resolver.
- The build carries a prerequisite. The transient login's hand-assembled
  authority moves onto the seam before the registry consumes it.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A converger needs an authority the seam cannot resolve from the keys
   the session stamped at login. The example already in sight is a
   ladder kind wanted from a remembered session. The change is then to
   `accountCeremonyContext` itself, and no second resolver is added.
2. A chain's held set has to change more than once in one run, so a
   single re-resolution after the pointer heal is not enough.
