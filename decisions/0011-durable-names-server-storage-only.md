# 0011: "Durable" names server-backed storage only

- Status: accepted
- Date: 2026-08-27
- Driving work: the domain-modeling pass run after
  `decisions/0010-durable-login-is-not-a-mender-trigger.md`. Reframing an
  enrolled client as a cache exposed the word "durable" as carrying three
  meanings at once, one of which is false.
- Affects: ARCHITECTURE.md's Glossary and prose, the persistence seam in
  `src/session/persistence.ts` and its ~43 call sites, wallet-core's
  client-forget names, and every gated design that reasons about what a
  torn stage can detect. No wire contract: no field name, log entry kind,
  or record layout changes.

## Context

Freewallet's default session is transient, because credential-only entry
is the steady state. Browsers get cleared and phones get lost, so an
enrolled client is not the account's durable state. What persists is the
unlock credential, the world-readable account log, and the server-held
roster and records. An enrolled client is an optimization over those: a
local replica plus a document-listed key that saves a self-enrollment.

The word "durable" predated that framing and was used for three different
things.

First, bytes that a torn ceremony stage can rely on having survived --
"detects its own completion from durable state", "durably written BEFORE
the Space is created". This is the ceremony vocabulary, and it is the
sense the persist-before-publish invariant is stated in.

Second, the session persistence seam: which storage a session may write to
(`durableSessionPersistence`, `isDurableSession`, `DurableSessionPersistence`).

Third, a keyring-bound login on a browser holding a client-key record --
"a durable login", "a durable client", "the durable login chain". This is
the sense decision 0010 is about.

Two problems followed. The second and third senses are not the same set: a
guest session takes the non-transient seam variant but is not a login of
that kind, which the code already knew and wrote out by hand as
`!isGuest && isDurableSession(persistence)` at three sites in
`initSession.ts`. And the first sense was itself split. Counting the 26
uses in ARCHITECTURE.md, about nine name server-backed state and the rest
name IndexedDB or localStorage -- the client-key record, the unlock-local
state, the replica database. The continuity pins were counted on that side
too, and `decisions/0012-no-durable-continuity-pins.md` has since removed
them. IndexedDB survives a reload; it does not survive an eviction, a
cleared profile, or a lost machine. Calling it durable asserts exactly the
permanence the transient default exists because it cannot assume.

The root was definitional. The Glossary's Ceremony entry read "an ordered
sequence of durable writes across the account's systems (the account log,
the roster, the unlock records, collection epochs, local storage)",
placing browser storage inside "durable writes" by definition.

## Decision

"Durable" names server-backed storage, and nothing else.

Storage has three tiers, and prose names the tier it means:

- durable -- persisted on the WAS host. Survives a cleared browser, an
  evicted origin, and a lost machine.
- browser-local -- IndexedDB or localStorage. Semi-durable: survives a
  reload, not an eviction or a clear.
- in-memory -- dies with the tab.

Neither a session, a client, a login, nor a browser is ever called durable.
Those take their own vocabulary:

- session persistence, the axis, with variants named for the tier each
  reaches: browser-local and in-memory. The typed object carrying it is
  the persistence strategy, at `session.persistence`.
- remembered / transient for a login and its session; remembered /
  non-remembered for the browser state that decides which one runs.
- enrolled / transient for clients.

The sense-three predicate is named as the conjunction it is:
`isRememberedSession` = `!isGuest && isBrowserLocal(persistence)`,
replacing the three hand-assembled sites.

One design-gate check follows. Every write before a ceremony's pivot names
its storage tier. A browser-local pre-pivot write owes an answer for a
cleared or evicted browser, not only for a tab death. The two current
cases differ: the credential-anchored genesis writes its unlock record
server-side before rung 0 publishes, and loses nothing to an eviction; the
self-enrollment writes the pending client-key record to IndexedDB before
the add entry publishes, and an eviction in that window leaves nothing for
the resume to resume from. The code handles the second (an unresumable
record is discarded and the browser routes record-less), but the shared
word made the two orderings read as equally strong.

## Rejected Alternatives

- Keep "durable" for the persistence seam on the grounds that IndexedDB is
  durable storage in the database sense. This is the reading that produced
  the problem. In a wallet, the threat is a cleared profile and a lost
  machine, and against those IndexedDB is a cache. The database-literature
  sense of the word is not the sense a reader of these ceremonies needs.
- Use "remembered" for the persistence strategy as well as the login, one
  word for the whole non-transient side. It reads well and matches the
  forget ceremony, but `isRememberedSession(persistence)` would return
  true for a guest, who is not remembered in the sense every existing
  `rememberBrowser` and `AlreadyRememberedError` identifier uses. Naming
  the strategy by the tier it reaches dissolves that: a guest session is
  browser-local, which is simply true.
- "Resident" for the login sense. Cleaner grammar than "remembered", but
  new vocabulary with no established inverse, where "remembered" already
  has one: the forget ceremony. You do not forget a durable thing.
- Invent a word for clients. Unnecessary. ARCHITECTURE.md already says
  "enrolled client" as its primary term and "durable client" was an
  intruding synonym, so the fix is subtraction.
- Fix the prose and leave the identifiers. It would leave docs and code
  disagreeing on the one word the ceremony arguments turn on, which is how
  the overload spread in the first place.

## Consequences

- ARCHITECTURE.md's Glossary gains Durable, Browser-local, In-memory,
  Session persistence, Persistence strategy, Remembered browser, and
  Enrolled client; Session durability is retired. Client states that a
  client is a cache and enrollment an optimization. Ceremony names the
  tier and carries the pre-pivot tier check. Tear mending and Repair say
  remembered-login sweep.
- About 50 further uses in ARCHITECTURE.md prose are re-worded to the tier
  they mean, and wallet-core's 173 uses need the same triage.
- Freewallet renames the persistence seam: the strategy variants become
  browser-local and in-memory, the discriminant becomes
  `persistence.storage` with `STORAGE_INDEXEDDB` / `STORAGE_IN_MEMORY`
  (values unchanged), and `DurableSessionRequiredError` follows the axis.
- wallet-core renames its client-forget surface: `forgetDurableClient`,
  `forgetLastDurableClient`, `LastDurableClientForgetError`, and the two
  result types take "enrolled". Greenfield, no compat shim; it needs a
  release, and freewallet's call sites move with it.
- Decision 0010 reads the same with "remembered-login sweep" in place of
  "durable-login sweep".
- `persistence` moves from `profile` to `session`, where the rest of the
  session-lifetime scaffolding lives. `ControllerProfile` is documented as
  a cryptographic identity bundle, which a storage policy is not. Call
  sites taking a bare profile take an explicit parameter or a session.
- The persistence strategy's `clientAnnex` member -- the annex DID and
  generation delegation, which are identity rather than storage -- is
  tracked separately for a move onto the profile. The three-tier model
  makes the current fusion of storage tier and signing identity a
  correlation rather than a rule, and the designed step-up ceremony
  (in-memory storage, enrolled-client authority) is where it breaks.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. Browser storage gains a durability guarantee a wallet can rely on
   against a cleared profile, making the two-way distinction between
   durable and browser-local no longer load-bearing.
2. The persistence strategy stops being the only thing deciding a
   session's storage tier -- a session mixing tiers per family would need
   the axis re-derived rather than renamed.
3. A wallet in this ecosystem holds its account state locally with no
   server-backed home, at which point "durable" would name a tier that
   deployment does not have.
