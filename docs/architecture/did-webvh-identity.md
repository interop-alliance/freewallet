<!-- Part of freewallet's architecture docs. The map and glossary are in
     ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The did:webvh identity (per-client keys, promoted controller)

The account's stable id is a `did:webvh` whose hash-chained log lives as
`did.jsonl` in the world-readable `id` collection
(`@interop/wallet-core/webvh`). Its document is the enrolled-client roster.
Each enrolled client contributes an Ed25519 verification method under
`authentication`, `assertionMethod`, `capabilityInvocation`, AND
`capabilityDelegation`, plus its X25519 twin under `keyAgreement`. Ids are
`<did:webvh>#<multibase>`. The signing method carries `controller:
<did:webvh>`. The key-agreement method carries `controller: did:key:<the
client's signing multibase>`, a marker naming its client. Every reader pairs
a client with its key-agreement key by that marker; nothing re-derives a
twin.

One KMS-held VM (`authentication`) stands in the document, a DIDAuth signing
key the wallet invokes client-side. It is the only KMS-held key the wallet
mints. No KMS `keyAgreement` key is minted, since that relation is the
source of record for user-key wrap recipients and no server-held key may be
a wrap target. No KMS assertion key is minted either, since log appends are
authorized by `assertionMethod` membership. That relation carries standing
credentials' ladder VMs beside client signing keys.

**Update keys are client-held.** `updateKeys` carries one update key per
enrolled client; apps get none. They derive from 32-byte seeds in the
wrapped client-key record, so the server cannot extend the log. Prerotation
stays on under a carry-over commitment convention: `nextKeyHashes` commits each
client's staged key AND each active key's own hash. The resolver re-checks
every entry's re-stated `updateKeys` against the previous entry's
commitments, so without the active-key hashes no non-rotating entry could
resolve. Rotation is per-client self-rotation (`rotateWebvhUpdateKey`),
swapping only that client's key: persist the rolled seeds into the
client-key record BEFORE the log entry publishes, then finalize.
`keys.json`'s webvh block is `{ did }` only; key roles do not live
server-side.

**Conditional publish.** Every ceremony publishes `did.jsonl` as a
compare-and-swap on the ETag of the read its entry was built on, so
concurrent clients cannot silently erase each other's entries. A lost race
surfaces as wallet-core's typed `WebvhLogConflictError`, and the ceremony
re-runs on the new head (`withLogConflictRetry`). The `did.json` projection
PUT stays unconditional, since it runs only behind a won log CAS. That
projection is the only producer of `id/did.json`; the wallet assembles no
did:web document of its own, so did:web and did:webvh resolution of one
account cannot disagree. It is the whole document with its ids rewritten.

**The projection's freshness on a credential-anchored account.** A
ladder-signed entry writes `did.jsonl` alone, since the bridge delegation is
a PUT on exactly that resource. So the ceremonies a standing credential runs
do not republish the projection, and a stale one keeps naming a client or a
credential the log has struck. That is a revocation bypass for a did:web
verifier rather than lag. WAS authorization is untouched, since the server
resolves a Space's controller out of `did.jsonl` and reads `did.json`
nowhere
(`decisions/0018-did-web-projection-refreshed-by-the-annex-writer.md`).

Three writers close it. The removal ceremonies PUT the post-removal
projection under the still-standing enrolled client's own root authority
immediately before their removal entry (see "The forget affordance"). A
ladder-branch ceremony that strikes an inventory -- a client disconnect, a
credential retirement, a recovery-code revocation -- PUTs it immediately
before its own entry too, through the account Space's `id` collection under
the visit's generation delegation, the store resolving that delegation at
each use. A failed PUT is warned and the entry still publishes, since a
projection under-listing a key the log still carries is the safe residue.
And every transient visit runs wallet-core's `ensureDidWebProjection`, which
re-derives the projection from the resolved log and republishes only on a
difference, invoking under the generation delegation. That delegation
targets the account Space's items subtree, which covers `id/did.json`, so no
bridge is widened.

The ensure's write is ordered twice over, since a difference alone does not
say which side is stale. It re-resolves the log under the visit's pins and
writes only if the refreshed derivation still differs, and the PUT is a
compare-and-swap on the ETag of the read it was based on. The window that
remains is between a ladder-signed entry and the next visit that runs the
ensure. A self-enrollment's add entry leaves the fail-closed
direction instead, a projection under-listing a client the log has. The
projection carries no signature and no chain, so a host may freeze it or
serve a different body per verifier; did:webvh resolution is the answer to
that.

**Log continuity within a session.** Resolving the world-readable log is
one-shot verification, and a valid PREFIX of the real log passes it: the
SCID, the DID check, the entry proofs, and chain verification all hold on a
prefix. A ceremony built on one would republish erased enrollments and
undone revocations. So every `verifyAccountLog` read carries
a chain-head pin (`persistence.logPins`, `@interop/vh-resource-log`'s keyed
`ResourceLogPinStore`), and a served log that is a rollback, a fork, or an
SCID or method switch against the pinned head is refused
(`ResourceLogContinuityError`). The pin is established at the visit's first
contact and advanced only by a log verifying past it; it never regresses.
One keyed store serves every log this session reads, under a per-log slot
key wallet-core derives of the form
`space/<spaceId>/<collection>/<resource>`, so two logs cannot clobber each
other's pin. The slot key is host-free, so a log served from a claimed new
host is checked against the pin already held. Every encrypted collection's
descriptor log takes a slot of its own
(`space/<spaceId>/<collectionId>/meta/log`).

The pin is a property of the store rather than an argument of the
ceremonies. Every did:webvh store this wallet builds carries
`persistence.logPins` under the slot for the log it serves, and a store
cannot be built without one. So the pin store exists BEFORE the first
account-log read: a login builds its persistence ahead of the keyring fetch,
and a caller whose own reads precede the login builds the persistence itself
and hands it in. The one read left on a fresh per-call store is the
`/recover` page's locate probe.

The pin store is in-memory on both persistence strategies
(`decisions/0012-no-durable-continuity-pins.md`). Continuity is checked
within a session and not across sessions. One login makes many log reads,
and the pin catches a host serving inconsistent versions across them.
Nothing carries a pin from one visit to the next, on any browser, so
remembered and transient sessions have identical continuity properties. The
successor to a pin is witnessing, which this wallet does not consume.

The bound is a visit's first read: a prefix served to a fresh visit is not
detected. That visit sees a stale document view, a revoked client still
listed or a retired credential still standing, and a rotation against it can
re-wrap the fresh user key to a client the account has revoked. That takes
host malice plus a previously-revoked client colluding. Against a passphrase
account the same malicious host can grind the credential offline anyway.

The pin rides the verified-log memo (`src/session/verifiedLog.ts`), the
recovery flows' direct reads, and the enrollment completion's first contact;
the login page renders the refusal (`auth.errors.accountLogContinuity`). A
`rollback` may be nothing worse than replication lag: nothing rolled back is
adopted, and a caller with a cached document view may carry on.
Ceremony-path `did.jsonl` reads also check the resolved DID against the
account pointer (`expectedDid`, which `verifyAccountLog` checks itself).
That is what refuses a mirror, since the did:webvh id embeds the Space id
and a mirror under a freshly minted Space id resolves to a DIFFERENT DID.
Login-time provisioning stays non-fatal, but a non-`rollback` refusal is
logged as an error and later account-log reads in the same login surface it
to the user.

**The Space-to-DID mapping.** One browser-local continuity artifact outlives
the visit, and it is not a pin: the account DID a data Space's log published
as, recorded by the client that published it (`saveAccountDidForSpace` in
`src/lib/sessionKey.ts`). It records what this browser did rather than a
version some host served. A signup torn between the publication and the
account-pointer backfill heals at a later login whose pointer still names no
did:webvh, and this mapping lets that heal state an `expectedDid` anyway.
Account deletion clears it through the shared wipe enumeration below.

The deletion ceremony runs from any session type. It re-derives the
credential fresh at its own confirm step rather than trusting the live
session's cached key, so a session held by anyone but the credential's owner
cannot complete it. A remembered session stops background replication and
closes the local replica first, so replication cannot race the local wipe.

Discovery comes next. The walk verifies the account log under the visit's
pins and requires this credential's ladder VM in the resolved document,
refusing the whole ceremony when the document anchors none. It reads the
unlock-methods registry under the visit's own authority and refuses on a
failed read, since a partial walk would strand Spaces the account can no
longer name. A registry sealed to a superseded user key is repaired in place
instead. A pending-shaped passphrase entry, and a standing credential the
registry never recorded, each name an unlock Space the walk cannot reach, so
each is reported as a residue and left for that credential's own next login.
Discovery also enumerates every `#DelegatedClients` value the account log's
history ever published, unioned with the acting record's own sibling target,
since a superseded pointer entry is append-only and its Space can still be
live. Every Space discovery finds gets its own probe, so the deletes that
follow can read a 404 as already-deleted rather than as a masked refusal.

The walk then deletes, in this order: the auxiliary annex Space(s); the KMS
keystore, when one exists, through its own route once that route exists
(skipped and reported until then); the sibling unlock Spaces other than the
acting credential's; the account Space; and, last, the acting credential's
own unlock Space, before the local wipe. Everything runs before the account
Space because every ladder-signed delegation the walk mints verifies against
the account document, which lives there.

Each delete but the last two rides a capability minted immediately before
its own DELETE and used once. On a transient session that is a ten-minute
DELETE-only child of the Space's own root, delegated to and invoked by the
ladder VM's own bare did:key re-derived at the confirm step, which resolves
from its own bytes and so outlives every Space the walk deletes. A sibling
unlock Space goes instead through a freshly minted DELETE-only child of that
entry's management zcap, the parent's `invocationTarget` copied verbatim. A
remembered session root-invokes the account and annex Spaces and signs a
sibling's child with the enrolled client's own account key.

Five states on a sibling refuse locally before anything is minted and are
reported as named residues rather than refusing the run or skipping in
silence: an entry recording no management zcap, one already expired, one
naming a delegatee this session cannot act as, one whose target is not this
deployment's URL, and one whose recorded actions lack the verb the child
would carry. That credential's own next login
re-delegates. A management zcap allowing DELETE but not GET leaves its Space
deletable and unprobeable, so the walk skips the probe and grades that
delete from an unknown discovery rather than refusing the whole run. A
sibling's DELETE is its REMOTE half alone, since every other credential's
browser-local state waits for the local wipe past the pivot, so a run that
refuses at the account Space has not quietly un-remembered this browser.

A `not-found` from any of these deletes is the server's masked 404, absent
OR unauthorized. Every discovery probe is status-exact for the same reason:
a read that resolves empty for a 404 and for an unparsable success alike
could record a live Space as absent, and an absence is what lets a later 404
grade as a deletion. The server admits the ladder-signed child under the
client-annex clause's third predicate: a ladder-signed delegation whose
target is a bare Space URL equal to its parent's unchanged (the parent a
delegated capability or the Space's own root) and whose action set is
exactly `['DELETE']` or exactly `['GET']`. The clause's locked property:
every ladder delegation either needs a loud companion entry to resolve, can
only write a log, or is a target-exact single-verb read or delete of one
Space of the delegator's own account. That delete is the one ladder
authority whose exercise leaves no record.

The account Space's delete is the pivot: past it the account is gone for the
acting credential, and nothing after it can fail the run. A 404 on a Space's
first delete counts as already-deleted only when discovery's own probe of
that same Space already returned 404 and the account log independently
corroborates the absence, or when this run already sent that same delete and
got a success. Every other 404 fails the run. Every phase before the pivot
refuses the whole run on failure, so a torn annex-Space or sibling-Space
delete leaves the account alive, enterable, and re-runnable. The acting
credential's own unlock Space is the one exception: past the pivot, a failed
delete there is retried in-run and then reported rather than failed, since
reporting failure would tell the user the account survived. The next login
with that credential offers to remove it instead. A wipe failure past the
pivot is accepted the same way, naming the surviving replica as an
unverified residue.

A re-run over an account that is already gone -- a second tab, or a re-click
after a delete whose 2xx was lost -- meets a 404 from the account log at
discovery and carries straight to the acting credential's own unlock Space
and the local wipe. That arm reads no unlock-methods registry and never can,
since the registry lived in the account Space the first run destroyed. Its
local wipe is narrowed to the acting credential, and it says so: the walk
passes `registryUnread`, the executor reports the failed
`unlock-methods-registry` stage, and the outcome carries
`localWipeNarrowed`. The result is `deleted-unverified` rather than
`deleted`, and Settings names the other sign-in methods whose browser-local
state may still stand, offering the browser-scoped wipe.

**The shared wipe enumeration** (`src/session/wipe.ts`) is the one list of
browser-local state an account leaves on a browser, and the one executor
that deletes it. Account deletion, the guest wipe, and the forget ceremony
consume it. It is snapshot-first, so every target derives from the live
session before anything is deleted. What it enumerates:

- The client-keyed families (the unlock-methods cache, the passkey-safety
  notice, the replica-database prefix, the local-mode cache scope), derived
  from this browser's own client did:key rather than the account controller.
- Each unlock method's unlock-local state, derived from the registry walked
  across every method and always including the session's own login
  credential. A registry read lost to a transient server error narrows the
  enumeration to the other methods and is reported on the wipe outcome
  (`unlock-methods-registry`), instead of leaving this browser's client-key
  record behind a wipe that reads clean.
- The Space-to-DID mapping, keyed by the account Space id.
- The per-account localStorage families: the descriptor and meta caches
  under both scope schemes.

No continuity pin is enumerated, because none is stored (see "Log continuity
within a session"). Cross-tab teardown precedes the replica delete, a
broadcast asking sibling tabs to drop open handles, and completion is
verified by re-probing rather than resolved while blocked. Global UI prefs
stay out; the global `writerId` clears only on the forget grade.

`indexedDB.databases()` is a discovery and verification aid rather than the
deletion gate: the session and replica databases go by known name whether or
not the engine can enumerate. A deletion the executor could not confirm, or
a replica prefix `databases()` alone would have named, is reported on the
outcome's `unverified` list rather than counted as a clean wipe.

Limits no enumeration reaches: deleted IndexedDB data stays forensically
recoverable, plaintext `public-credentials` rows included; the CHAPI popup's
partitioned third-party buckets are unreachable from any top-level wipe; and
the mediator-origin (authn.io) handler-registration bit records that a
wallet was used in this browser. Only clearing the browser profile removes
those. One more, on the client axis: a SIBLING enrolled client's replica and
caches survive a deletion run from a transient session, since the
client-keyed families are named by the acting session's own client did:key
and a sibling's lives only inside its own sealed record. What survives is
ciphertext with no key, but it survives.

**The forget affordance** (`src/session/forget.ts`) removes this browser
from an account, in two grades split by whether the unlock credential is in
hand.

From a live remembered session (Settings > Connected wallets, the current
client's row) it is the **forget ceremony**, wallet-core's
`forgetEnrolledClient`; the stage order is canonical in wallet-core's
ARCHITECTURE.md. The user key rotates off this client's roster wrap and
every encrypted collection re-epochs, both under this client's
still-standing authority, the self-forget inversion of the revocation's
document-edit-first order (wallet-core decision 0008). Then ONE atomic
ladder-signed removal entry through the login credential's bridge takes the
client's whole document inventory out. Immediately before that entry
publishes, the post-removal did:web projection is PUT through this client's
own root-authority `id` store, which is required (see "The projection's
freshness on a credential-anchored account"). The idempotent
already-forgotten path writes no projection at all, and the next transient
visit's ensure is that projection's mender. Only then does the
local teardown run: background replication stops first, so the poll timer is
not left driving a re-sync against a replica the next stage deletes, then
the local wipe (`clearWriter: true`, the wipe's one writerId consumer).

Wipe-last is the tear story. A run torn before the entry reads as "not
forgotten", and a re-click resumes. A run torn between the projection PUT
and the entry leaves `did.json` omitting a client the log still lists, the
fail-closed direction, and the re-run re-PUTs it. The other direction,
removal published but wipe torn, is caught at the next login by the
**forgotten-browser detector** (`assertClientStillEnrolled`): an enrolled
client-key record (its user key present) still here while the cleanly
verified account document no longer lists this client's verification method.
The detector finishes the wipe from what the keyring hit alone derives and
surfaces "this browser's access was removed" in place of raw authorization
errors. It persists nothing.

The detector sits past a record-to-account cross-check. An enrolled-shape
record whose stamped `pointerDid` names a DIFFERENT account than the unlock
record points at is stale residue rather than a forgotten browser: a prior
account under a reused passphrase, gone server-side, so no wipe ever touched
this browser. The stale wipe clears what the record alone derives (the dead
account's replica and caches, and the credential's whole unlock-local
state), and the login re-routes once as a record-less browser without
reaching the detector. A pending-shape record is spared for the
resume instead (`decisions/0007`), whose published-then-removed branch hands
the removal case back to the same wipe.

The ceremony needs the standing members the login stamped on the profile
(`profile.standingUnlock` beside `profile.ladderSeed`). It re-seals the
unlock-methods registry to the rotated user key while this client still
invokes, since surviving readers would otherwise find it sealed to a retired
generation. It writes no unlock record: every record's frame proof, bridge,
and sibling delegation are signed by its own credential's unlock identity
and ladder VM, which this removal entry does not strike. It refuses the
account's last enrolled client with wallet-core's name-stable
`LastEnrolledClientForgetError`.

That refusal routes to the **last-client transition**: the same
`forgetThisBrowser` entry with `lastClient: true`, chosen from the listing
and confirmed against transition-stating copy (a stale listing's refusal
flips the dialog to that copy for a second confirm). It runs wallet-core's
`forgetLastEnrolledClient`, the two-entry ceremony that lands the account
client-less and ladder-anchored (wallet-core decision 0004). Its stages, in
order:

1. The ladder VM's install entry, while the client's inventory stays.
2. The roster rotation off this client's wrap: ladder-signed and anchored at
   the install entry (the ceremony-tail license's inventory-changing
   version), but HTTP-invoked under the still-standing client. The
   roster store is the session store with the ladder VM's signer, so the
   roster head stays signed by a key the post-removal document lists. The
   ceremony anchors that store's controller view itself
   (`setMinimumControllerVersion`): at the pre-transition head for its
   opening probe, and at the post-install head for the rotation.
3. The collection fan-out.
4. The forced replacement of the embedded generation delegation with a fresh
   ladder-signed one, and the revocation of every still-unexpired
   ladder-signed delegation the annex history embedded.
5. The login credential's own record (`rebindLoginCredentialRecord`, the
   ceremony's required `onBeforeRemoval` seam): its bridge delegation and
   `delegatedClients` sibling re-signed by the ladder VM, the record
   re-sealed through the keyring hit's re-bind closure, and the registry
   pair refreshed in this client's last window of registry authority. It is
   the only unlock record the transition writes.
6. The removal entry, with the post-removal did:web projection PUT through
   this client's root-authority `id` store immediately before it publishes.
7. The local teardown: replication stopped, then the local wipe.

Stages 2 through 5 precede the removal entry because the removed client's
signatures rot there, and on a client-less account no remembered login's
refresh block will ever heal them.

The transition's refusals:

- A registry the transition cannot read refuses up front, since the pending
  check below is computed from it, as does a session whose hit carried no
  re-bind closure.
- A pending-shaped passphrase entry refuses up front with
  `PendingRetirementForgetError`: one recording an unlock key-agreement key
  that is not the credential the record at its unlock Space is sealed to,
  the residue of a passphrase change torn before its retirement landed. The
  record itself is the detector, since an entry naming another credential is
  also what a superseded passphrase's own login sees on a healthy account.
  Its mender is the torn-retirement repair, which runs on a transient login
  too, so the next login with a different standing credential clears it.

Readers settle a record's proof against `currentAccountRecordSigners`, the
enrolled clients' signing keys plus the ladder VMs the document lists.

From the login page's authenticity and continuity refusals (reachable from
passkey failures with no typed passphrase, reset between attempts) it is the
**no-unlock-material grade**. Nothing can be derived or signed, so no
ceremony runs. The wipe is whole-database and browser-scoped: every replica
database, the session database, and the per-account localStorage families,
with the cross-account blast radius stated in the confirm copy. Each
account's standing document client remains, unflagged anywhere, and the copy
points at the Connected wallets disconnect from a logged-in client. A
never-remembered browser is told it holds nothing to delete.

**Controller promotion by ordering.** The Space id is an independent random
identifier minted at signup (`mintSpaceId`) and carried in the account
pointer, rather than a hash of any controller: the did:webvh id embeds the
Space id, so a derivation would be circular. Unlock Spaces keep their
`hash(unlock did:key)` addressing, a discovery convention rather than an
identity. That deterministic unlock address is an accepted existence oracle
for passphrase guessing; the bound is KDF strength rather than placement.
The DID's embedded Space id need not equal a controlled Space's id, since
one did:webvh may control several Spaces on the host.

Every WAS signup bootstraps the Space under the ladder VM's bare did:key
inside the credential-anchored establishment, publishes the log, and PUTs
the Space Description carrying `controller: <did:webvh>`, before any
enrolled client exists. `StorageManager.ensurePromotedController` is the
login-time healer: it swaps the live session's signing to the promoted keyId
and re-runs the promotion PUT when a session finds it missing. Only a no-WAS
deployment's plain genesis promotes on that path from scratch. From then on
the server resolves the controller by reading and fully verifying the log
out of its own storage (SCID-pinned, hash chain, prerotation, update-key
signatures), and authorizes by the current-key-set rule (see Glossary).
