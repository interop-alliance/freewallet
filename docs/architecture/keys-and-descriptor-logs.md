<!-- Part of freewallet's architecture docs. The map and glossary are in
     ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The user key wrap-set roster (`key-map/user-key.jsonl`)

The user key is recipient zero of every encrypted collection. Its one remote
home is a roster in the private, capability-gated `key-map` collection,
outside the synced collections, with no local replica and no replication.
Its state is a `CollectionEncryption` descriptor, and the roster's current
key epoch IS the current user key. The epoch id is the user key's did:key,
and the epoch secret (its raw 32-byte key) is wrapped once per enrolled
client, to that client's identity key-agreement key, the X25519 twin of its
did:key. The roster delivers key material and sources no authority. Each
client caches the user key in its own client-key record, and the epoch stamp
marks that copy stale.

The roster is log-governed: the resource log `key-map/user-key.jsonl`.
wallet-core's `userKeyRosterDescriptorStore` (`@interop/wallet-core/keys`)
exposes it as a descriptor store over verified-head reads and signed
appends. `src/session/rosterStore.ts` holds two builders:
`accountRosterStore` for callers with no session profile, and
`sessionRosterStore` for a live session, which resolves the controller view
through the profile's verified-log memo so a ceremony that just extended the
account log anchors its appends at the post-edit head. Both pin on the
session's own store (`persistence.logPins`), under the slot wallet-core
derives from the Space id.

Provisioning initializes the roster idempotently with the account's existing
user key as the first epoch. That stage runs after did:webvh provisioning,
because the log's entry proofs anchor in the published account document.
Login makes one direct read before the storage clients are built, gated on a
promoted account pointer. It confirms the cached user key current, or, on an
epoch mismatch from another client's rotation, unwraps the fresh key, adopts
it, and persists it into the client-key record. A failed persist does not
fail the login, since the adopted key authenticated against the verified
roster; the session proceeds on it and the login page shows
`session.userKeyPersistFailed`. A failed persist must not read as an offline
start, so the adoption callback's throw propagates rather than being
swallowed.

Three client-side guards are load-bearing against a tampering host.

First, the resource log. Roster state is adopted only from a verified head.
Its entry proofs must be signed by keys the independently verified did:webvh
document lists under `assertionMethod` at the anchored version
(`ResourceLogIntegrityError`). Its chain-head pin refuses rollbacks, forks,
and SCID or method switches within the visit (`ResourceLogContinuityError`;
see "Log continuity within a session" in did-webvh-identity.md). At login the `rollback` reason is
the carve-out, degraded to the transport class instead of locking the user
out of a healthy account. The session keeps the cached user key and adopts
nothing rolled back. `fork` and the SCID or method switches stay
session-refusing.

Second, the visit's latest-seen roster epoch (`memoryEpochPinStore` in
`src/session/persistence.ts`). A served roster behind that pin is refused
(`UserKeyRosterContinuityError`), with no rollback carve-out, since a
chainless epoch pin cannot tell a rollback from a fork. The log pin does not
cover a chainless value, so this guard stands on its own.

Third, at rotation time, a recipient resolver backed by the locally verified
did:webvh document. It drops any roster entry with no `keyAgreement`
verification method marked for that client, so a server-injected entry never
receives a wrap and sits ignored.

## Per-collection descriptor logs

Every encrypted collection's `encryption` descriptor, the key-epoch roster
carrying its recipients, is governed by a resource log of its own at the
collection's `meta/log` sub-resource. wallet-core's
`collectionDescriptorLogStore` is the store over it. Reads resolve to the
verified head, writes are signed appends, and a create is the log's genesis.

The verification is the roster's. Entry proofs must be signed by keys the
verified did:webvh document lists under `assertionMethod` at the anchored
version, and each log pins its chain head in its own slot of the visit's
keyed pin store (`space/<spaceId>/<collectionId>/meta/log`; see "Log
continuity within a session"). The form buys client-side detection of
descriptor tampering. A recipient the host inserts is an entry either absent
or signed by a key the document does not list. The server's own monotonicity
checks remain the host's promise about itself.

The placement is the collection's own URL subtree, so the read capability a
share grantee or a connected app already holds covers the log, with no
second grant and no capability over the account's `key-map` collection.
Being a sub-resource rather than a Resource keeps the log out of listings
and the changes feed, and outside the encrypted collection's envelope rule,
so it stays plaintext JSON Lines and replication never ships it as a row.

**The wallet writes the log alone.** The server derives the Collection
Description's `encryption` member from the log head. No ceremony writes that
member, and no `configure` call carries it forward. Provisioning creates an
encrypted collection bare (`WASRemoteStore.ensureGovernedCollection`, a
guarded create), and the epoch[0] install through the collection's own store
is the genesis that declares it governed (`ensureIndexedFirstEpoch`). A
re-run adopts the standing log, and a lost create race resolves on the
collection that stands, so exactly one epoch[0] ever exists per collection.
A collection already carrying a client-written `encryption` member cannot be
governed, and provisioning refuses it up front. The wallet opens a governed
log by its placement rather than following a pointer in the Description.
Every recipient change is one signed full-state append: a share, an unshare,
an App Connect provisioning, an app revoke, and each collection's rotation
in the user key cascade.

**The two builders** in `src/session/collectionLogStore.ts` mirror the
roster's pair: `accountCollectionStores` for callers with no session
profile, and `sessionCollectionStores` for a live session, which reaches
each collection through the remote store's handle, so every request rides
the capability the session holds at call time. Both return a lookup keyed by
collection id and resolve the controller view once per lookup.
`sessionCollectionDescriptorSource` is the read-only counterpart the storage
layer reads descriptors through, held beside it by `StorageManager` as
`DescriptorLogs { source, storeFor }` when the account pointer names a
did:webvh.

**Which key signs** follows the session kind. A remembered session signs
with the enrolled client's own account key. A transient visit's per-visit
key stands in no account document, so it signs with the login credential's
ladder VM, read off the profile at each call since a passphrase change
restamps the seed. A descriptor log admits a ladder-signed append on
`assertionMethod` membership alone, since the ceremony-tail license binds
the user key roster log and not these, so no descriptor-writing ceremony
refuses on the kind of session it runs in.

Three ceremonies name their signer instead. The forget ceremony and the
last-client transition sign the collection appends with the login
credential's ladder VM, since their removal entry strikes this client's own
key and an append that key signed could not seal the logs behind it. The
passphrase change signs with the surviving credential's ladder VM, the
retiring credential's VM leaving the document in the same edit.

**The cascade is these logs' sealing pass.** A document edit that strikes an
`assertionMethod` key leaves every governed log needing an entry at or past
the post-edit version. So every sealable collection store takes the
ceremony's post-edit controller view as its minimum controller version,
before that collection's first append. A store on a stale view would anchor
its rotation ahead of the edit and seal nothing, and a ladder-signed append
there would be refused for naming a version the edit is not in. A rotation
that appends
nothing still seals. Which collections it covers is decided from the same
logs: the Space listing only enumerates collections, and whether one is
encrypted is answered by reading its own governing log, so a host omitting
the derived `encryption` member cannot keep a collection out of a rotation.

**The read path and the cache.** A descriptor is the verified head of its
collection's log, read at login and on the unknown-epoch refresh. The
browser-local descriptor cache holds the last head this browser verified,
and three cases are handled by error name. A verifier refusal (integrity, or
a continuity refusal other than a rollback) throws rather than falling back
to the cache, so a descriptor is adopted only from a verified head. A
transport failure serves the cached copy, and a rollback refusal falls
through to it the same way. That copy never seeds the
visit's pin, since localStorage is same-origin writable and a forged pin
could lock the user out. A served head listing fewer epochs than the cached
copy is warned about and then written (`regressionWarningCache`), since a
log behind the cache looks like replication lag. The in-memory strategy has
no cache, so a transient visit offline reads nothing.

A session with no did:webvh to verify against holds neither half. Its
descriptors come from the cache alone, no descriptor write can run, and
collection key-epoch provisioning is skipped with a warn, since each
epoch[0] is a log genesis anchored in the account document.
