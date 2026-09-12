<!-- Part of freewallet's architecture docs. The map and glossary are in
     ../../ARCHITECTURE.md; this file holds one topic in full. -->

# CHAPI integration

CHAPI (Credential Handler API) lets a website trigger a credential
request/store via a browser pop-up without the site ever seeing the user's
wallet passphrase.

Flow:

1. On login, `registerWallet()` (`src/lib/registerWallet.ts`) registers
   `/wallet/get` and `/wallet/store` as this wallet's handler URLs with the
   CHAPI mediator (`authn.io`).
2. A third-party site's `navigator.credentials.get/store()` opens
   `/wallet/get` or `/wallet/store` in a CHAPI-managed popup iframe, outside
   the normal app shell and `ProtectedRoute`.
3. The popup page intercepts the CHAPI event with
   `receiveCredentialEvent()`, shows a minimal login form, initialises a
   full `Session` in-popup, then returns the result to the site with
   `chapiEvent.respondWith(...)`.

The CHAPI pages (`src/pages/chapi/`) are not wrapped in `ProtectedRoute` and
do not use the main app layout.

**The DIDAuth holder follows the request.** A `DIDAuthentication` query may
carry `acceptedMethods`. `presentationSignerFor`
(`src/lib/walletRequest/composeVP.ts`) reads it and picks the holder in the
order `webvh`, `web`, `key`
(`decisions/0016-didauth-holder-dispatches-on-accepted-methods.md`). An
unconstrained request takes the did:web projection id when the session can
present it, and the client did:key otherwise.

A session can present the account's did:webvh or did:web form when its
pointer names a did:webvh and the resolved account document lists a
verification method it holds a signer for under `authentication`. That is
settled against the verified-log memo, read as a cache: no fetch, no throw,
and false when the memo is cold. A stored key map is not evidence, since the
map is written on paths that do not edit the document. The did:web arm's
holder is the projection id (`didWebFromSpace`). A remembered session signs
an account-form holder with the enrolled client's own account key. The
KMS-held key signs where no client key exists.

Refusal splits by position. Pre-login, the `didAuthMethodSupported` gate
judges deployment capability (`key` always, plus `web` and `webvh` when a
KMS is configured), so a method no session here could ever present is
refused before a password box renders. After login, a session that can
present none of the listed methods gets the block screen in place of the
consent panel.

**The get popup's pre-consent matrix runs before login.** It lives in
`src/lib/walletRequest/getRequest.ts` as plain functions, the way
`storeRequest.ts` carries the store popup's check and `externalRequest.ts` the
interaction-URL page's, so the matrix is exercisable with no DOM. Each refusal
raises `GetRequestRefusedError` carrying a `GetRequestRefusal`, which the page
sets as its `BlockReason` and renders from the matching `chapi.get.*` copy
cell. The order is: an origin this wallet cannot attribute
(`unattributedOrigin`), a body carrying no readable query and a body the
classifier rejects (both `malformedRequest`), a `DIDAuthentication`
constrained to DID methods no session on this deployment could present
(`unsupported`), and a `domain` that does not match the attested origin
(`domainMismatch`). The origin cell is read ahead of the request body, so an
unattributable request is refused before the popup opens a VC API exchange on
the requester's behalf. The consent screen's requester label and the Login
activity's `origin` both come from that attested value, and
`requestingOriginOf` returns undefined for a value that does not parse as well
as for one whose origin is opaque (`mailto:`, `data:`, `file:`, which
serialize their origin as the string `null`). Consent therefore renders with a
requester to name rather than with a blank chip. A path that has no attested
origin at all states that fact instead, on the model of the interaction-URL
page's `EXTERNAL_REQUEST_ORIGIN` marker.

**The store popup refuses a DID-Auth request before login.** A
`navigator.credentials.store()` may name a VC API exchange that opens with a
DID-Auth request. `checkStoreDIDAuthRequest`
(`src/lib/walletRequest/storeRequest.ts`) runs on the reply, before the
passphrase form renders, and each refusal raises `StoreRequestRefusedError`
with its own copy under `chapi.store.refusals.*`. The order is: the exchange
asked for something other than DID Authentication alone
(`unsupportedRequest`); the request states no `domain` (`noDomain`); the
`domain` does not match the attested requesting origin (`domainMismatch`);
the presentation endpoint is on another origin (`foreignDelivery`). A
`domain` is now required rather than defaulted to the exchange origin, and
it is compared by `domainMatchesOrigin` against
`requestingOriginOf(event.credentialRequestOrigin)`, the same predicate the
get page uses. Delivery goes to the exchange's own origin alone, the
endpoint being `interact.service` when the reply names one and the exchange
URL otherwise. Together these refuse a site that relays a third-party
verifier's challenge and collects the proof. Consent stays one gesture: the
login form carries a notice naming the exchange host and saying that logging
in proves the wallet identity to it (`chapi.store.didAuthNotice`), and the
passphrase submit is the approval.

**The popup follows the browser's routing.** It runs the same post-KDF
routing every login runs (`routeUnlockLogin`, see "Session persistence" in session-persistence.md),
with the Storage Access API handle threaded in as the record probe's `idb`
factory. A denied handle probes the partitioned bucket, finds no record, and
routes transient, as does every engine offering no unpartitioned-IndexedDB
request at all (Safari's and Firefox's steady state). That uniform routing
is `decisions/0009-popup-denied-storage-access-goes-transient.md`, reached
by construction rather than by a popup arm of the routing. A transient popup
session composes like any other, and its App Connect response VP holds and
signs as the visit key's bare did:key. A granted handle probes the
first-party client-key record instead, so a remembered browser proceeds as
that enrolled client.

The popup marker is a `popup` option on `loginWithPassphrase`,
`loginWithPasskey`, `sessionFromKeyringHit`, and `initSessionFromSeed`. It
gates only what the partitioning implies, and only in the remembered arm:
remote-direct storage (below), suppressed localStorage caches, and that
arm's popup refusals (the record-less branch's self-enrollment, the
pending-enrollment resume, and the login-time chain passes carrying the
guard). The Storage Access handle does not reach localStorage, so a
persisted descriptor or meta cache would be partitioned residue no top-level
wipe can reach. The popup's cache pair is therefore in-memory for the visit,
on a WAS deployment. On a no-WAS deployment the same
store is the only record of the locally minted key epochs, so a local-mode
popup keeps its persistent pair. Three chain passes carry no popup guard
today: the standing-delegation self-refresh, the ladder-rung refresh, and
the did:webvh pointer heal. Whether they should is an open decision.

Handler registration is not on the persistence axis. `registerWallet()` runs
at mount on the login page, before the routing decides, so a transient login
registers the handler too. It writes nothing to the wallet origin, since the
registration bit lives on the mediator's, and that mediator-origin bit
remains the stated limit no top-level wipe reaches.

**Remote-direct popup storage.** The popup's own IndexedDB is a partitioned
bucket no `SyncController` ever drives, so a credential stored there would
be stranded. A transient popup session is replica-less and reaches the
remote-direct backend as every transient session does. A remembered popup
session gets there by routing: every synced-collection operation goes to a
`RemoteDirectStore` (`src/stores/remoteDirectStore.ts`, selected via
`remoteDirect`, threaded from the `popup` option) rather than to the local
`BrowserStore`, which it still constructs with nothing routed to it.

That backend serves credential, history, and public-link reads and writes
straight over the remote WAS collections, with the same per-collection
ciphers the local store uses, so the envelope, id, and key-epoch logic lives
once. A listing is was-client's `Collection.documents()`, the snapshot walk
over the `changes` feed, one request per page; the feed's tombstones drop
out and a resource rewritten mid-walk keeps its latest state. A write
reproduces verbatim what background replication would have pushed: the raw
EDV envelope under its content-derived envelope-hash id, created with
`If-None-Match: *`, stamped with the same `Key-Epoch`. An unknown-epoch read
drives the same one-time descriptor refresh the local backend uses, so a
fresh-epoch credential is never dropped.

Contacts are reachable in the popup over the same path. Head rows are
mutable and updated in place under `If-Match` compare-and-swap, with ids and
epoch stamps matching what replication would have pushed, so a local replica
pulls the popup's contact edits cleanly. A delete leaves the server's own
tombstone, which the pull side maps to a removal like any other.

The remote-direct backend is selected only when a remote store is
configured. Reads gate on `StorageManager.ready()`: the local collections
being open, or nothing at all in remote-direct mode.
