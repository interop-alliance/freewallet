<!-- Part of freewallet's architecture docs. The map and glossary are in
     ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The interaction-URL request page (`/external/request`)

A request can also arrive from outside the app, with no CHAPI popup and no
attested requesting origin. An agent's `di was request-grant` prints an
interaction URL (`<exchange>/protocols?iuv=1`) plus the wallet deep link
`/external/request?url=<percent-encoded interaction URL>`. The same URL
pasted into Add Credential or scanned from a QR reaches the page too:
`resolveWalletInput` returns it as a typed `interaction-url` outcome.

The page (`src/pages/external/ExternalRequestPage.tsx`) is the
`WalletGetPage` shape minus CHAPI. It opens the exchange, classifies the
VPR, renders the storage-access consent panel, delegates through the
ordinary grant engine, and POSTs the zcap-only presentation back with the
exchange URL. The presentation is unsigned, except for a connection request
(see "The connection request" below). Its consent rows carry the same existing-collection
reading the popup's rows do, through the same hook (`useAttributedGrants`)
and second resolution pass (`attributeExistingCollections`). A collection
another requester (an app, service, or agent) created names that requester. An interaction-URL
grant that creates a collection, public or private, stamps its `generator`
with the agent's did:key as `id`, and the request's self-declared
`agent.name` as `name` when it carries one (`provisionFor` in
`src/lib/walletRequest/processZcaps.ts`). The stamp has no `origin` or `url`,
since this entry point has neither. So an agent re-requesting a collection
it provisioned reads `this-app` and gets no existing-collection note, and a
different agent reads `other` with the creator named. Every reader names an
agent's stamp by `generator.name`, else by its shortened `generator.id`, and
none looks it up in the `connections` directory.
Without a live app session it runs the ordinary login in place and
adopts it app-wide. The consent is recorded on the agent's `connections`
entry, of kind `agent` at the controller's DID, and then on a `Grant`
activity under the fixed origin marker `n/a (API request)`, as audit trail.
That sequence is the request consent ceremony the CHAPI popup also runs,
with the same pivot and tears (see "The consent record" in app-connect.md).

A request may name its requester through the VPR's root `agent: { name }`
member. The consent panel renders it beside the grantee key, marked
self-declared. The agent's entry records it as `name`, and the activity as
`object.actor`; the activity's own `actor` stays the user. The shared
classifier requires the name trimmed, 1 to 64 characters, with no control
characters, and refuses anything else as malformed.

The consent page also notes a known agent: a requester key this account has
granted before and not revoked. After consent renders, the page reads the
directory once and matches the controller in memory (`findKnownAgents` in
`src/lib/connectedApps.ts`), so the host sees no read at the id that DID
derives to. A match is an unretired `kind: 'agent'` entry holding at least
one grant, expired grants included, and the note shows its name and the
date of its newest grant. The note is display-only. Naming someone else's
DID gains a requester nothing, since only the key holder can invoke a grant
delegated to it. A failed read logs and shows no note.

The entry point is stricter than the popup, because the only requester
signals are the grantee DID and request-supplied text, all chosen by whoever
wrote the link. Every refusal is decided before consent renders, in the pure
module `src/lib/walletRequest/externalRequest.ts`, each with its own copy:

- a deep link that is not an interaction URL, a bare exchange URL included;
- a gone exchange (a 404 on either fetch, worded as expired-or-wrong-link
  since the server answers the same for both), an unreachable one, or one
  answering with no readable VPR;
- a request asking for no storage access;
- capability queries naming more than one grantee `controller`, since each
  grant is delegated to its own query's controller and an agent row names
  one;
- a `DIDAuthentication` query in either form, and a `domain` on any request
  (freewallet requires a `domain` for DID Auth and there is no origin to
  match it against);
- an `AppConnectQuery` (App Connect stays CHAPI-only);
- a VPR-named presentation endpoint (`interact.service`) on another origin
  than the exchange, since delivery prefers that endpoint and the consent
  panel names the resolved delivery host;
- any grant class outside the allowlist;
- a string target naming an existing encrypted collection, or a Resource
  inside one, whose current key epoch does not list the agent;
- a grantee `controller` that is the did:key of a wallet client the
  verified account document lists or ever listed (`enrolledClient`);
- a connection request that breaks its own rules, or whose account has no
  `inbox` the wallet trusts (see "The connection request" below).

The last is decided once the session can read the account document
(`refuseEnrolledClientController`), and a log that cannot be read fails the
preparation closed. A revoked client's did:key stays public in the account
log for good. A link naming it would put live grants on that client's
retired `wallet-client` entry, which no listing shows and no disconnect
reaches (`decisions/0037-an-interaction-url-may-not-name-an-enrolled-client.md`).
A consent that reaches the entry write and finds an entry of another kind
at the controller's id, such as a disconnected app's, is refused there by
wallet-core's `ConnectionKindMismatchError` and fails as a failed consent.

**The connection request.** An agent that needs a channel back to the
wallet sends a connection request. It is an interaction-URL request whose
grants include the `{ type: 'https://w3id.org/byoe#inbox' }` descriptor
(`namesInboxTarget` in `src/lib/walletRequest/connectionRequest.ts`).
Beside it, the request asks for GET and HEAD on audience collections, each
named by its plain container URL. The descriptor resolves to the `inbox`
target class, POST only, and provisions nothing. The resolver in
`processZcaps.ts` resolves it only when told the request is a connection
request (`requestKind`). For App Connect and every other kind it is
unsatisfiable. A plain URL string naming the inbox container stays under
the string-target rules, where the never-grantable marking refuses it.
Every other interaction-URL request runs as described above, with no seed
and an unsigned response.

Once the rules above pass, the precheck holds a connection request to four
more (`precheckConnectionRequest`), in this order:

- a grant naming any descriptor other than `#inbox`
  (`connectionTargetForm`). An audience is named by its container URL,
  which never provisions;
- a write on any target but the inbox (`connectionWithWriteGrant`);
- no `challenge` at the VPR root (`connectionWithoutChallenge`). One
  inside the capability query alone does not count, since the response
  proof signs over the root one;
- a proof that does not verify against the controller the request names
  (`connectionUnsigned`).

The proof is a `DataIntegrityProof` at the VPR root, by the named
controller's did:key, with cryptosuite `eddsa-jcs-2022`, purpose
`authentication`, the root `challenge`, and no `domain`. wallet-request's
`verifyCapabilityRequest` checks it, and any failure it reports refuses.
JCS signs the whole request but its `proof`, so the presentation endpoint,
the `controller`, the capability queries, and `agent.name` are all
covered. The proof is what keeps the wallet from minting a key toward a
party that never asked. The request carries no `domain`, and its response
carries none either. Relay is stopped at the request. A phishing exchange
cannot author a request the named agent signed. A verbatim copy of a
genuine one still names the agent's own presentation endpoint, which
`foreignDelivery` refuses when the copy is hosted elsewhere.

Two refusals follow the enrolled-client check, once the session can read
the Space (`refuseUntrustedInbox`). An account with no `inbox` is refused
with `noInbox`. An `inbox` that is public, carries an `encryption`
descriptor, or carries a `generator` stamp is refused with
`untrustedInbox`. Each of the three marks a collection some requester
created under that name, which the wallet does not adopt. The page reads
the inbox through `StorageManager.readInbox`, the same read the inbox pass
runs before it reads any mail, so the three tests live in one place. A
failed read fails the preparation closed.

A third refusal follows those two (`refuseUnattributedServer`). The inbox
pass attributes each message by the server's `createdBy`. A server promises
to record it by advertising the `created-by` feature token in its core
version entry, read from the one service discovery (`wasServiceInfo` in
`src/lib/wasService.ts`). A server without the token is refused with
`noCreatorAttribution`.

The consent panel shows the inbox row with its own copy and no write
banner. Every grant of a connection request takes the share TTL
(`SHARE_ZCAP_TTL_MS`), limited by the parent's remaining life, and every
row states the share TTL's day count (`shareTtlDays`). The rows also state that the access renews
while the connection stands, and that the agent passes its read access on
to people it chooses. The silent renewal rests on that copy.

On approval, before anything is delegated, the wallet resolves its
pairwise seed toward the agent (`resolvePairwiseSeed` in
`src/lib/walletRequest/respond.ts`). It reads the agent's entry at the
controller's id, the one direct read the directory allows at consent. A
stored `seed` is taken once its `seedTag` verifies under the directory's
blinded-index key. An entry with no seed, or no entry, gets 32 fresh random
bytes and their tag. A seed whose tag fails, an entry the codec refuses, or
a failed read fails the consent with nothing delivered. A host that planted
a seed is misbehaving, so the seed is not read as absent. The seed and its
tag ride the entry write with the grants. A connection request provisions
nothing, so it records after compose and before delivery. `recordGrants`
refuses an entry that already carries a different seed. A concurrent
consent won that race, and the composed response names a did:key the entry
does not, so the request fails closed.

The response is held and signed by the pairwise did:key
(`connectionDidKey`), over the request's root `challenge`, with no
`domain`. wallet-request's `processRequest` signs it through its
`signWithoutDidAuth` option. The proof answers no DID Auth query, so
freewallet's DID Auth `domain` rule does not reach it. The agent verifies
the proof against the `holder`, delegates POST on its own inbox to that
did:key, and posts the capability into the owner's `inbox`. The next inbox
pass stores it (see "The agent connection" in app-connect.md). A consent
rolled back leaves a freshly written seed on the entry. Nothing outside the
wallet saw its did:key, so it is inert, and the next consent reuses it.

Only `#public-collection` and `#private-collection` targets are granted from
a link, string targets resolving to those classes included. The one other
class is `inbox`, on a connection request alone. A string target
names only a collection that already exists, since it never provisions.
One the same request provisions does not count. A
share would hand the grantee decryption of the user's own encrypted
collections, and a protected-collection read covers the plaintext
`public-credentials`. `barredGrants` runs once the grants are resolved, the
first point a target's class is known. Widening the allowlist is a
documented decision rather than a code change.

A string target passes the allowlist as the `collection` class, but it
admits the grantee to no key roster. On an encrypted collection whose
current key epoch does not list the agent, the zcap would fetch only
ciphertext. The `#private-collection` descriptor naming the same collection
is the form that adds the agent as a recipient. So `unreadableGrants`
refuses such a grant with `unreadableTarget`, and the copy tells the
developer to request that descriptor instead. The check needs the key
epochs, which only the attribution pass reads. When a string target names
an existing collection (`namesExistingCollectionByUrl`), the page awaits
the attribution pass `useAttributedGrants` hands back before consent. Any
other request renders consent at once, with the attribution pass behind it. The verdict
(`ResolvedTarget.outsideKeyEpoch` in `processZcaps.ts`) rests on positive
evidence only. The collection must be encrypted, the current epoch's
recipients must have been read, and the agent must be absent from them. A
failed or skipped read decides nothing, so that grant delegates with the
ciphertext note. A string target whose current epoch already lists the
agent delegates as before. The refusal is shown on the page alone. The
protocol defines no decline or problem-report message, so nothing is
delivered to the exchange. The CHAPI get popup does not refuse here: it
delegates and shows the ciphertext note.

A failed POST-back leaves the
grant recorded and offers the composed response for manual delivery; a
decline abandons the exchange, which expires on its own.

Grants answered here are listed and revocable on the Applications page as
agent rows, one per unretired `kind: 'agent'` entry (`listConnectedAgents`
in `src/lib/connectedApps.ts`). The precheck refuses a request naming two
controllers, so every grant of a request lands on one entry, and a later
request merges its grants into the same entry. A row is titled by the
entry's `label`, then its `name`, or by the grantee key's fingerprint when
it has neither. It is listed while the entry holds a live grant. A row whose
grants have all expired stays listed while the agent's key still sits in the
current key epoch of a collection its grants target, since that roster entry
stays until a revocation rotates it away. The check is the revocation's own
rule (`granteeRosterCollections` on `StorageManager`): a target counts when
it names an unprotected collection of this Space whose governed descriptor
lists the agent. The row then carries an Access expired chip. The
descriptors are read only when some row has fully expired, each collection
once for all such rows, and a failed read keeps the row. A row no current
epoch lists the agent in is dropped, and so is an entry with no grants. A
row opens the detail page an app row opens (`/applications/:resourceId`).

Revoking a row (`revokeAgentAccess`) runs the app path's stages with no app
key to delete, as the grant revocation ceremony (see "Disconnecting an app"
in app-connect.md). It reads the agent's entry, and first rotates each candidate
collection off the agent's key (`revokeCollectionRecipients`). The
candidates are the collections the entry's grants target, expired grants
included, plus every unprotected collection in the full listing whose
`generator.id` is the agent's did:key. So a collection the agent provisioned
is still rotated after its grants lapsed. The match reads `generator.id`
alone and ignores `origin`. The stamp is request-supplied, so an agent
naming an app's did:key as its `controller` stamps that DID. That makes the
app's collections candidates only for a rotation off the key that same DID
derives. The rotation's pull revokes under the per-grant policy below.

Then each remaining grant is POSTed through wallet-core's
`revokeRecordedGrant`. Only a grant expired beyond the clock-skew margin is
skipped locally, the orphaned marker gating nothing on its own. A plain
refusal the verified document can explain counts as skipped: expired,
orphaned, or chained under a parent delegation whose signer has left the
document or whose generation is no longer the pointed one. The server's
`AlreadyRevokedError` counts as revoked, and any other refusal is thrown.
Then the entry is retired, which is what takes the row off the listing, and
a Revoke activity naming the grants the run confirmed revoked is written as
audit trail.

A stage that does not land throws before the retirement, so the row stays
listed and a retry re-runs every stage. A collection the rotation could not
re-key is such a failure, and so is a collection listing that cannot be
read. The grant stage still runs. The retirement refuses when a concurrent
consent has merged a grant the run did not handle. The toast says whether
the run withdrew anything (`agentRevokeOutcomeKey` in
`src/session/applications.ts`): a grant whose POST landed on this run, or a
collection it re-keyed. Expired and dead-chain grants do not count, being
already over, and neither does a grant the server had already revoked.

A `#private-collection` grant provisions its collection encrypted, as on
the App Connect path: the user is recipient zero and the agent's identity
KAK, derived from its `did:key` controller, is escrowed beside it. So the
agent reads and writes EDV envelopes with its own key. A controller no KAK
derives from makes the grant unsatisfiable. Consent still renders, and the
row shows it as one that cannot be fulfilled. This page and App Connect are
the only paths that provision a collection, since both list their grantees
and can revoke them.

A collection the grant targets but did not create carries no stamp naming
the agent, so for it the entry's grants are the rotation's only source. That
is why the entry is written before any collection is provisioned. Approval
signs every grant first, writes the agent's entry with the signed grants,
then the Grant activity, and only then provisions, which is the step that
escrows the agent into a key epoch. A failed entry write fails the request
with nothing escrowed. A provisioning failure after the write fails the
request too. The request's grants whose escrow did not land are removed from
the entry again. When none escrowed, the Grant goes with them, and an entry
that was absent or retired before the consent is retired again (see "The
consent record" in app-connect.md). A request that provisions nothing is
recorded after compose and before delivery. A failed entry write there
fails closed as well, with the same rollback.

A grant delegated from a transient session chains under the session's
generation delegation (`profile.invocationCapability`) rather than the Space
root, which an annex key the account document never lists would have to
sign, and its `expires` cannot exceed the parent's. A generation delegation
that is expired, inside its renewal window, or signed by a key the session's
memoized verified account document no longer lists under
`capabilityDelegation` runs a blocking renewal stage first: a fresh
ladder-signed delegation, minted through the credential's sibling
delegation, installed in place and adopted by the live session. The approval
refuses (`GenerationDelegationStaleError`) only when the renewal cannot run
at all (the account document does not anchor this credential's ladder VM) or
when it fails, rather than minting a silently short grant.
