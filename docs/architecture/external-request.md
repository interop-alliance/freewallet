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
ordinary grant engine, and POSTs the unsigned zcap-only presentation back
with the exchange URL. Its consent rows carry the same existing-collection
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
none looks it up in the app keys or the App Connect Grant activities.
Without a live app session it runs the ordinary login in place and
adopts it app-wide. A `Grant` activity records the grant under the fixed
origin marker `n/a (API request)`, which the Applications page
keys agent rows on.

A request may name its requester through the VPR's root `agent: { name }`
member. The consent panel renders it beside the grantee key, marked
self-declared, and the activity records it as `object.actor`; the activity's
own `actor` stays the user. The shared classifier requires the name trimmed,
1 to 64 characters, with no control characters, and refuses anything else as
malformed.

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
  inside one, whose current key epoch does not list the agent.

Only `#public-collection` and `#private-collection` targets are granted from
a link, string targets resolving to those classes included. A string target
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
agent rows, keyed by the grant's `controller` did:key (`listConnectedAgents`
in `src/lib/connectedApps.ts`), which is every grant's controller, since the
precheck refuses a request naming two and titled by `agent.name`, or by the grantee
key's fingerprint when no name was sent. A row's grants are the union over
every agent Grant for that controller newer than the latest matching Revoke
activity (same origin marker, no `appConnect`, the controller in
`object.controller`), since a later request can add a grant without retiring
an earlier one. A row whose grants have all expired stays listed while the
agent's key still sits in the current key epoch of a collection its grants
target, since that roster entry stays until a revocation rotates it away.
The check is the revocation's own rule (`granteeRosterCollections` on
`StorageManager`): a target counts when it names an unprotected collection
of this Space whose governed descriptor lists the agent. The row then
carries an Access expired chip. The descriptors are read only when some row
has fully expired, each collection once for all such rows, and a failed read
keeps the row. A row no current epoch
lists the agent in is dropped. Revoking a
row POSTs each recorded capability through wallet-core's
`revokeRecordedGrant` (only a grant expired beyond the clock-skew margin is
skipped locally), the orphaned marker gating nothing on its own; a plain
refusal the verified document can explain (expired, orphaned, or chained
under a parent delegation whose signer has left the document or whose
generation is no longer the pointed one) counts as skipped, the server's
`AlreadyRevokedError` counts as revoked, and any other refusal is thrown
before any Revoke is recorded. The Revoke's
`created` is stamped at least one millisecond past the latest Grant, so a
fast-clocked terminal cannot leave the row standing. A run that left a
recorded grant with no capability to POST (a legacy summary-only entry)
ends with its own toast (`agentRevokeOutcomeKey` in
`src/session/applications.ts`), so a partial revoke does not read as a clean
one. Expired and dead-chain grants do not count, being already over, and
neither does a grant delegated to another agent's key.

A `#private-collection` grant provisions its collection encrypted, as on
the App Connect path: the user is recipient zero and the agent's identity
KAK, derived from its `did:key` controller, is escrowed beside it. So the
agent reads and writes EDV envelopes with its own key. A controller no KAK
derives from makes the grant unsatisfiable. Consent still renders, and the
row shows it as one that cannot be fulfilled. This page and App Connect are
the only paths that provision a collection, since both list their grantees
and can revoke them. Revoking the row
rotates each candidate collection off that key first
(`revokeAgentCollectionRecipients`), then POSTs the remaining grants. The
candidates are the collections the agent's recorded grants target, expired
grants included. The revocation also reads the full collection listing and
adds every private collection whose `generator.id` is the agent's did:key.
So a collection the agent provisioned is still rotated when its Grant
activity is gone. A protected collection is not a candidate. The match reads
`generator.id` alone and ignores `origin`. The stamp is request-supplied, so
an agent naming an app's did:key as its `controller` stamps that DID. That
makes the app's collections candidates only for a rotation off the key that
same DID derives. The rotation's pull revokes under the same per-grant
policy. A collection the rotation could not re-key keeps the row listed with
no Revoke recorded, since a Revoke would hide the row. The grant stage still
runs, and the retry's Revoke names what it withdrew. There is no app key to
delete.

A collection the grant targets but did not create carries no stamp naming
the agent, so for it the recorded grants are the rotation's only source.
That is why the Grant activity is persisted before any collection is provisioned.
Approval signs every grant first, persists the Grant with the signed grants,
and only then provisions, which is the step that escrows the agent into a
key epoch. A failed persist fails the request with nothing escrowed. A
provisioning failure after the persist fails the request and leaves a Grant
naming a grant the collection may not list. The rotation skips such a
collection, since its current epoch does not list the agent. A Grant
activity lost later still leaves the agent a recipient of an existing
collection its grant targeted, with nothing to find it by.

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
