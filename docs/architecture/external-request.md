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
with the exchange URL. Without a live app session it runs the ordinary login
in place and adopts it app-wide. The Login activity records the grant under
the fixed origin marker `n/a (API request)`, which the Applications page
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
- a `DIDAuthentication` query in either form, and a `domain` on any request
  (freewallet requires a `domain` for DID Auth and there is no origin to
  match it against);
- an `AppConnectQuery` (App Connect stays CHAPI-only);
- a VPR-named presentation endpoint (`interact.service`) on another origin
  than the exchange, since delivery prefers that endpoint and the consent
  panel names the resolved delivery host;
- any grant class outside the allowlist.

Only `#public-collection` and `#private-collection` targets are granted from
a link, plain collection URLs resolving to those classes included. A share
would hand the grantee decryption of the user's own encrypted collections,
and a whole-Space or protected-collection read covers the plaintext
`public-credentials`. `barredGrants` runs once the grants are resolved, the
first point a target's class is known. Widening the allowlist is a
documented decision rather than a code change. A failed POST-back leaves the
grant recorded and offers the composed response for manual delivery; a
decline abandons the exchange, which expires on its own.

Grants answered here are listed and revocable on the Applications page as
agent rows, keyed by the grant's `controller` did:key (`listConnectedAgents`
in `src/lib/connectedApps.ts`) and titled by `agent.name`, or by the grantee
key's fingerprint when no name was sent. A row's grants are the union over
every agent Login for that controller newer than the latest matching Revoke
activity (same origin marker, no `appConnect`, the controller in
`object.controller`), since a later request can add a grant without retiring
an earlier one. A row whose grants have all expired is dropped. Revoking a
row POSTs every recorded capability's revocation regardless of the orphaned
marker, and stamps the Revoke's `created` at least one millisecond past the
latest Login, so a fast-clocked terminal cannot leave the row standing.
There is no app key to delete and no collection epoch to rotate, an agent
never being a key-epoch recipient.

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
