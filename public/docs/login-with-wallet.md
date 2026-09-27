# Login with Wallet

**Login with Wallet** lets a website (a "relying party", RP) authenticate a
user in a single CHAPI exchange, without ever seeing the user's passphrase.

The RP sends one Verifiable Presentation Request over CHAPI; the wallet shows a
consent screen and responds with a Verifiable Presentation.

A plain Login with Wallet request grants no storage access. To get delegated
access to the user's Wallet Attached Storage (WAS), connect through
[App Connect](https://github.com/interop-alliance/app-connect-spec) instead:
see "Storage access" below.

## The request

Send a `VerifiablePresentation` request whose `query` combines any of:

- **`DIDAuthentication`** -- ask the wallet to prove control of the user's
  DID over your `challenge` / `domain`.
- **`QueryByExample`** with `example.type: "LoginCredential"` -- ask for the
  user's self-issued **Login Credential** (their preferred username). Best
  effort: if the user has not set a handle, no credential is returned and the
  flow still succeeds.

```json
{
  "verifiablePresentationRequest": {
    "query": [
      {
        "type": "DIDAuthentication",
        "acceptedMethods": [{ "method": "key" }]
      },
      {
        "type": "QueryByExample",
        "credentialQuery": {
          "reason": "Show your username on Example App.",
          "example": { "type": "LoginCredential" }
        }
      }
    ],
    "challenge": "99612b24-63d9-11ea-b99f-4f66f3e4f81a",
    "domain": "app.example.com"
  }
}
```

A request that also carries an `AuthorizationCapabilityQuery` (or its alias
`ZcapQuery`) outside an `AppConnectQuery` is refused before the user logs in.
The wallet answers it with `null`, as it does a cancel.

## The response

The wallet returns a Verifiable Presentation. When `DIDAuthentication` was
requested it is **signed** over your `challenge` / `domain`. It carries the
Login Credential when one was asked for and the user has set a handle.

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiablePresentation"],
  "holder": "did:key:z6MkUser...",
  "verifiableCredential": [/* the LoginCredential, when a handle is set */],
  "proof": {
    "type": "DataIntegrityProof",
    "proofPurpose": "authentication",
    "...": "..."
  }
}
```

## Storage access

Storage capabilities are granted only through App Connect: an
`AppConnectQuery` naming your app and carrying its own `capabilityQuery`.
The wallet mints an app key for your app, delegates the grants to that key's
DID, and lists the app on its Applications page, where the user can revoke
it. The wallet fills each grant's `controller` with the app key's DID, so a
`capabilityQuery` inside App Connect needs none. The rest of this section
describes those capability queries.

### `invocationTarget` grammar

The wallet does not expose which WAS server or Space the user uses; you
describe the target abstractly and the wallet maps it onto its own Space
(a descriptor provisions a named collection if it does not exist yet):

- `{ "type": "https://w3id.org/byoe#private-collection", "name": "<collection-id>" }` -- a named
  collection. `name` must match `^[a-z0-9][a-z0-9-]{0,63}$`. A new collection
  is provisioned encrypted and non-public, with your app key as a recipient
  of its key epochs beside the user.
- `{ "type": "https://w3id.org/byoe#public-collection", "name": "<collection-id>" }` -- a
  named collection provisioned plaintext with a world-readable policy: anyone
  on the web can read it without a capability. Writes still require your grant.
  Refused on any of the wallet's own collections, and on any existing
  collection that is not already public: an app can never make the user's
  existing data world-readable.
- `{ "type": "https://w3id.org/byoe#shared-wallet-collection", "name": "<collection-id>" }` -- read
  **and decrypt** one of the wallet's own encrypted collections: your app key
  joins the collection's key-epoch roster, so you see plaintext rather than
  ciphertext. `name` must be one of the shareable encrypted standard
  collections (the decryption key is derived from your app key's DID, never
  carried in the request), and the grant is always read-only.
- a **plain URL string** -- satisfied only if it parses as a URL on the same
  origin as the user's Space and names a collection, or a Resource inside
  one. A query string or fragment, a path that escapes the Space, or a first
  path segment that is not a valid collection id all make the grant
  unsatisfiable; the target is not rewritten to make it fit. A string target
  never provisions, so the collection must already exist. The first path
  segment names the collection, and the grant is capped exactly as the
  equivalent descriptor form would be.

No grant reaches the whole Space. `https://w3id.org/byoe#space` is a reserved
type, and a string naming the Space URL itself (with or without a trailing
slash) is unsatisfiable. The `app-connections`, `key-map`, and
`unlock-methods` collections are never granted, whatever the target form.

An unknown descriptor `type` is unsatisfiable, so a wallet that predates a
descriptor refuses visibly rather than degrading into something weaker.

Two of the wallet's standard collections (`private-credentials`,
`wallet-activity`) are encrypted at rest; an ordinary grant on them exposes
only ciphertext (the wallet's vault key never leaves the wallet) -- decryption
is what `https://w3id.org/byoe#shared-wallet-collection` adds.

### `allowedAction` and the action limits

`allowedAction` is a subset of the closed WAS action vocabulary: `GET`, `POST`,
`PUT`, `DELETE`, plus `HEAD`, which the wallet mints alongside `GET` in every
read grant (the spec authorizes a `HEAD` request as a `GET`). Anything else --
an unrecognized verb, a non-string entry -- is **dropped**, not passed through.
Omitting `allowedAction` defaults to `["GET", "HEAD"]`, not "inherit all".

What survives is then intersected with a limit fixed by the class of target
you asked for:

| Target                                                                       | Limit                                  |
| ---------------------------------------------------------------------------- | -------------------------------------- |
| a wallet collection (standard, `id`)                                         | `GET`, `HEAD`                          |
| a share (`https://w3id.org/byoe#shared-wallet-collection`)                   | `GET`, `HEAD`                          |
| a public collection (`https://w3id.org/byoe#public-collection`)              | `GET`, `HEAD`, `POST`, `PUT`, `DELETE` |
| your own provisioned collection (`https://w3id.org/byoe#private-collection`) | `GET`, `HEAD`, `POST`, `PUT`, `DELETE` |

If nothing is left after dropping unknown verbs and applying the limit, the
grant is **refused** -- shown to the user as "cannot fulfill" and absent from
the response -- rather than downgraded to a read grant you did not ask for. So
request the actions you actually need, and expect a target-appropriate subset
back: check each returned capability's `allowedAction` rather than assuming you
got what you asked for.

### Using a grant

The App Connect response carries the delegated capabilities in a `zcap`
array. Each entry is a self-contained delegated capability carrying its own
`@context` and `capabilityDelegation` proof. To use one, invoke it against its
`invocationTarget` with a `Capability-Invocation` header signed by your app
key (see the
[zCap Developer Guide](https://github.com/interop-alliance/zcap-developer-guide)).
You learn the user's WAS server and Space from each grant's
`invocationTarget`. Correlate grants back to your requests by
`invocationTarget` (the delegation proof cannot carry your `referenceId`).

A grant expires on its own: a write grant sooner than a read-only one. The
user can also revoke it earlier from the wallet's Applications page.
