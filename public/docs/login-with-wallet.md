# Login with Wallet

**Login with Wallet** lets a website (a "relying party", RP) authenticate a
user and receive delegated access to the user's Wallet Attached Storage (WAS)
in a single CHAPI exchange -- without ever seeing the user's passphrase.

The RP sends one Verifiable Presentation Request over CHAPI; the wallet shows a
consent screen and responds with a Verifiable Presentation.

## The request

Send a `VerifiablePresentation` request whose `query` combines any of:

- **`DIDAuthentication`** -- ask the wallet to prove control of the user's
  `did:key` over your `challenge` / `domain`.
- **`QueryByExample`** with `example.type: "LoginCredential"` -- ask for the
  user's self-issued **Login Credential** (their preferred username). Best
  effort: if the user has not set a handle, no credential is returned and the
  flow still succeeds.
- **`AuthorizationCapabilityQuery`** (alias: **`ZcapQuery`**) -- ask for one or
  more storage capabilities. `capabilityQuery` may be a single object or an
  array.

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
      },
      {
        "type": "AuthorizationCapabilityQuery",
        "capabilityQuery": [
          {
            "referenceId": "example-app-data",
            "reason": "Example App stores your documents in your wallet storage.",
            "allowedAction": ["GET", "HEAD", "PUT", "POST", "DELETE"],
            "controller": "did:key:z6MkrRP...your RP DID...",
            "invocationTarget": {
              "type": "urn:was:collection",
              "name": "example-app-data"
            }
          }
        ]
      }
    ],
    "challenge": "99612b24-63d9-11ea-b99f-4f66f3e4f81a",
    "domain": "app.example.com"
  }
}
```

### `invocationTarget` grammar

The wallet does not expose which WAS server or Space the user uses; you
describe the target abstractly and the wallet maps it onto its own Space
(provisioning a named collection if it does not exist yet):

- `{ "type": "urn:was:collection", "name": "<collection-id>" }` -- a named
  collection. `name` must match `^[a-z0-9][a-z0-9-]{0,63}$`. A new collection
  is provisioned plaintext and non-public (reachable only through your grant).
- `{ "type": "urn:was:public-collection", "name": "<collection-id>" }` -- a
  named collection provisioned plaintext with a world-readable policy: anyone
  on the web can read it without a capability. Writes still require your grant.
  Refused on any of the wallet's own collections -- an RP can never make the
  user's existing data world-readable.
- `{ "type": "urn:was:shared-collection", "name": "<collection-id>" }` -- read
  **and decrypt** one of the wallet's own encrypted collections: your DID joins
  the collection's key-epoch roster, so you see plaintext rather than
  ciphertext. `name` must be one of the encrypted standard collections, your
  `controller` must be an Ed25519 `did:key` (the decryption key is derived from
  it, never carried in the request), and the grant is always read-only.
- `{ "type": "urn:was:space" }` -- the whole Space. **Always granted
  read-only** (`GET`/`HEAD`); a Space-wide write would allow controller
  takeover.
- a **plain URL string** -- satisfied only if it parses as a URL on the same
  origin as the user's Space and resolves to a path inside it. A query string
  or fragment, a path that escapes the Space, or a first path segment that is
  not a valid collection id all make the grant unsatisfiable; the target is not
  rewritten to make it fit. The Space URL itself (with or without a trailing
  slash) is a whole-Space grant; otherwise the first path segment names the
  collection, and the grant is capped exactly as the equivalent descriptor
  form would be.

An unknown descriptor `type` is unsatisfiable, so a wallet that predates a
descriptor refuses visibly rather than degrading into something weaker.

`controller` is **your** DID (the RP's) -- the only party that can later invoke
the grant. Two of the wallet's standard collections (`private-credentials`,
`wallet-activity`) are encrypted at rest; an ordinary grant on them exposes
only ciphertext (the wallet's vault key never leaves the wallet) -- decryption
is what `urn:was:shared-collection` adds.

### `allowedAction` and the action ceilings

`allowedAction` is a subset of the closed WAS action vocabulary: `GET`, `POST`,
`PUT`, `DELETE`, plus `HEAD`, which the wallet mints alongside `GET` in every
read grant (the spec authorizes a `HEAD` request as a `GET`). Anything else --
an unrecognized verb, a non-string entry -- is **dropped**, not passed through.
Omitting `allowedAction` defaults to `["GET", "HEAD"]`, never "inherit all".

What survives is then intersected with a ceiling fixed by the class of target
you asked for:

| Target                                                 | Ceiling                                |
| ------------------------------------------------------ | -------------------------------------- |
| whole Space (`urn:was:space`)                          | `GET`, `HEAD`                          |
| a wallet collection (standard, `id`, `key-map`)        | `GET`, `HEAD`                          |
| a share (`urn:was:shared-collection`)                  | `GET`, `HEAD`                          |
| a public collection (`urn:was:public-collection`)      | `GET`, `HEAD`, `POST`                  |
| your own provisioned collection (`urn:was:collection`) | `GET`, `HEAD`, `POST`, `PUT`, `DELETE` |

A public collection is **add-only** on purpose: it is plaintext and
world-readable, so a write there is publication under the user's identity and
irreversible in practice (retracting removes the link, not the copies already
fetched). You can add to what you published; you cannot rewrite or retract it.

If nothing is left after dropping unknown verbs and applying the ceiling, the
grant is **refused** -- shown to the user as "cannot fulfill" and absent from
the response -- rather than downgraded to a read grant you did not ask for. So
request the actions you actually need, and expect a target-appropriate subset
back: check each returned capability's `allowedAction` rather than assuming you
got what you asked for.

## The response

The wallet returns a Verifiable Presentation. When `DIDAuthentication` was
requested it is **signed** over your `challenge` / `domain`; the delegated
capabilities are embedded in a **`zcap` array** on the presentation **before
signing**, so the authentication proof covers the grants -- verify the VP as
received. Each entry in `zcap` is a self-contained delegated capability
carrying its own `@context` and `capabilityDelegation` proof, rooted at
`urn:zcap:root:<the user's Space URL>`, which the WAS server resolves.

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
  },
  "zcap": [
    {
      "@context": [
        "https://w3id.org/zcap/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
      ],
      "id": "urn:zcap:delegated:...",
      "parentCapability": "urn:zcap:root:https%3A%2F%2Fwas.example.com%2Fspace%2F...",
      "invocationTarget": "https://was.example.com/space/.../example-app-data",
      "controller": "did:key:z6MkrRP...your RP DID...",
      "allowedAction": ["GET", "HEAD", "PUT", "POST", "DELETE"],
      "expires": "2026-08-03T12:00:00Z",
      "proof": {
        "type": "Ed25519Signature2020",
        "proofPurpose": "capabilityDelegation",
        "...": "..."
      }
    }
  ]
}
```

To use a grant, invoke it against its `invocationTarget` with a
`Capability-Invocation` header signed by your `controller` key (see the
[zCap Developer Guide](https://github.com/interop-alliance/zcap-developer-guide)).
You learn the user's WAS server and Space from each grant's
`invocationTarget`. Correlate grants back to your requests by
`invocationTarget` (the delegation proof cannot carry your `referenceId`).

### Notes

- **Zcap-only requests** (no `DIDAuthentication`) return an **unsigned** VP
  carrying the `zcap` array. That is safe: each grant is individually signed
  and bound to your DID, so an intercepted response grants nothing to anyone
  else. Login flows should still pair zcaps with `DIDAuthentication` so
  identity and grants arrive together in one signed response.
- **Revocation** is currently expiry-only (default 30 days); the WAS server has
  no Space-side revocation endpoint yet.
