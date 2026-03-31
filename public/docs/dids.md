# Decentralized Identifiers

**Decentralized Identifiers (DIDs)** are a new type of globally unique identifier
defined by the [W3C DID Core specification](https://www.w3.org/TR/did-core/).

Unlike traditional identifiers (email addresses, usernames, etc.), DIDs are:

- **Self-owned** — created and controlled by the holder, not a central authority.
- **Cryptographically verifiable** — ownership can be proven using public/private key pairs.
- **Decentralized** — they don't depend on a single registry or certificate authority.

## DID Syntax

A DID looks like this:

```
did:example:123456789abcdefghi
```

It has three parts:

| Part       | Description                          |
|------------|--------------------------------------|
| `did`      | The scheme (always "did")            |
| `example`  | The DID method                       |
| `123456…`  | The method-specific identifier       |

## DID Documents

Every DID resolves to a **DID Document** — a JSON-LD object that contains the
public keys, authentication methods, and service endpoints associated with that DID.

## Learn More

- [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
- [DID Method Registry](https://w3c.github.io/did-spec-registries/#did-methods)
