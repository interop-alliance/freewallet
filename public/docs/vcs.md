# Verifiable Credentials

**Verifiable Credentials (VCs)** are a W3C standard for expressing credentials
on the web in a cryptographically secure, privacy-respecting, and
machine-verifiable way.

## How They Work

A Verifiable Credential involves three roles:

1. **Issuer** — the entity that creates and signs the credential.
2. **Holder** — the entity that receives and stores the credential (e.g. in Freewallet).
3. **Verifier** — the entity that checks the credential's authenticity.

## Example

A university (issuer) issues a diploma credential to a graduate (holder).
The graduate stores it in their wallet and later presents it to an employer (verifier),
who can cryptographically verify it was issued by the university and hasn't been tampered with.

## Key Properties

- **Tamper-evident** — signed with digital signatures (linked to DIDs).
- **Privacy-preserving** — holders can selectively disclose only the claims they choose.
- **Interoperable** — based on open standards (JSON-LD, JWT).

## Learn More

- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model-2.0/)
- [Verifiable Credentials Use Cases](https://www.w3.org/TR/vc-use-cases/)
