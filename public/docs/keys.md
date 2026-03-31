# Cryptographic Keys

**Cryptographic keys** are the foundation of identity and trust in the
Verifiable Credentials ecosystem. They allow users to prove ownership of
DIDs and to sign or verify credentials.

## Key Pairs

A key pair consists of:

- **Private key** — kept secret by the owner; used to create digital signatures.
- **Public key** — shared openly (typically in a DID Document); used to verify signatures.

## Common Key Types

| Type              | Algorithm   | Usage                              |
|-------------------|-------------|------------------------------------|
| Ed25519           | EdDSA       | Fast signatures, widely supported  |
| P-256             | ECDSA       | NIST standard, broad compatibility |
| X25519            | ECDH        | Key agreement / encryption         |

## How Freewallet Uses Keys

When you create an account, Freewallet generates a key pair for you.
Your private key is used to:

- **Authenticate** — prove you control your DID.
- **Sign** — create Verifiable Presentations from your stored credentials.

Your public key is published in your DID Document so that verifiers can
check your signatures.

## Learn More

- [Ed25519 Signature Suite](https://w3c-ccg.github.io/lds-ed25519-2020/)
- [JSON Web Key (JWK) Format](https://www.rfc-editor.org/rfc/rfc7517)
