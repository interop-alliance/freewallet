# 0017: did:webvh is always provisioned; the standalone did:web mint is retired

- Status: accepted
- Date: 2026-09-03
- Driving work: the FW-344 design gate (retiring the wallet's standalone
  did:web mint, whose hand-assembled document was overwritten moments
  later by the did:webvh log's own projection). Extracted at that
  design's approval.
- Affects: freewallet (`src/lib/didWeb.ts`, `src/app.config.ts`,
  `src/stores/storageManager.ts`, `src/session/credentialAnchoredGenesis.ts`,
  the Settings identity row, `public/docs/did-web.md`),
  `@interop/wallet-core` `/genesis` and `/clientAnnex` (the KMS key
  closure), the WAS deployment's `id` collection.

## Context

Account provisioning minted a second identity beside the account's
`did:webvh`: two KMS-held keys, a key map, and a hand-assembled
`id/did.json`. On every promoted account the did:webvh log's own did:web
projection then overwrote that document inside the same ceremony, so the
mint was a contested second writer of one resource, and the loser. The
two documents named the same DID.

Whether the log was provisioned at all was configurable. A build-time
opt-out selected a reduced provisioning path that publishes no log, so
its only `did.json` was the hand-assembled one -- which publishes the
KMS X25519 key under `keyAgreement`, against the standing rule that no
server-held key may be a wrap target.

## Decision

Every account on a WAS deployment provisions its `did:webvh`. The
build-time opt-out and its config export are removed, so no
configuration selects the reduced provisioning path.

The reduced path survives only for a session that structurally lacks the
material -- no keystore agent, no user key, or no client webvh keys, so
a no-WAS deployment or a guest. Such a session presents did:key only and
publishes no `did.json` at all.

The did:webvh log's did:web projection is the only producer of
`id/did.json`. The document assembler and its publisher are deleted, and
the surviving KMS stage writes the key map alone. The one other
projection write, the recovery continuation's republish, is unchanged.

The surviving KMS key keeps its alias template verbatim,
`did:web:<host>:space:<spaceId>:id#{publicKeyMultibase}`. The alias
shapes the stored key description's id and nothing else: the sign route
ignores it, the sign wire carries no verification-method id, and the
client builds its signer handle locally, so one key signs under the
did:key, did:web and did:webvh forms with no server change.

Greenfield, with no migration and no one-shot remediation: an account
provisioned before this change keeps whatever `did.json` it has, and no
writer corrects it. The change note says the exposure is closed for
accounts created after this change.

## Rejected Alternatives

- Keeping the opt-out. After this change it would select a path that
  publishes no DID document of any kind, so the flag would mean
  "publish nothing" rather than "publish did:web only" -- a
  configuration surface with no honest meaning and no consumer.
- Letting the wallet own `did.json` and having the log publication skip
  it. The log is the source of truth and the projection is what a
  did:web resolver reads; a hand-assembled document omitting the client
  keys, the ladder VM and the credential's `keyAgreement` commitment
  would make did:web resolution disagree with did:webvh resolution of
  the same account, and did:web would stop coming for free.
- A one-shot overwrite of a pre-existing hand-assembled document by the
  surviving KMS ensure. It resurrects on that path exactly the
  second-writer arrangement this decision removes, for accounts the
  greenfield stance does not owe a migration.
- Re-pointing the KMS alias at the keystore's live controller
  (`{+controller}#{publicKeyMultibase}`). The description's id would
  change under the client at promotion time and disagree with the id the
  key map recorded, giving one key two recorded ids with no reader for
  the difference.
- A did:key alias: a fourth id form for the same key, with no consumer.

## Do not reopen

Re-introducing a standalone did:web document writer -- a second producer
of `id/did.json` beside the projection -- is rejected. The contested
write is the defect this decision removes, and any need it would serve
is a need for the projection to be correct or fresh.

## Consequences

- A reduced-path account provisioned before this change keeps a
  document publishing the KMS X25519 key under `keyAgreement`, with no
  writer left to correct it. The exposure is closed for accounts created
  after the change, and that is what the change note says.
- The alias template is stored per key at generate time with no update
  path, and it hard-codes the storage host. A host migration leaves a
  description whose id resolves nowhere; the key still signs, since the
  sign route ignores the alias.
- The projection is now the wallet's whole did:web story, which raises
  the cost of two standing gaps: a stale projection on a
  credential-anchored account (a revocation bypass rather than lag), and
  a sub-path deployment whose projection id resolves nowhere. Both are
  pre-existing and tracked separately.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A deployment must serve did:web for accounts that have no did:webvh
   log, which would need a producer for that document and a story for
   how it stays consistent with the account's own keys.
2. A concrete remediation need appears for accounts carrying a
   hand-assembled document (a support request, or a key inventory that
   must be provably empty), which would be its own item rather than a
   revival of the writer.
