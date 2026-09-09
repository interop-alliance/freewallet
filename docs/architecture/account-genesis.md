<!-- Part of freewallet's architecture docs. The map and glossary are in
     ../../ARCHITECTURE.md; this file holds one topic in full. -->

# Account genesis (`@interop/wallet-core/genesis`)

The signup wizard starts the ceremony in its own click handler, since the
passkey path spends the WebAuthn user gesture there, and navigates to the
lobby (`/lobby`) at once, so the run outlives the page that began it. The
ceremonies report stage boundaries through an observational `onStage`
notifier. The lobby renders that as a step feed and routes from the settled
outcome: the dashboard, `/login` when the credential already had a wallet,
or back to the wizard with the error copy.

Every WAS signup runs the credential-anchored establishment below, whose
genesis order promotes the Space controller inline. It mints no enrolled
client, so the account lands ladder-anchored and is reachable by the
credential alone from any browser. The plain genesis
(`ensureAccountGenesis`) is the other path: a no-WAS deployment's signup,
and the login-time heal for any account it provisioned.

**The credential-anchored establishment.** Every WAS signup, passphrase or
passkey and remembered or not, runs this establishment first, through
wallet-core's `establishCredentialAnchoredAccount`
(`@interop/wallet-core/clientAnnex`). The stage order is canonical in
wallet-core's ARCHITECTURE.md, "Ceremonies and cascades".
`src/session/credentialAnchoredGenesis.ts` is a thin binding over that
orchestrator, supplying the app-specific hooks: the unlock-record codec, the
roster store builder, the KMS-authentication thunk and keystore-promotion
closure, and the callers' registry-write `beforePromotion` hook. That
registry write is read-first. The entry is upserted into an existing
registry, and a refused read skips the write rather than starting from an
empty one, since the heal re-run fires the same hook. The establishment's
own entries end with the `#DelegatedClients` pointer, a second rung-0-signed
account-log entry, and the Space controller is promoted last.

Persist-before-publish applies transposed. The unlock record carrying the
ladder seed, with an interim bridge delegated by the ladder's bare did:key,
is durably written BEFORE the Space is created and before rung 0 publishes.
The Space is bootstrapped under the ladder VM's bare did:key, re-derivable
from the record's ladder seed, so a tab death before promotion strands
nothing. The roster's epoch[0] wraps the user key to the credential's
standing KAK under a ladder-signed entry proof.

Entry paths. A non-remembered browser continues into the transient
composition (see "Session persistence" in session-persistence.md), with zero local residue. A
`rememberBrowser: true` signup follows the establishment with the remembered
login, whose self-enrollment makes this browser an enrolled client from the
record just written; that login builds its own pin store and meets the
account log at first contact. A signup torn before the self-enrollment is
resumed by a later `rememberBrowser: true` attempt, which re-runs the
establishment from the record's own ladder seed and then self-enrolls. The
passkey signup is the same shape under the WebAuthn PRF-derived credential:
WebAuthn `create`, this establishment, then the remembered passkey login.

The establishment is an ensure, so a torn signup converges by re-running,
the published log adopted by ladder attribution. `createDID` timestamps the
genesis entry, so a naive re-create would mint a different SCID and never
land.

**The KMS stage** (`kms-authentication`, `ensureKmsAuthentication` in
`src/lib/kms.ts`). With `KMS_SERVER_URL` set, the establishment provisions
the one KMS-held key the account document publishes: a single Ed25519
`authentication` key, in a keystore created under the ladder VM's bare
did:key, recorded as `{ authentication: { vmId, kmsKeyId } }` in
`key-map/keys.json`. The genesis entry then carries that key under the
account's own controller, and the promotion stage moves the keystore
controller to the did:webvh beside the Space's. Nothing else is minted here,
since no server-held key may be a wrap recipient or stand under
`assertionMethod`.

The stage runs alongside Space provisioning, joined before the genesis
entry, and orders its own Space-touching half on a `spaceReady` promise.
Only the `keys.json` read and write touch the Space. The probe starts at
once, over a plaintext codec, so a 404 from an absent Space reads as the
same absence an unwritten `keys.json` does, and the keystore the mint path
needs is acquired only past the probe's miss. The write joins on
`spaceReady` and carries `If-None-Match: *`; the genesis then rewrites the
same resource under `If-Match` on that ETag, adding the `webvh: { did }`
block. A lost race adopts the served map.

A served map is adopted only when the multibase in its `vmId` names a key
this session's own keystore lists. The genesis takes that `vmId` verbatim
into the world-readable document, so a host serving a map naming an
attacker's key would otherwise get it published under `authentication` and
signed by the account. The check creates nothing. A non-creating keystore
lookup that finds nothing, and a `listKeys` listing that does not name the
key, are both the integrity verdict and refuse at once. A lookup or listing
that THROWS is transport instead, retried briefly (three attempts, well
inside the stage timeout) and then refused with the last error as its
cause.

The stage is best-effort, with a timeout that starts once the Space is ready
so slow Space provisioning cannot eat it. A timeout can still win with the
`keys.json` write in flight and leave a map the genesis entry does not
publish; the next run adopts that map after the same listing check. A failed
or hung KMS leaves the account with no `authentication` relation in its
document, which is a complete account presenting did:key, and Settings shows
the state. Because the stage's failure is collected rather than thrown, the
account pointer still binds and no re-run fires the stage again. That
residue is an open gap (see "Ceremony inventory" in ../../ARCHITECTURE.md).

**The plain genesis.** `ensureAccountGenesis` is shared with the mobile
wallet, and `mintAccountKeySet` mints the whole key set locally: Space id,
client seed, user key, did:webvh update-key seeds. The order is Space
provisioning under this client's did:key, the KMS authentication binding
(the one stage that overlaps its neighbour), the did:webvh genesis, the user
key roster strictly after the DID publication, and key epoch[0] on every
encrypted collection. Every stage detects its own completion from durable
state, so a torn run heals by re-running at the next login.
`StorageManager.#provisionUserCollections` is the one caller: it supplies
the KMS stage and the roster store builder, adopts the published DID (also
dropping the verified-log memo unless it already holds a settled document
for that DID), and maps per-stage failures onto warns.

There is no opt-out (`decisions/0017-did-webvh-always-provisioned.md`).
Every WAS account provisions did:webvh, and the reduced path is reached only
by a session that structurally cannot produce a log: one with no keystore
agent, or no client update keys or user key. It runs Space provisioning, key
epochs, and the KMS binding alone, publishes no `did.json`, and so presents
did:key. A Space that never came up is the one fatal stage:
`AccountGenesisSpaceError` is rethrown and login fails.

The plain path keeps the keyring bind before any data Space exists, is
called with `promoteController: false`, and leaves promotion and healing to
`ensurePromotedController`. The no-WAS plain signup keeps its own
`userExists` probe; on a WAS deployment the establishment's create-nothing
probe (`fetchTransientKeyring`) is the one signup-time existence check.
