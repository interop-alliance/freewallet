<!-- Part of freewallet's architecture docs. The map and glossary are in
     ../../ARCHITECTURE.md; this file holds one topic in full. -->

# Client revocation and the epoch cascade

Disconnecting an enrolled wallet client from the account. The cascade is
`revokeAccountClient` in `@interop/wallet-core/clients`, and its stage order
is canonical in wallet-core's ARCHITECTURE.md. `revokeEnrolledClient` in
`src/session/revocation.ts` is the freewallet binding, supplying the session
preconditions, the collections source, the generation-delegation re-mint,
and the adoption side effects. The Settings "Connected wallets" panel drives
it, synchronously and in dependency order, in the session that disconnects.
The four stages, in the enrolled kind's form:

1. **The document edit** (`revokeWebvhClient`): one log entry removes the
   revoked client's two verification methods, its update key, and both
   standing `nextKeyHashes` commitments, the carry-over hash and the staged
   hash recovered by log attribution. An opaque committed hash left behind
   would be a re-seizure credential through the reveal mechanism. Under the
   current-key-set rule that one edit pulls the client's whole authority at
   once. The cascade makes no per-collection revoke calls; apps it had
   connected reconnect through the ordinary App Connect flow.
2. **The user key rotation** in the `key-map/user-key.jsonl` roster,
   recipients resolved from the just-updated verified document. An account
   with no roster yet stops here, the document edit having landed. First the
   orchestrator sets the store's minimum controller version from the
   post-edit log, so a stale cached controller view can anchor neither the
   rotation nor the sealing append at a head predating the removal. Every
   collection store the fan-out writes through takes that same view.
3. **The epoch cascade**, over the collections `src/session/userKeyCascade.ts`
   enumerates: every encrypted collection, standard plus any remotely listed
   one whose Metadata object carries an encryption descriptor, re-epoch'd
   onto the fresh user key in parallel. Each rotation is a signed append on that
   collection's governing log, so it signs with the key the calling ceremony
   is licensed to append with. Revoked generations retire from the epoch
   rosters and the fresh key escrows into every prior epoch, so other
   replicas keep decrypting. A collection is stale exactly when its current
   epoch names a non-current user key generation, decided from stored state
   alone; a never-epoch'd one takes the newest prior generation as its first
   epoch. A descriptor whose `currentEpoch` names no epoch in its own
   `epochs` list is refused fail-closed. Failures collect per collection;
   the rest still rotate.
4. **The generation-delegation re-mint** (`remintGenerationDelegation` in
   `src/session/revocation.ts`): an embedded generation delegation the
   revoked client had signed also stopped chaining at step 1. It is replaced
   in place, same fragment and no revocation POST, since the rotted chain no
   longer verifies. It signs with the login credential's ladder seed, and
   skips with a report when that seed or a promoted pointer is absent. It
   runs in the no-roster early return too. Grants chained under the old
   delegation die with it, a stated consequence of an ordinary disconnect.

The revoking session then adopts the fresh user key in place: vault keys
swapped, storage ciphers rebuilt on the re-epoch'd descriptors, the
unlock-methods registry re-wrapped. It keeps operating without a re-login.
Self-revocation is refused up front; use another enrolled client, or a
recovery code. A naive full re-run converges, since the log entry is
idempotent and the staleness rule finds exactly the stranded collections.
The limitation: ciphertext the revoked client already fetched stays readable
to it, and old epochs open to keys it already held.

One key survives every rotation: a collection's blinded-index HMAC key,
minted with epoch[0] and wrapped to each recipient on the `encryption`
descriptor. Rotating it would orphan every existing `indexed` entry, since
blinded index tokens must compare across the collection's whole history.
Recipient removal only drops the leaver's wrap, so a removed recipient
colluding with the server could confirm guessed attribute values
indefinitely. That is a guessing oracle rather than a read path: the query
endpoint stays behind the pull grant, and the content keys rotate above.

The standing backstop is the **cascade-completion sweep**: session creation
re-runs stages 2 and 3 on every login whose roster read succeeded, as the
first stage of the login-time chain on `session.registryReady`, best-effort.
That chain runs after the dashboard has rendered (see "Session & auth
flow"), so a write in the navigation window can seal under an epoch a
disconnect's rotation has not caught up to, readable by a client the revoke
already removed. Whether to hold such writes until the sweep completes is an
open decision.

The roster stage runs first (`convergeUserKeyRosterToDocument`). A cascade
torn between its document edit and its rotation leaves the roster wrapping
the CURRENT key to a recipient the locally verified document no longer keys,
silently, since that document edit will never be re-run. Such a recipient is
rotated away here, and the fresh key adopted (client-key record, epoch pin,
live session vault keys and ciphers) before the fan-out runs against it.
Staleness being decided from stored state alone, the fan-out completes a
cascade another client crashed partway through. Together the two stages
check that the roster keys exactly the document's clients and that no
collection's current epoch names a retired user key generation. The roster
stage writes through the store instance the login read came through, so it
acquires the roster log no second time.

Recovery-code spend and revocation drive stages 2 and 3 of the same cascade.
Their document edits are their own, and a spent code's replacement
delegation is minted by its own ceremony.

**The ladder branch.** A transient session on a standing unlock credential
runs the same cascade with the credential's ladder in the enrolled client's
seat. The removal entry is signed by a rung of that ladder through the
record's bridge delegation, the convergence append by its ladder VM, and
every request is invoked by the per-visit annex key under the generation
delegation. Two refusals lift with the signer (`disconnectEligibility` takes
its kind): a ladder has no self to refuse, and the last enrolled client is
removable, since the account lands ladder-anchored rather than stranded.

Two refusals run first, before anything is written. A registry this session
cannot read is one, since the check below is computed from it. A
pending-shaped passphrase entry is the other, the torn-retirement repair
being its only mender; the in-band registry re-seal at the tail would
otherwise rewrite a half-retired entry. The refusal names the method and its
mender.

The rule for a struck signer runs next, before the pivot. On an account
whose annex generation was minted by the client being removed, that client's
account key signed the generation delegation this visit's every request
rides, and the removal entry strikes it. The replacement is minted by the
acting credential's ladder VM, installed in place through the credential's
sibling delegation and adopted into the live session before the entry lands.

No unlock record is written on either branch, since every record's frame
proof, bridge, and sibling delegation are signed by its OWN credential's
unlock identity and ladder VM, which this entry does not strike. The
post-removal did:web projection is PUT immediately BEFORE the removal entry,
through the account Space's `id` collection under the visit's generation
delegation (see "The projection's freshness on a credential-anchored
account"). The store resolves that delegation at each use, so the PUT rides
the replacement the re-mint just installed. A failed PUT is warned and the
entry still publishes.

The residue the branch leaves is the roster. A disconnect torn after the
removal entry leaves the current key wrapped to the removed client. An
account that still has an enrolled client gets it mended by the
remembered-login sweep. The account a last-client disconnect produces has no
mender: the row is gone from the listing, so there is no re-click, and no
sweep runs there. The retire-direction convergence of any later
ladder-branch ceremony is the only one left, and the user may never run one.
That is an open gap, recorded in the Ceremony inventory.

## The Settings clients surface ("Connected wallets")

The management surface over the enrolled-client roster
(`src/components/EnrolledClientsSection.tsx`, glue in
`src/session/clients.ts`): where "disconnect this phone" lives. Apps are
grantees rather than enrolled clients and stay on the sibling Applications
page. The connect-another-wallet entry point lives here too, one card
offering both the QR onboarding invite and the pasted connect code.

The listing is wallet-core's `listAccountClients` over the locally verified
did:webvh log, keyed on `capabilityInvocation`. That keying excludes
structurally rather than by filter: a recovery code's key publishes under
`keyAgreement` only, the KMS-held DIDAuth signing key under
`authentication`.

Two members come from log attribution rather than the current document. One
is each client's active update key, since the flat `updateKeys` set has no
per-client grouping: the entry publishing a client's verification methods
revealed its initial key, and each later entry retiring the attributed key
while revealing exactly one replacement is that client's self-rotation. An
ambiguous attribution disables disconnect for the row. The other is the
enrollment moment, the `versionTime` of the publishing entry.

Disconnect drives the client-revocation cascade verbatim, on a row carrying
both key members. Eligibility is the shared `disconnectEligibility` policy
(self, last-wallet, and unattributed-update-key refusals) rather than UI
state, and the policy takes the signer that would sign the removal entry. It
confirms the limitation first: re-keying stops future reads, and
already-fetched ciphertext stays readable. A partial collection fan-out is
reported as a resumable success pointing at the login-time sweep.

On the enrolled branch the last enrolled client cannot be disconnected,
since it is always the current one from its own session and self-revocation
is refused. Its row offers the last-client transition instead (see "The
forget affordance"). On a transient session only the unattributed-update-key
refusal survives, so every row offers Disconnect and the last row states the
transition it makes: the account lands ladder-anchored, reached by the
sign-in credentials alone. No row carries the "This browser" chip there, and
the forget ceremony's entry point does not appear, since a transient session
runs as no enrolled client. Its resumable-failure copy says the remaining
re-keying resumes at the next disconnect or passphrase change, no transient
login running the cascade sweep.

**Labels** live beside the keys rather than in the document, which carries
key material only: `key-map/client-labels.json`, over wallet-core's
`readClientLabels` / `setClientLabel` store seam. They are plaintext in the
private, capability-gated `key-map` collection, since the host already
serves the world-readable log naming every client key. A label is chosen at
enrollment approval, written best-effort, and editable inline. A "This
browser" chip marks the current client, matched on the session's own signing
key rather than on stored state. The store rides the remote store's bound
invocation capability, so a transient session reads and writes labels under
its generation delegation.

**The Applications sibling** knows the current-key-set rule. That page
(`src/lib/connectedApps.ts`) holds app grantees where this panel holds
wallet clients, with a cross-pointer in each. Its listing checks each
recorded App Connect grant's delegation signer against the same verified
document, matched on the key-multibase fragment so a key's did:key and
promoted did:webvh forms agree; the full zcap is recorded on the Login
activity. An app whose recorded signers have all left the document shows as
orphaned, and reconnecting through the ordinary App Connect flow is the
recovery path. A grant minted in a transient session is signed by an annex
key the account document never lists, so that signer derives as unknown and
the row carries no marker. The marker is display-only; each grant's
revocation is wallet-core's `revokeRecordedGrant`, the same policy the
generation delegation's revocation follows. A grant expired beyond the
revocation clock-skew margin is skipped without a POST. Every other grant
is POSTed, whatever the document says about its signer, since the document
a login read is a snapshot. The server's `AlreadyRevokedError` counts as
skipped. A plain `ValidationError` is read against the same document
(`classifyGrantRevocationRefusal`): a grant at or past its own `expires`,
an orphaned one (delegated under the Space root, signer gone), or one
chained under an embedded parent delegation that has rotted (the parent's
own proof key gone from the document under `capabilityDelegation`,
wallet-core's `delegationSignerGone`, which covers a generation delegation
replaced within its generation; or a parent whose `controller` parses as an
annex DID other than the pointed one) counts as skipped. A refusal the
client cannot read (a parent with no proof key, a parent of another shape,
a document pointing at no generation, a signer still enrolled) is thrown,
as is any other failure, after the sibling POSTs settle, before the app key
is deleted or the Revoke recorded, so the row stays listed and a retry
re-runs. A failure leaves the app-provisioned collections already
rotated off the app's recipient key (the rotation stage runs first) with
the credential kept and no Revoke recorded; the rotation is idempotent and
the landed revocations answer `AlreadyRevokedError`, so the retry converges
once the refused POST succeeds. The check is best-effort, so
with no verified document this session the page lists without the marker
rather than failing, and the revocation skips on expiry alone. Agent rows
run the identical check over the recorded grant's `controller` instead of an
app-key subject, and revoking an agent follows the same per-grant reading.
