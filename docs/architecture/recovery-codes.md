<!-- Part of freewallet's architecture docs. The map and glossary are in
     ../../ARCHITECTURE.md; this file holds one topic in full. -->

# Recovery codes (`@interop/wallet-core/recovery`)

The "lost my only client" answer: a 16-byte base58 **recovery code**, shown
exactly once at issuance, that restores the whole account from a fresh
browser with nothing else in hand. A code is a minimal wallet client that
stands in the user key roster while publishing no `capabilityInvocation`
relation, so it is not an enrolled client. Its whole key set derives
deterministically from its bytes: an unlock identity under a distinct
single-expansion HKDF (so a code and a passphrase that stringify alike
cannot reach the same unlock Space), a client seed, an update-key ladder
seed, and a binding MAC key. The material exists nowhere until the code is
typed.

A code is a standing unlock credential with a ladder of its own. Rung 0 is
the update key whose hash the document commits, so the spend's
reveal-and-commit entry is the ordinary ladder reveal, and the ladder VM
signs the code's own bridge delegation. A code retires on spend, so no rung
past 0 is ever revealed. Its 16 uniform bytes are high-entropy, which is
what admits both the verbatim `keyAgreement` (the hash-commitment rule
below) and the ladder itself. A passphrase-derived ladder would be a
standing offline grind oracle against a revealed rung.

Its inventory is split. Decryption stands: the `keyAgreement` verification
method publishes in the did:webvh document as an ordinary, unmarked Multikey
entry, and its user key wrap stands in the `key-map/user-key.jsonl` roster.
Being keyAgreement-only, it never shows in client listings keyed on
`capabilityInvocation`, and the document does not label which keyAgreement
key is the recovery one. Its ladder VM publishes beside them under
`assertionMethod` and `capabilityDelegation`. Update authority stays latent.
Rung 0 joins `updateKeys` nowhere, only its hash is committed in
`nextKeyHashes`, and the one bridge into the zcap profile is a pre-minted
PUT-on-`did.jsonl` delegation inside the code's unlock record, signed by the
code's own ladder VM. The record holds no seed and no key wrap. That narrow
scope keeps recovery loud: any use of a code must extend the world-readable,
hash-chained log before it can read a byte. Without a reveal entry the
standing ladder VM reaches only the account-deletion walk's DELETE-only
child and one licensed roster append to recipients the verified document
already lists.

The record splits into a code-authenticated core and a shell the binding
does not cover. The core is the account binding `{ controller, pointer }`,
MAC'd at issuance under a code-derived key the host never holds. The tag
rides the frame in the clear, and recovery verifies it BEFORE trusting the
pointer. That closes the host-forgery redirect, where a malicious host seals
a record of its own naming an account it controls and every signature-side
check passes on it. The tag covers the pointer's host, so codes need
re-issuing when the account migrates hosts. The shell is the plaintext frame
(controller, pointer, timestamp) plus the sealed `bridge` member under the
frame proof, signed with the code-derived unlock key and verified before
decrypt. No ceremony re-mints any unlock record's bridge: each is signed by
its own credential's ladder VM, and another credential's strike cannot rot
it.

The record carries no email and the locate step shows none, since a
self-declared display string is the deception payload a forged record could
show as "this is your wallet". `/recover` confirms only that the code
located an account. A network failure and a `rollback` both surface as
"could not check"; a fork or identity switch surfaces as its own continuity
refusal.

Issuance (Settings > Recovery codes, `issueRecoveryCode` in
`src/session/recovery.ts`) runs from either session kind. The code's unlock
record and its self-signed bridge are written first on both, inert twice
over: the ladder VM stands in no document, and rung 0 is uncommitted. The
document half then splits by signer kind. An enrolled client's roster append
needs no license, so the escrow comes first, into every epoch, and one entry
carries the code's whole inventory. A ladder-signed append is licensed only
at the inventory-changing version its own entry mints, so the ladder branch
publishes the `keyAgreement` alone (the pivot), escrows anchored at that
entry, then publishes the ladder VM and the rung-0 commitment together. The
registry entry of public halves comes last on both, recording rung 0's
multibase as the anchor a later revocation attributes the ladder VM from.

That boundary is load-bearing both ways. A code that could spend before it
could decrypt would strike every standing credential and then fail, since
the spend unwraps every epoch through the code's own wrap. Publishing the
ladder VM first would leave a torn issuance with a code that cannot spend
and can still delete the account. Every stage converges on a re-run with the
same code.

Nothing binds until the confirm-once dialog's "I saved this code". An
issuance torn after its document entry leaves a saved code that locates no
account, plus a document `keyAgreement` entry and roster wrap nothing names.
The login sweep rotates the orphan wrap away, but the registry-driven health
check cannot see the code, so the saved code stays silently dead. The
retire-and-reissue mender for that orphaned entry is not built, and the
last-client transition refuses while it stands.

Recovery (`/recover`, `recoverAccountWithCode`): the typed code decrypts its
unlock record, the log is fetched and locally verified against the pointer,
and the delegation writes the self-enrolling continuation. That is a
**reveal-and-commit** entry signed by the code's pre-committed update key,
then an **add-and-retire** entry. The continuation enrolls what the login's
routing decision would, and its stage order is canonical in wallet-core's
ARCHITECTURE.md.

On a non-remembered browser, the default, the continuation is the
**transient recovery** (wallet-core's `recoverWebvhLadderAnchored`), and no
enrolled client is minted anywhere. The add-and-retire entry publishes the
fresh credential's ladder VM in the new client's place (`assertionMethod`
and `capabilityDelegation` only), beside the new passphrase's `keyAgreement`
commitment and the replacement code's inventory. It retires every other
standing credential, passphrases, passkeys, and unspent codes alike: the
`keyAgreement` member, the ladder VM, the committed rung hashes, and any
revealed rung still held. The remembered continuation strikes the same set.
Rungs are attributed from the log alone, and a credential the log cannot
attribute is reported on the outcome's `unclaimedCredentialVmIds` rather
than struck, keeping a committed rung it could still reveal. A retired
credential's bridge delegation is not revoked, but the entry strikes the
ladder VM that signed it, so it stays live and inert. The account lands
client-less and ladder-anchored, reachable by the new passphrase and the
replacement code alone, and the recovery page says so.

The continuation's persist-before-publish seam runs after the reveal entry
validates the code and before the ladder VM publishes. It mints a fresh
annex generation under the new ladder's bootstrap did:key, loudly enrolls
the per-visit transient client into it, and durably writes two unlock
records: the new passphrase's (ladder seed inside, bridge and sibling signed
by that credential's ladder VM) and the replacement code's, whose bridge is
signed by the REPLACEMENT CODE's own ladder VM and published by the same
entry, so no other credential's later strike can rot it. A recovery record
carries no annex sibling, so the old generation falls to orphan discovery.
The seam names the fresh generation back to the ceremony, so the
`#DelegatedClients` pointer moves to it inside the SAME add-and-retire
entry. A pointer written afterwards would leave a window in which neither
credential could enroll.

The mandatory rotation is the first request past the entry, so nothing is
enrolled and nothing is read between the typed code dying in the document
and the new credential gaining its wrap. It is the ONE ladder-signed roster
append the ceremony-tail license admits (`replaceUserKeyRosterRecipients`:
spent code retired, fresh credential and replacement code escrowed, fresh
epoch minted, one write anchored at the add-and-retire entry). The
pre-rotation user key the registry update needs is unwrapped afterwards, out
of the superseded epoch's escrow. The epoch cascade and the unlock-methods
registry update (spent entry out, every retired credential's entry out with
it, replacement and new-passphrase entries in, re-sealed to the rotated user
key) ride the generation delegation. Which entries are retired is keyed on
the continuation's own report (`retiredCredentialVmIds`) inside the
compare-and-swap. An entry the report lists as unclaimed is kept, since it
still records the rung-0 anchor a later retirement attributes the credential
by. Each retired entry's unlock Space is then deleted best-effort through a
DELETE-only child of its own management zcap, and only once the registry
write dropping the entries has landed, since a registry naming a deleted
Space breaks every later registry-driven walk. The visit then enters through
the ordinary transient composition with zero local residue.

Three residues remain, none of them mended here. A tear inside the append
leaves the spent code dead (a re-run refuses it as spent) and the current
epoch wrapped to the removed code alone; the mender would be a repair
holding both the spent code and the new passphrase, and it is not built. A
rotation torn mid-fan-out strands a collection keyed to the spent code until
the next remembered login or a spend re-run. A tail torn between the
registry drop and the deletes leaves the retired credentials' unlock Spaces
standing with nothing naming them, and a failed registry write leaves their
entries standing with no pass here to drop them. Both of the last are inert,
and a lingering retired entry is dropped by the next spend's own registry
pass.

The remembered spend, the `rememberBrowser` entry, mints a fresh
enrolled-client key set instead. Its required `onCommitted` seam, between
the two entries, writes the successors: the new passphrase's unlock record
in the standing LAYOUT, the browser-local PENDING client-key record (seeds,
controller, `pointerDid`, the pending group of built-on head, unwrap key and
replacement-code bytes; no user key), and the replacement code's record and
bridge. A colliding unlock record refuses up front. The add-and-retire entry
brings in the new client, retires the spent code's inventory, and adds the
replacement code's. The tail then makes the passphrase standing before the
rotation, and the registry mutation, keyed on the same report, runs between
the re-seal and the cascade. The new enrolled client then deletes each
retired entry's unlock Space and this browser's unlock-local state for it,
best-effort, under the same registry-write-first ordering. A failed write
leaves the entries named and their Spaces standing for the spend resume's
registry pass, which drops and deletes them on every arm. The resume never
re-enters the continuation, so it reads the same report back off the log
(`recoverySpendRetirementFromLog`). The replacement code's save confirm
completes the local record and clears the carrier. The spent code's unlock
Space is deleted, so a spent code thereafter fails distinctly. A post-entry
tab death leaves the pending record for that resume, which backfills the
standing configuration and the registry, re-displays the code until
confirmed saved, and completes the rotation and cascade.

Revoking a code from Settings is the issuance reversal and is REAL, since
the secret was only ever a pointer to the record. It runs from either
session kind, in the retirement order: the retirement gate read-only, the
post-removal did:web projection on the ladder kind (see "The projection's
freshness on a credential-anchored account"), the document entry out, the
user key rotated off the code's wrap and the collections re-epoch'd by the
same cascade, the unlock Space deleted, the registry entry dropped. The live
session adopts the rotated user key in place.

The document entry takes the code's whole inventory: its `keyAgreement`, its
committed rung-0 hash, and its ladder VM. The revoker holds neither the code
bytes nor its ladder seed, so the VM claim is seedless, anchored on the
rung-0 update-key multibase the registry recorded at issuance. It is
required rather than best-effort. A claim no attribution arm makes refuses
the whole revocation with `UnclaimedLadderVmRetirementError` before anything
is written, since a standing ladder VM whose credential is otherwise retired
keeps its delegation authority. The Space goes through a DELETE-only child
of the entry's management zcap, behind the deletion walk's five pre-mint
refusals. A refusal or a masked 404 is reported as a residue rather than
failing the run.

A login-time health check watches for delegation rot and delegation expiry,
either of which bricks recovery when it is needed. A stored delegation rots
the moment its signing key's verification method leaves the document, and
it stops chaining from then on. The bridge TTL is one
year (NIST SP 800-57 cryptoperiod guidance), so the registry entry records
its `expires`, and a delegation expired or inside the 30-day renewal window
is flagged the same way. No ceremony re-mints a bridge on another
credential's behalf, so for a recovery code the check is the whole remedy
and re-issuing the code is the fix. A standing passphrase or passkey
refreshes its own bridge at its own login, on those same three staleness
axes. The predicates (`delegationKeyInDocument`, `zcapExpiring`) and the
delegation builder live in `@interop/wallet-core/recovery`.

Two standing boundary rules. First, the hash-commitment rule: **a
low-entropy-derived public key is never published in the world-readable
document**. The document carries a hash commitment of the key
(`MultikeyCommitment`); the real key rides in the capability-gated roster
entry, and the recipient resolver verifies it against the commitment (the
oracle argument is in "Session & auth flow" in session-and-auth.md). A high-entropy credential's
key (a passkey PRF output, a recovery code) may publish verbatim. Second,
the unlock-methods registry's additive `method` enum is the explicit seam
for a later quorum recovery method, rejected for v1 as presupposing a
contact roster most accounts lack.
