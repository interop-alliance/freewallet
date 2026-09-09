<!-- Part of freewallet's architecture docs. The map and glossary are in
     ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The client enrollment ceremony (`@interop/wallet-core/enrollment`)

Connecting a second wallet client (a fresh browser profile) to an existing
account, with no secret leaving either side. A fresh browser holding a
standing unlock credential self-enrolls at login instead (see "Session &
auth flow"). This two-party ceremony remains the path for records without
standing authority, for onboarding another wallet app over the rendezvous
transport below, and as the future opt-in step-up approval policy.

The new client mints its whole key set locally (client seed, did:webvh
update-key seeds). Only PUBLIC halves travel, as a compact **connect code**
(`freewallet-connect:<base64url(JSON)>`) carried point-to-point, and nothing
travels back over the channel. The account pointer comes out of the keyring
and the user key out of the wrap-set roster. Both screens show the new
client's did:key fingerprint, compared by the person running the ceremony
before approving.

The flow is quorum-of-one. Any single enrolled client can enroll, and so can
any transient session on a standing unlock credential. The stage order is
canonical in wallet-core's ARCHITECTURE.md.

1. **Enrollee** (the login page's connect-this-browser card):
   `mintEnrollmentRequest` mints the key set and shows the code. Nothing is
   written yet.
2. **The approving side** (Settings > Connect another wallet) pastes the
   code, compares the fingerprint, and approves (`approveEnrollment`). The
   session's account-ceremony kind decides where the escrow falls.

   An ENROLLED client escrows first, decryption material before
   authorization. The user key wraps to the new client's key-agreement key
   in `key-map/user-key.jsonl`, into every epoch, so pre-enrollment history
   decrypts. The commit entry follows, then the add entry publishing the
   client's two verification methods and its update key, and no
   authorized-but-blind window opens.

   A LADDER signer runs commit, add, then escrow, since a ladder-signed
   roster append is licensed only at the inventory-changing version its own
   add entry mints. The window that opens is the branch's stated cost. The
   new client stands in the document holding `assertionMethod` and its own
   update key while holding no wrap. It is one request wide on the happy
   path, mended by a re-run with the same connect code or by the
   escrow-direction convergence of any later ladder-branch ceremony, and
   visible as a row in Connected wallets. The label write is best-effort on
   both kinds.

3. **Enrollee** ("finish connecting") verifies the enrollment from the
   world-readable log against the pointer's DID, makes its first roster read
   signed with its `<did:webvh>#<multibase>` key, unwraps the user key,
   persists the key set into the client-key record under the passphrase's
   unlock layer, stamped with the account controller, and logs in as an
   enrolled client.

**The connect code's keys must be canonical.** The enrolling client refuses
a code whose key-agreement key is not the canonical X25519 twin of its
signing key (`assertCanonicalEnrollmentKeys`, run inside the connect-code
parse, so the refusal lands before anything publishes). A client's
key-agreement method publishes under `controller: did:key:<its signing
multibase>` and every reader pairs the two by that claim, so without the
check an enrollee could publish a key-agreement key nobody can pair. Both
approval surfaces refuse.

Every stage is idempotent and the ceremony resumes from durable state alone,
so re-running with the same code converges. A tear after the roster write
leaves an orphan wrap, invisible to authorization and harmless. A tear
between the log entries is detected from the standing `nextKeyHashes`
commitments, so the add entry alone is appended and no fork is written.

**The rendezvous transport (onboarding another wallet).** When the enrollee
is a camera-holding wallet rather than a browser with a paste box, the same
ceremony runs over the WAS server's ephemeral-exchanges facet
(`/workflows/ephemeral/exchanges`). That facet is unauthenticated. The
unguessable exchange URL is the only access control, and it travels
point-to-point in the QR. Settings > Connected wallets > "Connect another
wallet" offers both halves, the QR invite and the paste-a-connect-code form.

The invite side creates an exchange whose stored request is a
`WalletOnboardingQuery` VPR carrying the account pointer and controller,
renders the interaction URL (`.../protocols?iuv=1`) as a QR code, and polls.
The other wallet scans it, mints its key set, and posts back an
onboarding-response envelope of the ordinary `freewallet-connect:` code plus
a suggested display label. An oversize or malformed envelope is refused
whole.

Poll completion swaps the card to a consent panel that must state four
things: the fingerprint comparison, leading, since anyone holding the
exchange URL could inject a response; the full-peer consequence (an enrolled
wallet reads and changes everything in the Space, connects apps, onboards or
disconnects other wallets, issues and revokes recovery codes); the
disconnect limitation; and an editable label prefilled from the envelope's
suggestion. Approval drives the same approve-and-label path as the paste
dialog. The channel carries only the four public key multibases and the
label, and the account pointer rides inside the stored request, bounded in
confidentiality by the exchange URL.
