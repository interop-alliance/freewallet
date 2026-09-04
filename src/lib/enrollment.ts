/**
 * Freewallet's glue over the shared client enrollment ceremony
 * (`@interop/wallet-core/enrollment`): the two halves that need this app's own
 * session shape and its `freewallet-session` IndexedDB unlock layer.
 *
 * - `approveEnrollment` -- the approving half, resolving this session's
 *   account-ceremony context (an enrolled client's own keys, or a standing
 *   credential's ladder on a transient session) and handing the ceremony the
 *   signer, the stores and the keys that kind acts with.
 * - `completeEnrollment` -- the enrollee's half: the account pointer comes out
 *   of the keyring (the enrollee holds the passphrase), the portable core
 *   verifies and reads the roster, the key set is persisted under the
 *   passphrase's unlock layer here, and the ordinary passphrase login it now
 *   finds is run in the same call -- one derived unlock identity for all
 *   three, so the ceremony runs its KDF once.
 *
 * Everything else in the ceremony -- the connect-code codec,
 * `mintEnrollmentRequest`, `EnrollmentPendingError` -- is imported from
 * wallet-core directly at its call sites.
 */
import {
  approveEnrollment as approveEnrollmentCore,
  completeEnrollmentCore,
  type EnrollmentRequest
} from '@interop/wallet-core/enrollment'
import {
  isWebvhDid,
  type ClientWebvhUpdateKeys
} from '@interop/wallet-core/webvh'
import { setClientLabel } from '@interop/wallet-core/keys'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import { WAS_SERVER_URL } from '@/app.config'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import {
  bindPassphrase,
  deriveUnlockCredential,
  fetchKeyring
} from '@/session/keyring'
import { loginWithPassphrase } from '@/session/initSession'
import {
  invalidateVerifiedLog,
  reprimeVerifiedAccountLog
} from '@/session/verifiedLog'
import { accountCeremonyContext } from '@/session/accountCeremonyContext'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:enrollment')

/**
 * THE APPROVING SIDE: approves a connect code the person has compared against
 * the enrollee's screen. It resolves the account-ceremony context and runs the
 * shared ceremony on whichever kind this session is.
 *
 * On the ENROLLED kind the order is the push order it has always been: the
 * user key wrap lands in the `key-map/user-key.jsonl` roster log first, and
 * only then the two did:webvh log entries publish. An enrolled client's
 * roster append needs no license, so nothing forces the flip.
 *
 * On the LADDER kind (a transient session on a standing unlock credential)
 * the order is commit entry, add entry, then the escrow append. A
 * ladder-signed append is licensed only at an inventory-changing version its
 * own ladder signed, and the add entry is what mints that version. wallet-core
 * places the escrow by signer kind, so both orders come out of one body. The
 * one-request window between the add entry and the append is the ladder
 * branch's stated cost: the new client stands in the document holding no
 * wrap. It is mended by a re-run with the same connect code, by the
 * escrow-direction convergence of any later ladder-branch ceremony, and by a
 * disconnect from the Connected wallets listing the row now appears in.
 *
 * @param options {object}
 * @param options.request {EnrollmentRequest}   the parsed connect code
 * @param options.session {Session}   the approving session
 * @param [options.label] {string}   a display label for the new client,
 *   chosen here at approval (the document carries key material, never
 *   labels, so it lands in `key-map/client-labels.json`); best-effort -- a
 *   label write failure never fails the completed ceremony
 * @returns {Promise<object>}   the account's did:webvh, plus the newly
 *   enrolled client's own identity as the ceremony states it (its did:key and
 *   its signing-key multibase -- what a label or a listing row is filed under)
 */
export async function approveEnrollment({
  request,
  session,
  label
}: {
  request: EnrollmentRequest
  session: Session
  label?: string
}): Promise<{ did: string; clientDid: string; signingKeyMultibase: string }> {
  const context = await accountCeremonyContext({ session })
  if (!context) {
    throw new Error(
      'Connecting another wallet needs an account on a storage server, ' +
        'reached either from a connected browser or with a standing ' +
        'passphrase or passkey; this session holds neither.'
    )
  }
  const { remoteStore, pointer } = context
  const { profile } = session
  // The party that unwraps each epoch to re-wrap it for the enrollee: this
  // client's own key-agreement key when one is enrolled here, the acting
  // credential's standing key on the ladder kind.
  const clientKeyAgreementKey =
    context.kind === 'enrolled'
      ? context.clientKeyAgreementKey
      : context.standingKeyAgreementKey

  // The memo is dropped BEFORE the ceremony as well as after it. On the
  // ladder kind the escrow append is licensed only at the version the add
  // entry mints, and the roster store resolves its controller view through
  // this memo -- a view primed before the entries (the Connected wallets
  // listing that opened this dialog primes one) would anchor the append at
  // the pre-add head, which licenses nothing (`ResourceLogLicenseError`).
  // Dropped here, the append's own resolution fetches the post-add log.
  invalidateVerifiedLog({ profile })
  // The approval publishes the new client's log entries (and a torn approval
  // may have published the commit entry before failing), so this session's
  // verified-log memo is dropped afterwards too -- the listing that renders
  // right afterwards must show the newly enrolled client.
  const approved = await approveEnrollmentCore({
    request,
    signer: context.signer,
    clientKeyAgreementKey,
    userKeyRosterStore: context.rosterStore,
    idStore: context.idStore
  }).finally(() => invalidateVerifiedLog({ profile }))
  // Nothing else on a transient session re-settles the memo, and the surfaces
  // that peek it (the Key Management chip, the DIDAuth holder dispatch) would
  // read cold until some other section fetched. Best-effort.
  await reprimeVerifiedAccountLog({ profile, pointer })
  if (label?.trim()) {
    try {
      await setClientLabel({
        store: remoteStore.clientLabelsStore(),
        signingKeyMultibase: approved.signingKeyMultibase,
        label
      })
    } catch (err) {
      log.warn("Could not save the new client's label", { err })
    }
  }
  return approved
}

/**
 * ENROLLEE, step two (after the other browser approves): looks the account up
 * from the passphrase's keyring, runs the shared verification + first roster
 * read, and persists the whole key set into the local client-key record under
 * the passphrase's unlock layer, then performs the ordinary passphrase login
 * that now finds an enrolled client and hands its session back.
 *
 * Throws `EnrollmentPendingError` while the add entry is not published yet
 * (complete again once the other browser finishes); any integrity failure
 * (a log that resolves to a different DID than the account pointer names, a
 * missing roster wrap) throws its own error.
 *
 * The unlock identity is derived ONCE here and threaded through all three
 * unlock-layer steps (the keyring lookup, the key-set bind, and the login
 * that ends the ceremony), so finishing an enrollment runs the 600k-iteration
 * KDF a single time.
 *
 * @param options {object}
 * @param options.clientSeed {Uint8Array}   from `mintEnrollmentRequest`
 * @param options.webvhUpdateKeys {ClientWebvhUpdateKeys}   from
 *   `mintEnrollmentRequest`
 * @param options.passphrase {string}   the account passphrase (it located the
 *   account; enrollment is what makes it sufficient to act here)
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<Session>}   the logged-in session of the newly enrolled
 *   client, exactly as an ordinary passphrase login builds it
 */
export async function completeEnrollment({
  clientSeed,
  webvhUpdateKeys,
  passphrase,
  idb
}: {
  clientSeed: Uint8Array
  webvhUpdateKeys: ClientWebvhUpdateKeys
  passphrase: string
  idb?: IDBFactory
}): Promise<Session> {
  if (!WAS_SERVER_URL) {
    throw new Error('Enrollment requires a configured WAS server.')
  }
  const credential = await deriveUnlockCredential({
    secret: passphrase,
    kdf: KEYRING_KDF
  })
  const found = await fetchKeyring({ passphrase, credential, idb })
  if (!found) {
    throw new Error('No account was found for this passphrase.')
  }
  const pointer = found.pointer
  // The ceremony core refuses a pointer that names no did:webvh, so the
  // promoted-account check is made here rather than left to fail deeper in.
  if (!pointer || !isWebvhDid(pointer.did)) {
    throw new Error(
      'The account pointer names no did:webvh; only a promoted account can ' +
        'enroll additional clients.'
    )
  }
  const { userKey } = await completeEnrollmentCore({
    clientSeed,
    webvhUpdateKeys,
    pointer,
    // The ceremony's own in-memory chain-head pin: one enrollment reads the
    // log more than once, and nothing about the pin outlives the ceremony.
    accountLogPinStore: memoryResourceLogPinStore()
  })

  // Persist the key set under the unlock layer (this also pins the account
  // pointer and refreshes the keyring cache); the next passphrase login
  // finds an enrolled client. A standing record's members -- the bridge
  // delegation, the annex-Space `delegatedClients` sibling, the ladder seed
  // -- are re-stated whole (spread, not enumerated), so the rebind can
  // never downgrade the credential's standing authority to a plain pointer
  // record or drop a member the transient login depends on.
  await bindPassphrase({
    clientSeed,
    controller: found.controller,
    passphrase,
    email: found.email,
    userKey,
    webvhUpdateKeys,
    pointer,
    ...(found.standing ?? {}),
    credential,
    idb
  })

  // The ordinary login the ceremony ends in, on the identity already derived:
  // the caller gets the same session shape every other login path returns.
  const { session } = await loginWithPassphrase({ passphrase, credential, idb })
  if (!session) {
    throw new Error(
      'The enrolled key set did not produce a session; connecting this ' +
        'browser again mints a fresh key set.'
    )
  }
  return session
}
