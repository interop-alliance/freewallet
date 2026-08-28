/**
 * Freewallet's glue over the shared client enrollment ceremony
 * (`@interop/wallet-core/enrollment`): the two halves that need this app's own
 * session shape and its `freewallet-session` IndexedDB unlock layer.
 *
 * - `approveEnrollment` -- the enrolling client's half, guarding on the live
 *   session's profile and storage before handing the ceremony the stores and
 *   keys it needs.
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
import { sessionRosterStore } from '@/session/rosterStore'
import { assertAccountCeremonyAllowed } from '@/session/persistence'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import {
  bindPassphrase,
  deriveUnlockCredential,
  fetchKeyring
} from '@/session/keyring'
import { loginWithPassphrase } from '@/session/initSession'
import { invalidateVerifiedLog } from '@/session/verifiedLog'
import { requireEnrolledClientContext } from '@/session/enrolledContext'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:enrollment')

/**
 * ENROLLING CLIENT: approves a connect code the person has compared against
 * the enrollee's screen. Guards that this session can actually run the
 * ceremony (a configured WAS server, and this client's own did:webvh update
 * keys and key-agreement key in memory), then runs the shared push-order
 * ceremony: the user key wrap lands in the `key-map/user-key.jsonl` roster log
 * first, and only then the two did:webvh log entries publish.
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
  assertAccountCeremonyAllowed({
    persistence: session.profile.persistence,
    ceremony: 'Approving a wallet enrollment'
  })
  const { remoteStore, clientWebvhKeys, clientKeyAgreementKey } =
    requireEnrolledClientContext({ session, action: 'Enrollment' })
  const { profile } = session

  // The approval publishes the new client's log entries (and a torn approval
  // may have published the commit entry before failing), so this session's
  // verified-log memo is dropped either way -- the listing that renders right
  // afterwards must show the newly enrolled client.
  const approved = await approveEnrollmentCore({
    request,
    clientWebvhKeys,
    clientKeyAgreementKey,
    userKeyRosterStore: sessionRosterStore({ profile }),
    idStore: remoteStore.webvhIdStore()
  }).finally(() => invalidateVerifiedLog({ profile }))
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
