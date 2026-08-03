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
 *   verifies and reads the roster, and the key set is persisted under the
 *   passphrase's unlock layer here, so the next ordinary login finds an
 *   enrolled client.
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
import type { ClientWebvhUpdateKeys } from '@interop/wallet-core/webvh'
import { setClientLabel } from '@interop/wallet-core/keys'
import { WAS_SERVER_URL } from '@/app.config'
import { savePukEpochPin } from '@/lib/sessionKey'
import { bindPassphrase, fetchKeyring } from '@/session/keyring'
import type { ControllerProfile } from '@/types/auth'
import type { StorageManager } from '@/stores/storageManager'

/**
 * ENROLLING CLIENT: approves a connect code the person has compared against
 * the enrollee's screen. Guards that this session can actually run the
 * ceremony (a configured WAS server, and this client's own did:webvh update
 * keys and key-agreement key in memory), then runs the shared push-order
 * ceremony: the PUK wrap lands in `key-map/puk.json` first, and only then the
 * two did:webvh log entries publish.
 *
 * @param options {object}
 * @param options.request {EnrollmentRequest}   the parsed connect code
 * @param options.profile {ControllerProfile}   the approving session's profile
 * @param options.storage {StorageManager}   the approving session's storage
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
  profile,
  storage,
  label
}: {
  request: EnrollmentRequest
  profile: ControllerProfile
  storage: StorageManager
  label?: string
}): Promise<{ did: string; clientDid: string; signingKeyMultibase: string }> {
  const remoteStore = storage.remoteStore
  if (!remoteStore) {
    throw new Error('Enrollment requires a configured WAS server.')
  }
  if (!profile.clientWebvhKeys) {
    throw new Error(
      "Enrollment requires this client's did:webvh update keys; this " +
        'session does not hold them.'
    )
  }
  if (!profile.clientKeyAgreementKey) {
    throw new Error(
      "Enrollment requires this client's key-agreement key; this session " +
        'does not hold it.'
    )
  }

  const approved = await approveEnrollmentCore({
    request,
    clientWebvhKeys: profile.clientWebvhKeys,
    clientKeyAgreementKey: profile.clientKeyAgreementKey,
    pukRosterStore: remoteStore.pukRosterStore(),
    idStore: remoteStore.webvhIdStore()
  })
  if (label?.trim()) {
    try {
      await setClientLabel({
        store: remoteStore.clientLabelsStore(),
        signingKeyMultibase: approved.signingKeyMultibase,
        label
      })
    } catch (err) {
      console.warn("Could not save the new client's label:", err)
    }
  }
  return approved
}

/**
 * ENROLLEE, step two (after the other browser approves): looks the account up
 * from the passphrase's keyring, runs the shared verification + first roster
 * read, and persists the whole key set into the local client-key record under
 * the passphrase's unlock layer. After this an ordinary passphrase login finds
 * an enrolled client.
 *
 * Throws `EnrollmentPendingError` while the add entry is not published yet
 * (complete again once the other browser finishes); any integrity failure
 * (a log that resolves to a different DID than the account pointer names, a
 * missing roster wrap) throws its own error.
 *
 * @param options {object}
 * @param options.clientSeed {Uint8Array}   from `mintEnrollmentRequest`
 * @param options.webvhUpdateKeys {ClientWebvhUpdateKeys}   from
 *   `mintEnrollmentRequest`
 * @param options.passphrase {string}   the account passphrase (it located the
 *   account; enrollment is what makes it sufficient to act here)
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
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
}): Promise<void> {
  if (!WAS_SERVER_URL) {
    throw new Error('Enrollment requires a configured WAS server.')
  }
  const found = await fetchKeyring({ passphrase, idb })
  if (!found) {
    throw new Error('No account was found for this passphrase.')
  }
  const pointer = found.pointer
  if (!pointer) {
    throw new Error(
      'The account pointer names no did:webvh; only a promoted account can ' +
        'enroll additional clients.'
    )
  }

  const { puk, latestEpochId } = await completeEnrollmentCore({
    clientSeed,
    webvhUpdateKeys,
    pointer
  })
  await savePukEpochPin({
    spaceId: pointer.spaceId,
    epochId: latestEpochId,
    idb
  })

  // Persist the key set under the unlock layer (this also pins the account
  // pointer and refreshes the keyring cache); the next passphrase login
  // finds an enrolled client.
  await bindPassphrase({
    clientSeed,
    controller: found.controller,
    passphrase,
    email: found.email,
    puk,
    webvhUpdateKeys,
    pointer,
    idb
  })
}
