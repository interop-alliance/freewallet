/**
 * Builders for the log-governed user key roster store
 * (`key-map/user-key.jsonl`): freewallet's wiring of wallet-core's
 * `userKeyRosterDescriptorStore` -- the store whose reads resolve to the
 * roster log's verified head (entry proofs checked against the locally
 * verified did:webvh document, chain-head pin enforced) and whose writes are
 * signed log appends.
 *
 * Two builders for the two caller shapes:
 *
 * - `accountRosterStore` -- the bare parts (a signing client, a key agent, an
 *   account pointer naming a did:webvh), for callers with no session profile:
 *   the login-time direct read, and the recovery continuation's fresh client.
 * - `sessionRosterStore` -- a live session, resolving the controller view
 *   through the profile's verified-log memo so ceremonies that just extended
 *   the log (and invalidated the memo) anchor their appends at the post-edit
 *   head.
 *
 * The chain-head pin is durable either way (`userKeyLogPinStore`, keyed by
 * the data Space id in the session database), so log continuity spans logins,
 * not just one session. The bare-parts builder's own `verifyAccountLog` read
 * carries the account-log chain-head pin (`accountLogPinStore`) the same way;
 * the session builder's read gets it inside the verified-log memo.
 */
import type { ZcapClient } from '@interop/ezcap'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner
} from '@interop/wallet-core/keys'
import { webvhResourceLogController } from '@interop/wallet-core/resourceLog'
import type { ResourceLogController } from '@interop/wallet-core/resourceLog'
import {
  verifyAccountLog,
  type ICapabilityAgent
} from '@interop/wallet-core/webvh'
import type { AccountLogPointer } from '@interop/wallet-core/clients'
import type { ControllerProfile } from '@/types/auth'
import { accountLogPinStore, userKeyLogPinStore } from '@/lib/sessionKey'
import { verifiedAccountLog } from '@/session/verifiedLog'

/**
 * Builds the roster store from bare parts, for callers with no session
 * profile. The controller view is resolved per operation from a fresh
 * `verifyAccountLog` of the pointer (memoized as the in-flight promise per
 * store instance, so one read does not verify the log twice), never from the
 * channel the roster came from.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the signing client for the WAS
 *   requests (promoted where the account is)
 * @param options.keyAgent {ICapabilityAgent}   this client's signing key
 *   agent -- its enrolled key signs the log appends
 * @param options.pointer {AccountLogPointer}   the account pointer; its `did`
 *   must name the did:webvh the roster log's entry proofs anchor to
 * @param [options.idb] {IDBFactory}   first-party IndexedDB for the chain-head
 *   pin (CHAPI popups thread the Storage Access API handle here)
 * @returns {EncryptionDescriptorStore}
 */
export function accountRosterStore({
  zcapClient,
  keyAgent,
  pointer,
  idb
}: {
  zcapClient: ZcapClient
  keyAgent: ICapabilityAgent
  pointer: AccountLogPointer
  idb?: IDBFactory
}): EncryptionDescriptorStore {
  let pending: Promise<ResourceLogController> | undefined
  return userKeyRosterDescriptorStore({
    storageServerUrl: pointer.host,
    zcapClient,
    spaceId: pointer.spaceId,
    resolveController: async () => {
      pending ??= verifyAccountLog({
        did: pointer.did,
        spaceId: pointer.spaceId,
        host: pointer.host,
        pinStore: accountLogPinStore({ spaceId: pointer.spaceId, idb })
      }).then(
        ({ log }) => webvhResourceLogController({ did: pointer.did, log }),
        err => {
          pending = undefined
          throw err
        }
      )
      return await pending
    },
    pinStore: userKeyLogPinStore({ spaceId: pointer.spaceId, idb }),
    signer: userKeyRosterLogSigner({ keyAgent })
  })
}

/**
 * Builds the roster store for a live session: signing under the profile's
 * (promoted) zcap client and key agent, resolving the controller view through
 * the profile's verified-log memo -- so a ceremony that just extended the
 * account log and dropped the memo writes its roster appends anchored at the
 * post-edit head, and steady-state surfaces share one log verification.
 *
 * @param options {object}
 * @param options.profile {ControllerProfile}   the live session's profile; it
 *   must hold a key agent and an account pointer naming a did:webvh
 * @param [options.idb] {IDBFactory}
 * @returns {EncryptionDescriptorStore}
 */
export function sessionRosterStore({
  profile,
  idb
}: {
  profile: ControllerProfile
  idb?: IDBFactory
}): EncryptionDescriptorStore {
  const pointer = profile.accountPointer
  const { keyAgent } = profile
  if (!pointer?.did || !keyAgent) {
    throw new Error(
      'The user key roster store needs an account pointer naming a DID and ' +
        'this client key agent; this session holds none.'
    )
  }
  const spaceId = pointer.spaceId
  return userKeyRosterDescriptorStore({
    storageServerUrl: pointer.host,
    zcapClient: profile.zcapClient,
    spaceId,
    resolveController: async () => {
      const { log } = await verifiedAccountLog({ profile })
      return webvhResourceLogController({ did: pointer.did!, log })
    },
    pinStore: userKeyLogPinStore({ spaceId, idb }),
    signer: userKeyRosterLogSigner({ keyAgent })
  })
}
