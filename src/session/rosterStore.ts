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
 * Both builders return wallet-core's sealable store unwrapped, so the
 * revocation cascade's controller-floor contract (`setControllerFloor`, set by
 * the shared orchestrator from the document edit's own post-edit log) reaches
 * the store as-is.
 *
 * The chain-head pin is in-memory on either persistence variant: the
 * session builder takes it from the profile's persistence strategy, and the
 * bare-parts builder mints its own unless a `pinStore` is supplied. It
 * guards one visit's several roster reads against a host serving
 * inconsistent versions across them, and remembers nothing past the tab. The
 * bare-parts builder's own `verifyAccountLog` read carries the same store
 * for the account-log chain-head pin; the session builder's read gets it
 * inside the verified-log memo. A bare-parts caller inside a ceremony that
 * already stands on a head hands it over instead, and makes no read at all.
 */
import type { DIDLog } from '@interop/did-method-webvh'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import {
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner
} from '@interop/wallet-core/keys'
import type { SealableEncryptionDescriptorStore } from '@interop/wallet-core/keys'
import {
  webvhResourceLogController,
  type WebvhResourceLogController
} from '@interop/wallet-core/resourceLog'
import {
  verifyAccountLog,
  type ICapabilityAgent
} from '@interop/wallet-core/webvh'
import type { AccountLogPointer } from '@interop/wallet-core/clients'
import {
  memoryResourceLogPinStore,
  type ResourceLogPinStore
} from '@interop/vh-resource-log'
import type { ControllerProfile } from '@/types/auth'
import { verifiedAccountLog } from '@/session/verifiedLog'

/**
 * Builds the roster store from bare parts, for callers with no session
 * profile. The controller view is resolved per operation from a fresh
 * `verifyAccountLog` of the pointer (memoized as the in-flight promise per
 * store instance, so one read does not verify the log twice), never from the
 * channel the roster came from.
 *
 * A caller inside a ceremony that just read or published the account log
 * hands that head over as `log` instead: the controller view is built from
 * it and `did.jsonl` is never fetched. The head carries this run's own
 * verification -- the ceremony resolved it and checked it against the same
 * chain-head pin before handing it on -- so the seed is only ever a head
 * from within one run, never one carried across visits.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the signing client for the WAS
 *   requests (promoted where the account is)
 * @param options.keyAgent {ICapabilityAgent}   this client's signing key
 *   agent -- its enrolled key signs the log appends
 * @param options.pointer {AccountLogPointer}   the account pointer; its `did`
 *   must name the did:webvh the roster log's entry proofs anchor to
 * @param [options.pinStore] {ResourceLogPinStore}   the chain-head pin store,
 *   overriding the fresh in-memory default -- pass the session's own log-pin
 *   member so this log's continuity is checked alongside the account log's
 * @param [options.log] {DIDLog}   the account log this run already stands on
 *   (a ceremony's own published or adopted head), used in place of the fetch
 * @returns {SealableEncryptionDescriptorStore}
 */
export function accountRosterStore({
  zcapClient,
  keyAgent,
  pointer,
  pinStore,
  log
}: {
  zcapClient: ZcapClient
  keyAgent: ICapabilityAgent
  pointer: AccountLogPointer
  pinStore?: ResourceLogPinStore
  log?: DIDLog
}): SealableEncryptionDescriptorStore {
  const pins = pinStore ?? memoryResourceLogPinStore()
  // A seeded head resolves the controller view once, for the life of this
  // store: it is what the run itself published or adopted, so re-reading
  // `did.jsonl` could only serve something the run has not built on.
  let pending: Promise<WebvhResourceLogController> | undefined = log
    ? Promise.resolve(webvhResourceLogController({ did: pointer.did, log }))
    : undefined
  return userKeyRosterDescriptorStore({
    storageServerUrl: pointer.host,
    zcapClient,
    spaceId: pointer.spaceId,
    resolveController: async () => {
      pending ??= verifyAccountLog({
        did: pointer.did,
        spaceId: pointer.spaceId,
        host: pointer.host,
        pinStore: pins
      }).then(
        ({ log: served }) =>
          webvhResourceLogController({ did: pointer.did, log: served }),
        err => {
          pending = undefined
          throw err
        }
      )
      return await pending
    },
    pinStore: pins,
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
 *   must hold a key agent and an account pointer naming a did:webvh. The
 *   chain-head pin rides the profile's persistence strategy.
 * @param [options.capability] {IZcap}   an invocation capability every request
 *   rides (a transient session's generation delegation, the only authority
 *   that session holds); the root capability is invoked otherwise
 * @returns {SealableEncryptionDescriptorStore}
 */
export function sessionRosterStore({
  profile,
  capability
}: {
  profile: ControllerProfile
  capability?: IZcap
}): SealableEncryptionDescriptorStore {
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
    pinStore: profile.persistence.logPins,
    signer: userKeyRosterLogSigner({ keyAgent }),
    ...(capability ? { capability } : {})
  })
}
