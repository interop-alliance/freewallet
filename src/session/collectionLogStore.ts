/**
 * Builders for the log-governed collection descriptor stores: freewallet's
 * wiring of wallet-core's `collectionDescriptorLogStore`, one per encrypted
 * collection, over the collection's own `meta/log` sub-resource. A store's
 * reads resolve to the log's verified head (entry proofs checked against the
 * locally verified did:webvh document, chain-head pin enforced) and its
 * writes are signed log appends, exactly the shape the user key roster store
 * in `rosterStore.ts` has, applied to the descriptors that carry the key
 * epochs.
 *
 * Two builders for the two caller shapes, mirroring the roster's:
 *
 * - `accountCollectionStores` -- the bare parts (a signing client, a key
 *   agent, an account pointer naming a did:webvh), for callers with no
 *   session profile: the geneses, the mend, and the recovery continuations.
 * - `sessionCollectionStores` -- a live session, resolving the controller
 *   view through the profile's verified-log memo, and reaching each
 *   collection through the remote store's handle so every request rides the
 *   capability the session holds at call time.
 *
 * Each builder returns a lookup, `(collectionId) => store`, since that is
 * the seam wallet-core's epoch installers and the cascade take. The
 * controller view is resolved once per lookup instance and shared across
 * its collections, so a fan-out over six collections verifies the account
 * log once. Beside the builders, `sessionCollectionDescriptorSource` is the
 * read-only counterpart the storage layer acquires descriptors through, and
 * `descriptorLogSignerAgent` names which key a session's appends sign with:
 * the enrolled client's own on a remembered session, the credential's
 * ladder VM on a transient one.
 */
import type { DIDLog } from '@interop/did-method-webvh'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { WasClient, type Space } from '@interop/was-client'
import { resourceLogStore } from '@interop/was-client/log'
import type { EncryptionDescriptorSource } from '@interop/was-client/edv'
import {
  collectionDescriptorLogStore,
  userKeyRosterLogSigner,
  type SealableEncryptionDescriptorStore
} from '@interop/wallet-core/keys'
import { logGovernedDescriptorSource } from '@interop/wallet-core/descriptors'
import {
  webvhResourceLogController,
  type WebvhResourceLogController
} from '@interop/wallet-core/resourceLog'
import {
  verifyAccountLog,
  type ICapabilityAgent
} from '@interop/wallet-core/webvh'
import type { AccountLogPointer } from '@interop/wallet-core/clients'
import { ladderVmAgent } from '@interop/wallet-core/clientAnnex'
import {
  memoryResourceLogPinStore,
  type ResourceLogPinStore,
  type ResourceLogSigner
} from '@interop/vh-resource-log'
import type { ControllerProfile } from '@/types/auth'
import { isBrowserLocalSession } from '@/session/persistence'
import { verifiedAccountLog } from '@/session/verifiedLog'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

/**
 * The per-collection store lookup wallet-core's installers and the cascade
 * take.
 */
export type CollectionStoreFor = (
  collectionId: string
) => SealableEncryptionDescriptorStore

/**
 * Builds the per-collection stores from bare parts, for callers with no
 * session profile. The controller view is resolved from a fresh
 * `verifyAccountLog` of the pointer, memoized as the in-flight promise for
 * the life of the lookup so a fan-out over every collection verifies the
 * account log once; a caller inside a ceremony that just read or published
 * the log hands that head over as `log` instead, and `did.jsonl` is never
 * fetched.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the signing client for the WAS
 *   requests
 * @param options.keyAgent {ICapabilityAgent}   the agent whose key signs the
 *   log appends; it must be listed under `assertionMethod` in the account
 *   document at the version each append anchors at
 * @param options.pointer {AccountLogPointer}   the account pointer; its `did`
 *   must name the did:webvh the logs' entry proofs anchor to
 * @param [options.pinStore] {ResourceLogPinStore}   the chain-head pin store,
 *   overriding the fresh in-memory default
 * @param [options.log] {DIDLog}   the account log this run already stands on
 * @param [options.capability] {IZcap}   an invocation capability every
 *   request rides (a transient visit's generation delegation)
 * @returns {CollectionStoreFor}
 */
export function accountCollectionStores({
  zcapClient,
  keyAgent,
  pointer,
  pinStore,
  log,
  capability
}: {
  zcapClient: ZcapClient
  keyAgent: ICapabilityAgent
  pointer: AccountLogPointer
  pinStore?: ResourceLogPinStore
  log?: DIDLog
  capability?: IZcap
}): CollectionStoreFor {
  const pins = pinStore ?? memoryResourceLogPinStore()
  // Built on the first lookup, so a lookup handed to a ceremony that never
  // installs or rotates an epoch costs nothing.
  let space: Space | undefined
  let signer: ResourceLogSigner | undefined
  let pending: Promise<WebvhResourceLogController> | undefined = log
    ? Promise.resolve(webvhResourceLogController({ did: pointer.did, log }))
    : undefined
  const resolveController = async () => {
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
  }
  return collectionId => {
    space ??= new WasClient({ serverUrl: pointer.host, zcapClient }).space(
      pointer.spaceId,
      { capability }
    )
    signer ??= userKeyRosterLogSigner({ keyAgent })
    return collectionDescriptorLogStore({
      collection: space.collection(collectionId),
      resolveController,
      pinStore: pins,
      signer
    })
  }
}

/**
 * Builds the per-collection stores for a live session: each collection is
 * reached through the remote store's handle (so a request rides whatever
 * capability the store holds at call time, the generation delegation a
 * transient session renews mid-run included), the controller view comes
 * from the profile's verified-log memo, and the chain-head pins ride the
 * profile's persistence strategy.
 *
 * @param options {object}
 * @param options.profile {ControllerProfile}   the live session's profile; its
 *   account pointer must name a did:webvh
 * @param options.remoteStore {WASRemoteStore}   the session's remote store
 * @param options.keyAgent {ICapabilityAgent}   the agent whose key signs the
 *   appends (`descriptorLogSignerAgent` names the session's default)
 * @returns {CollectionStoreFor}
 */
export function sessionCollectionStores({
  profile,
  remoteStore,
  keyAgent
}: {
  profile: ControllerProfile
  remoteStore: WASRemoteStore
  keyAgent: ICapabilityAgent
}): CollectionStoreFor {
  const pointer = profile.accountPointer
  if (!pointer?.did) {
    throw new Error(
      'The collection descriptor stores need an account pointer naming a ' +
        'DID; this session holds none.'
    )
  }
  const did = pointer.did
  let signer: ResourceLogSigner | undefined
  return collectionId => {
    signer ??= userKeyRosterLogSigner({ keyAgent })
    return collectionDescriptorLogStore({
      collection: remoteStore.collectionHandle({ collectionId }),
      resolveController: async () => {
        const { log } = await verifiedAccountLog({ profile })
        return webvhResourceLogController({ did, log })
      },
      pinStore: profile.persistence.logPins,
      signer
    })
  }
}

/**
 * The read-only descriptor source for a live session: each collection's
 * descriptor is the verified head of its governing log, read under the
 * session's pins and the profile's verified-log memo. It is what the storage
 * layer acquires descriptors through at login and on an unknown-epoch
 * refresh, in place of the served Collection Description member.
 *
 * @param options {object}
 * @param options.profile {ControllerProfile}   its account pointer must name a
 *   did:webvh
 * @param options.remoteStore {WASRemoteStore}
 * @returns {EncryptionDescriptorSource}
 */
export function sessionCollectionDescriptorSource({
  profile,
  remoteStore
}: {
  profile: ControllerProfile
  remoteStore: WASRemoteStore
}): EncryptionDescriptorSource {
  const pointer = profile.accountPointer
  if (!pointer?.did) {
    throw new Error(
      'The collection descriptor source needs an account pointer naming a ' +
        'DID; this session holds none.'
    )
  }
  const did = pointer.did
  return logGovernedDescriptorSource({
    logFor: (collectionId: string) =>
      resourceLogStore({
        collection: remoteStore.collectionHandle({ collectionId })
      }),
    resolveController: async () => {
      const { log } = await verifiedAccountLog({ profile })
      return webvhResourceLogController({ did, log })
    },
    pinStore: profile.persistence.logPins,
    spaceId: remoteStore.spaceId
  })
}

/**
 * The agent whose key signs a session's descriptor-log appends. A
 * remembered session signs with the enrolled client's own key, which the
 * account document lists. A transient session's per-visit key stands in no
 * account document, so it signs with the login credential's ladder VM
 * (`profile.ladderSeed`), admitted on `assertionMethod` membership alone.
 * Read off the profile at each call rather than captured, since a passphrase
 * change restamps the seed mid-session.
 *
 * @param options {object}
 * @param options.profile {ControllerProfile}
 * @returns {Promise<ICapabilityAgent>}
 */
export async function descriptorLogSignerAgent({
  profile
}: {
  profile: ControllerProfile
}): Promise<ICapabilityAgent> {
  if (isBrowserLocalSession(profile.persistence)) {
    if (!profile.keyAgent) {
      throw new Error(
        'Signing a collection descriptor log needs this client key agent; ' +
          'this session holds none.'
      )
    }
    return profile.keyAgent
  }
  if (!profile.ladderSeed) {
    throw new Error(
      'Signing a collection descriptor log from a transient session needs ' +
        "the login credential's ladder seed; this session holds none."
    )
  }
  return await ladderVmAgent({ ladderSeed: profile.ladderSeed })
}
