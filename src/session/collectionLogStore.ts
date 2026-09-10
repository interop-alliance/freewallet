/**
 * The session-shaped wiring of the log-governed collection descriptor
 * stores: one per encrypted collection, over the collection's own
 * `meta/log` sub-resource. A store's reads resolve to the log's verified
 * head (entry proofs checked against the locally verified did:webvh
 * document, chain-head pin enforced) and its writes are signed log appends,
 * exactly the shape the user key roster store in `rosterStore.ts` has,
 * applied to the descriptors that carry the key epochs.
 *
 * The builders themselves live in `@interop/wallet-core/keys`:
 * `accountCollectionStores` takes bare parts (a signing client, a signer,
 * the account DID and Space) for callers with no session profile (the
 * geneses, the mend, the recovery continuations), and
 * `collectionDescriptorStores` takes the collection reach and the controller
 * resolver as functions. `sessionCollectionStores` here is the live
 * session's binding onto the latter: the controller view comes from the
 * profile's verified-log memo, and each collection is reached through the
 * remote store's handle so every request rides the capability the session
 * holds at call time. Beside it, `sessionCollectionDescriptorSource` is the
 * read-only counterpart the storage layer acquires descriptors through, and
 * `descriptorLogSignerAgent` names which key a session's appends sign with:
 * the enrolled client's own on a remembered session, the credential's
 * ladder VM on a transient one.
 */
import { resourceLogStore } from '@interop/was-client/log'
import type { EncryptionDescriptorSource } from '@interop/was-client/edv'
import {
  collectionDescriptorStores,
  userKeyRosterLogSigner,
  type CollectionStoreFor
} from '@interop/wallet-core/keys'
import { logGovernedDescriptorSource } from '@interop/wallet-core/descriptors'
import { webvhResourceLogController } from '@interop/wallet-core/resourceLog'
import type { ICapabilityAgent } from '@interop/wallet-core/webvh'
import { ladderVmAgent } from '@interop/wallet-core/clientAnnex'
import type { SessionCore } from '@/types/auth'
import { isBrowserLocalSession } from '@/session/persistence'
import { verifiedAccountLog } from '@/session/verifiedLog'
import type { WASRemoteStore } from '@/stores/wasRemoteStore'

/**
 * Builds the per-collection stores for a live session over wallet-core's
 * `collectionDescriptorStores`: each collection is reached through the
 * remote store's handle (so a request rides whatever capability the store
 * holds at call time, the generation delegation a transient session renews
 * mid-run included), the controller view comes from the profile's
 * verified-log memo, and the chain-head pins ride the session's persistence
 * strategy.
 *
 * @param options {object}
 * @param options.session {object}   the live session's profile and
 *   persistence strategy; the profile's account pointer must name a did:webvh
 * @param options.remoteStore {WASRemoteStore}   the session's remote store
 * @param options.keyAgent {ICapabilityAgent}   the agent whose key signs the
 *   appends (`descriptorLogSignerAgent` names the session's default)
 * @returns {CollectionStoreFor}
 */
export function sessionCollectionStores({
  session,
  remoteStore,
  keyAgent
}: {
  session: SessionCore
  remoteStore: WASRemoteStore
  keyAgent: ICapabilityAgent
}): CollectionStoreFor {
  const { profile, persistence } = session
  const pointer = profile.accountPointer
  if (!pointer?.did) {
    throw new Error(
      'The collection descriptor stores need an account pointer naming a ' +
        'DID; this session holds none.'
    )
  }
  const did = pointer.did
  return collectionDescriptorStores({
    collectionFor: collectionId =>
      remoteStore.collectionHandle({ collectionId }),
    resolveController: async () => {
      const { log } = await verifiedAccountLog({ session })
      return webvhResourceLogController({ did, log })
    },
    pinStore: persistence.logPins,
    signer: userKeyRosterLogSigner({ keyAgent })
  })
}

/**
 * The read-only descriptor source for a live session: each collection's
 * descriptor is the verified head of its governing log, read under the
 * session's pins and the profile's verified-log memo. It is what the storage
 * layer acquires descriptors through at login and on an unknown-epoch
 * refresh, in place of the served Collection Description member.
 *
 * @param options {object}
 * @param options.session {object}   the live session's profile and
 *   persistence strategy; the profile's account pointer must name a did:webvh
 * @param options.remoteStore {WASRemoteStore}
 * @returns {EncryptionDescriptorSource}
 */
export function sessionCollectionDescriptorSource({
  session,
  remoteStore
}: {
  session: SessionCore
  remoteStore: WASRemoteStore
}): EncryptionDescriptorSource {
  const { profile, persistence } = session
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
      const { log } = await verifiedAccountLog({ session })
      return webvhResourceLogController({ did, log })
    },
    pinStore: persistence.logPins,
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
 * @param options.session {object}   the live session's profile and
 *   persistence strategy
 * @returns {Promise<ICapabilityAgent>}
 */
export async function descriptorLogSignerAgent({
  session: { profile, persistence }
}: {
  session: SessionCore
}): Promise<ICapabilityAgent> {
  if (isBrowserLocalSession(persistence)) {
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
