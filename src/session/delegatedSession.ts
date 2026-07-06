/**
 * Refresh-surviving sessions via delegated zcaps.
 *
 * At login the root (passphrase-derived) key delegates to the browser
 * session key's did:key, all chains rooted at the Space's root capability:
 *
 * - a read-only capability on the Space URL (GET/HEAD anywhere under it --
 *   the WAS server accepts Space-rooted target attenuation), and
 * - a read/write capability per standard wallet collection, its
 *   `invocationTarget` attenuated down to the collection at delegation time
 *   -- so the session key can sync and share but can never rewrite the
 *   Space Description (no controller takeover) or write outside the
 *   wallet's collections;
 * - plus a `sign` capability on the WebKMS keystore, scoped to the did:web
 *   `authentication` key (the webkms-client routes a capability-invoked
 *   operation to the capability's own target, so it names that key rather
 *   than the whole keystore) -- letting a restored session sign KMS-backed
 *   DIDAuth with no re-login. Absent a did:web it falls back to the (inert)
 *   keystore target.
 *
 * On the next page load `restoreDelegatedSession()` reconstitutes a
 * restricted session from the persisted record: the zcap client signs with
 * the non-extractable session key and invokes the delegated capabilities.
 * No root key and no vault KAK are present -- encrypted collections stay
 * locked ("logged in but locked vault") until the user re-enters the
 * passphrase; envelope replication and public/plaintext reads still work.
 */
import { ZcapClient } from '@interop/ezcap'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { KmsClient } from '@interop/webkms-client'
import type { IZcap } from '@interop/data-integrity-core'
import type { DidWebKeyMap } from '@/lib/didWeb'
import type { WebvhUpdateKey, WebvhStagedKey } from '@/lib/didWebvh'
import type { Session, User } from '@/types/auth'
import {
  SESSION_ZCAP_TTL_MS,
  WALLET_STANDARD_COLLECTIONS,
  WAS_SERVER_URL
} from '@/app.config'
import {
  clearPersistedSession,
  getOrCreateSessionKeyPair,
  loadSessionKeyPair,
  loadSessionRecord,
  saveSessionRecord,
  sessionKeySigner
} from '@/lib/sessionKey'
import { StorageManager } from '@/stores/storageManager'

/**
 * What a `full` session persists at login (alongside the session key pair in
 * the same IndexedDB database). The zcaps are inert without the
 * non-extractable session key.
 */
export interface PersistedSessionRecord {
  // The root controller did:key (the user's identity).
  controller: string
  email?: string
  spaceId: string
  // The session key's did:key (sanity-checked against the stored key pair on
  // restore).
  sessionDid: string
  // ISO timestamp: when the delegated zcaps expire (restore refuses after).
  expires: string
  // GET/HEAD on the Space URL; covers reads anywhere under the Space.
  spaceReadCapability: IZcap
  // Read/write per standard collection, keyed by WAS collection id.
  collectionCapabilities: Record<string, IZcap>
  // `sign` on the WebKMS keystore (present when one was provisioned).
  keystoreId?: string
  keystoreCapability?: IZcap
  // The published did:web DID and its key-id map (present when did:web
  // provisioning succeeded). Absent = pre-did:web record; a restored session
  // then simply has no KMS-signed DIDAuth, degrading to today's behavior --
  // so no record-version bump is needed.
  didWeb?: { did: string; keys: DidWebKeyMap }
  // The published did:webvh DID and its update-key refs (present when
  // did:webvh provisioning succeeded). Key refs only, never secrets. Absent =
  // pre-did:webvh record; the restored session simply has no `didWebvh`,
  // degrading to did:web behavior -- additive, no record-version bump.
  didWebvh?: {
    did: string
    updateKey: WebvhUpdateKey
    stagedKey: WebvhStagedKey
  }
}

const SESSION_WRITE_ACTIONS = ['GET', 'HEAD', 'PUT', 'POST', 'DELETE']

/**
 * Delegates the session zcaps to the browser session key and persists the
 * session record. Called (fire-and-forget) after a successful full login;
 * a failure here only costs refresh-survival, never the login itself.
 *
 * @param options {object}
 * @param options.session {Session}   the freshly initialized full session
 * @param [options.idb] {IDBFactory}   where to persist; defaults to the
 *   global factory. The CHAPI popup passes the first-party factory from the
 *   Storage Access API so a popup login persists where the top-level wallet
 *   (and the next popup visit) will find it.
 * @returns {Promise<void>}
 */
export async function persistDelegatedSession({
  session,
  idb
}: {
  session: Session
  idb?: IDBFactory
}): Promise<void> {
  // Guests have nothing to restore; without a remote Space there is nothing
  // the session key could invoke.
  if (session.isGuest || !session.storage.hasRemoteStorage) {
    return
  }
  const spaceUrl = session.storage.spaceUrl!
  const spaceId = session.storage.spaceId!
  const { zcapClient, keystoreAgent, didWeb, didWebvh } = session.profile

  const keyPair = await getOrCreateSessionKeyPair({ idb })
  const { did: sessionDid } = await sessionKeySigner({ keyPair })

  const expires = new Date(Date.now() + SESSION_ZCAP_TTL_MS)
  const spaceRootCapability = `urn:zcap:root:${encodeURIComponent(spaceUrl)}`

  // Read-only over the whole Space (chain root: the Space itself).
  const spaceReadCapability = await zcapClient.delegate({
    invocationTarget: spaceUrl,
    controller: sessionDid,
    allowedActions: ['GET', 'HEAD'],
    expires
  })

  // Read/write per standard collection: rooted at the Space, target
  // attenuated down to the collection at delegation time.
  const collectionCapabilities: Record<string, IZcap> = {}
  for (const { id } of WALLET_STANDARD_COLLECTIONS) {
    collectionCapabilities[id] = await zcapClient.delegate({
      capability: spaceRootCapability,
      invocationTarget: `${spaceUrl}/${id}`,
      controller: sessionDid,
      allowedActions: SESSION_WRITE_ACTIONS,
      expires
    })
  }

  // A `sign` capability for the did:web `authentication` key, when a keystore
  // was provisioned. It targets that key's URL specifically, not the whole
  // keystore: the webkms-client routes a capability-invoked operation to the
  // capability's own `invocationTarget` (no client-side target attenuation),
  // so a keystore-level target would POST the SignOperation to the wrong
  // endpoint. The chain still roots at the keystore (KMS key operations root
  // there). Without a did:web there is no key to sign with, so the capability
  // falls back to the (inert) keystore target.
  let keystoreId: string | undefined
  let keystoreCapability: IZcap | undefined
  if (keystoreAgent?.keystoreId) {
    keystoreId = keystoreAgent.keystoreId
    const signTarget = didWeb?.keys.authentication.kmsKeyId ?? keystoreId
    keystoreCapability = await zcapClient.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      invocationTarget: signTarget,
      controller: sessionDid,
      allowedActions: ['sign'],
      expires
    })
  }

  const record: PersistedSessionRecord = {
    controller: session.user.id,
    email: session.user.email,
    spaceId,
    sessionDid,
    expires: expires.toISOString(),
    spaceReadCapability,
    collectionCapabilities,
    keystoreId,
    keystoreCapability,
    didWeb,
    didWebvh
  }
  await saveSessionRecord({ record, idb })
}

/**
 * Reconstitutes a restricted (`delegated` tier) session from the persisted
 * record and session key, or returns `null` when there is nothing (or
 * nothing valid) to restore. An expired or key-mismatched record is cleared
 * on the way out.
 *
 * @param [options] {object}
 * @param [options.idb] {IDBFactory}   where to read the persisted session
 *   from; defaults to the global factory. The CHAPI popup passes the
 *   first-party factory from the Storage Access API (the popup's own global
 *   factory is a partitioned bucket that never holds a session).
 * @returns {Promise<Session | null>}
 */
export async function restoreDelegatedSession({
  idb
}: {
  idb?: IDBFactory
} = {}): Promise<Session | null> {
  if (!WAS_SERVER_URL) {
    return null
  }
  const record = (await loadSessionRecord({
    idb
  })) as PersistedSessionRecord | null
  const keyPair = await loadSessionKeyPair({ idb })
  if (!record || !keyPair) {
    return null
  }
  if (new Date(record.expires).getTime() <= Date.now()) {
    await clearPersistedSession({ idb })
    return null
  }
  const { signer, did: sessionDid } = await sessionKeySigner({ keyPair })
  if (sessionDid !== record.sessionDid) {
    // The key pair does not match the record (e.g. a partially cleared
    // database) -- the zcaps are unusable.
    await clearPersistedSession({ idb })
    return null
  }

  const zcapClient = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: signer
  })
  const user: User = { id: record.controller, email: record.email }
  const { storage } = await StorageManager.initDelegatedStorageClients({
    user,
    zcapClient,
    spaceId: record.spaceId,
    sessionCapabilities: {
      spaceRead: record.spaceReadCapability,
      collections: record.collectionCapabilities
    }
  })

  return {
    user,
    profile: {
      zcapClient,
      keystoreId: record.keystoreId,
      // Paired with the session key, these let the restored session sign with
      // the KMS-held keys (KMS-signed DIDAuth) without the passphrase.
      keystoreCapability: record.keystoreCapability,
      didWeb: record.didWeb,
      didWebvh: record.didWebvh
    },
    storage,
    expires: record.expires,
    isGuest: false,
    tier: 'delegated'
  }
}

/**
 * Ends the persisted session: revokes the keystore session zcap on the KMS
 * (best-effort -- the server may be unreachable; the zcaps also expire on
 * their own) and always deletes the local records and session key. The WAS
 * server has no revocation endpoint yet, so the Space-side zcaps rely on
 * expiry.
 *
 * @param options {object}
 * @param [options.session] {Session}   the active session, when logging out
 *   of one (supplies the root signer in the full tier; the delegated tier --
 *   and a logged-out visit -- revoke with the session key, which the KMS
 *   accepts from any controller in the revoked zcap's chain)
 * @returns {Promise<void>}
 */
export async function endDelegatedSession({
  session
}: {
  session?: Session | null
} = {}): Promise<void> {
  try {
    const record = (await loadSessionRecord()) as PersistedSessionRecord | null
    if (record?.keystoreCapability && record.keystoreId) {
      let invocationSigner = session?.profile.keyAgent?.getSigner()
      if (!invocationSigner) {
        const keyPair = await loadSessionKeyPair()
        if (keyPair) {
          ;({ signer: invocationSigner } = await sessionKeySigner({ keyPair }))
        }
      }
      if (invocationSigner) {
        await new KmsClient({ keystoreId: record.keystoreId }).revokeCapability(
          {
            capabilityToRevoke: record.keystoreCapability,
            invocationSigner
          }
        )
      }
    }
  } catch (err) {
    console.warn('Session zcap revocation failed (expiry still applies):', err)
  } finally {
    await clearPersistedSession()
  }
}
