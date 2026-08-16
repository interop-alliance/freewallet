/**
 * The standing-posture establishment ceremony: what turns a passphrase or
 * passkey bind into a STANDING unlock credential -- one a fresh browser can
 * later self-enroll with, holding nothing but the credential (FW-154's
 * one-codepath model, the recovery-code posture minus spend-on-use). Run from
 * a live enrolled session, in the recovery-anchor order (decryption material
 * before authorization):
 *
 * 1. The credential's user-key wrap lands in the `key-map/user-key.jsonl`
 *    roster first (escrow: every epoch, so a later self-enrollment decrypts
 *    pre-bind history), kept alive by rotation fan-out from then on.
 * 2. The document entry: the credential's `keyAgreement` key -- verbatim for
 *    a high-entropy credential (a passkey PRF output), a hash commitment for
 *    a low-entropy-derived one (a passphrase; publishing the key verbatim
 *    would turn the server-gated guessing oracle into a world-readable
 *    offline one) -- and the hash of ladder rung 0 in `nextKeyHashes`.
 * 3. The authorization bridge: a pre-minted PUT-on-`did.jsonl` delegation to
 *    the credential-derived signing DID, sealed into the unlock record beside
 *    the freshly minted update-key ladder seed.
 * 4. The re-bind: the unlock record is rewritten in the standing layout
 *    (`wrapUnlockRecord` -- shell, bridge, ladder, binding MAC), superseding
 *    the plain pointer record of the pre-promotion bind.
 *
 * The caller records the returned standing fields in the unlock-methods
 * registry entry, which is what lets the revocation cascade re-mint the
 * bridge without the credential and the login health check watch its expiry.
 *
 * The delegated log store a self-enrolling browser writes through
 * (`unlockLogStore`) lives here too, shared with the recovery continuation's.
 */
import type { IZcap } from '@interop/data-integrity-core'
import { WasClient } from '@interop/was-client'
import {
  generateLadderSeed,
  ladderRung,
  publishUnlockKey,
  selfEnrollClientCore,
  type UnlockLogStore
} from '@interop/wallet-core/unlock'
import type { ClientKeyRecord } from '@interop/wallet-core/keys'
import { isWebvhDid } from '@interop/wallet-core/webvh'
import {
  delegateLogWrite,
  delegationProofKeyId
} from '@interop/wallet-core/recovery'
import { addUserKeyRosterRecipient } from '@interop/wallet-core/keys'
import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import type { AccountPointer, UnlockKdf } from '@interop/wallet-core/keyring'
import type { ZcapClient } from '@interop/ezcap'
import { ID_COLLECTION } from '@interop/wallet-core/space'
import type { Session } from '@/types/auth'
import {
  bindUnlockSecret,
  deriveUnlockCredential,
  unlockManagementGrantee,
  type KeyringFetchResult,
  type PersistableClientKeys,
  type UnlockCredential
} from '@/session/keyring'
import { saveUserKeyEpochPin, sessionLogPinStore } from '@/lib/sessionKey'
import { WAS_SERVER_URL } from '@/app.config'
import {
  enrolledClientContext,
  requireEnrolledClientContext
} from '@/session/enrolledContext'
import { sessionRosterStore } from '@/session/rosterStore'
import { invalidateVerifiedLog } from '@/session/verifiedLog'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import {
  emptyUnlockMethodsRegistry,
  getUnlockMethods,
  putUnlockMethods,
  upsertPassphraseUnlockMethod,
  type StandingUnlockFields
} from '@/session/unlockMethods'

/**
 * The narrow store a credential's self-enrollment continuation writes
 * through: public fetches for the world-readable log (carrying the response
 * ETag as the ceremony's compare-and-swap token), and the delegated PUT (the
 * record's bridge zcap, invoked by the credential-derived did:key client) for
 * `did.jsonl`, forwarding the ceremony's conditional-write preconditions.
 * Shared by the standing self-enrollment and the recovery continuation.
 *
 * @param options {object}
 * @param options.pointer {AccountPointer}   the account pointer (host +
 *   Space id locate the world-readable `id` collection)
 * @param options.delegation {IZcap}   the record's PUT-on-`did.jsonl` bridge
 * @param options.zcapClient {ZcapClient}   the credential-derived client the
 *   delegated PUT is invoked with
 * @returns {UnlockLogStore}
 */
export function unlockLogStore({
  pointer,
  delegation,
  zcapClient
}: {
  pointer: AccountPointer
  delegation: IZcap
  zcapClient: ZcapClient
}): UnlockLogStore {
  const was = new WasClient({
    serverUrl: pointer.host,
    zcapClient
  })
  return {
    async getIdResourceRaw({ resourceId }: { resourceId: string }) {
      const response = await fetch(
        new URL(
          `/space/${pointer.spaceId}/${ID_COLLECTION.id}/${resourceId}`,
          pointer.host
        )
      )
      if (response.status === 404) {
        return undefined
      }
      if (!response.ok) {
        throw new Error(
          `Fetching "${resourceId}" failed (HTTP ${response.status}).`
        )
      }
      return {
        text: await response.text(),
        etag: response.headers.get('etag') ?? undefined
      }
    },
    async putIdResource({
      resourceId,
      content,
      contentType,
      ifMatch,
      ifNoneMatch
    }: {
      resourceId: string
      content: object | string
      contentType?: string
      ifMatch?: string
      ifNoneMatch?: boolean
    }) {
      const serialized =
        typeof content === 'string' ? content : JSON.stringify(content)
      const headers: Record<string, string> = {
        'content-type': contentType ?? 'application/json'
      }
      if (ifMatch !== undefined) {
        headers['if-match'] = ifMatch
      }
      if (ifNoneMatch) {
        headers['if-none-match'] = '*'
      }
      // A failed precondition (HTTP 412) surfaces from `was.request` as
      // was-client's `PreconditionFailedError` -- the exact name the
      // `WebvhIdStore` seam contract requires for the ceremony's rebase.
      await was.request({
        path: `/space/${pointer.spaceId}/${ID_COLLECTION.id}/${resourceId}`,
        method: 'PUT',
        headers,
        body: new TextEncoder().encode(serialized),
        capability: delegation
      })
    }
  }
}

/**
 * Runs the whole establishment described in the module doc for one unlock
 * secret, from a live enrolled session. Idempotent under re-run: the roster
 * escrow no-ops on a standing wrap, the document edit no-ops on a standing
 * entry, and the re-bind supersedes the previous record.
 *
 * Best-effort callers (the signup tail) catch and warn: a failed
 * establishment leaves the credential's record in the plain layout, which
 * logs in normally and falls back to the connect-another-wallet ceremony on
 * a fresh browser -- never a broken account.
 *
 * @param options {object}
 * @param options.session {Session}   a live enrolled session
 * @param options.secret {string | Uint8Array}   the unlock secret being made
 *   standing
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @param options.lowEntropy {boolean}   whether the secret is low-entropy (a
 *   passphrase): a low-entropy-derived key publishes only its hash
 *   commitment in the world-readable document; a high-entropy one (a passkey
 *   PRF output) publishes verbatim
 * @param [options.email] {string}   the account email, carried in the
 *   re-wrapped record
 * @param [options.credential] {UnlockCredential}   an already-derived
 *   credential for the secret, so the caller's bind and this ceremony run
 *   the KDF once
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<object>}   the new record's unlock Space id, management
 *   zcap, persist closure, and the standing fields the registry entry
 *   records
 */
export async function establishStandingUnlock({
  session,
  secret,
  kdf,
  lowEntropy,
  email,
  credential: derived,
  idb
}: {
  session: Session
  secret: string | Uint8Array
  kdf: UnlockKdf
  lowEntropy: boolean
  email?: string
  credential?: UnlockCredential
  idb?: IDBFactory
}): Promise<{
  unlockSpaceId: string
  manageCapability?: IZcap
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
  standingFields: StandingUnlockFields
}> {
  const { remoteStore, pointer, clientWebvhKeys, clientKeyAgreementKey } =
    requireEnrolledClientContext({
      session,
      action: 'Establishing a standing unlock credential'
    })
  const { clientSeed, userKey, zcapClient } = session.profile
  if (!clientSeed) {
    throw new Error(
      "Establishing a standing unlock credential requires this client's " +
        'seed in the session.'
    )
  }
  const controller = session.profile.accountController ?? session.user.id
  const credential = derived ?? (await deriveUnlockCredential({ secret, kdf }))
  const { standing } = credential

  // 1. Decryption material first: the credential's wrap into every roster
  // epoch. Idempotent -- a wrap already standing is returned as-is.
  await addUserKeyRosterRecipient({
    store: sessionRosterStore({ profile: session.profile, idb }),
    recipient: {
      id: standing.recipientKid,
      publicKeyMultibase: standing.keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: clientKeyAgreementKey
  })

  // 2. The document entry: the keyAgreement publication (commitment for a
  // low-entropy credential, verbatim for a high-entropy one) and the hash of
  // ladder rung 0 in `nextKeyHashes`.
  const ladderSeed = generateLadderSeed()
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  await publishUnlockKey({
    idStore: remoteStore.webvhIdStore(),
    updateKeys: clientWebvhKeys,
    unlockKeys: {
      keyAgreement: lowEntropy
        ? {
            commitment: await keyAgreementCommitment({
              keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase
            })
          }
        : { publicKeyMultibase: standing.keyAgreementKeyMultibase },
      updateKeyMultibase: rung0.keyMultibase
    },
    expectedDid: pointer.did
  })
  invalidateVerifiedLog({ profile: session.profile })

  // 3. The authorization bridge to the credential-derived signing DID.
  const delegation = await delegateLogWrite({
    zcapClient,
    pointer,
    recoveryClientDid: standing.clientDid
  })

  // 4. The re-bind: the unlock record in the standing layout.
  const bound = await bindUnlockSecret({
    clientSeed,
    controller,
    secret,
    kdf,
    email,
    userKey,
    webvhUpdateKeys: clientWebvhKeys,
    pointer,
    delegateManagementTo: unlockManagementGrantee({ pointer, controller }),
    delegation,
    ladderSeed,
    credential,
    idb
  })

  const delegationKeyId = delegationProofKeyId(delegation)
  const delegationExpires = (delegation as { expires?: string }).expires
  return {
    unlockSpaceId: bound.unlockSpaceId,
    manageCapability: bound.manageCapability,
    persistClientKeys: bound.persistClientKeys,
    standingFields: {
      rosterKid: standing.recipientKid,
      keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
      updateKeyMultibase: rung0.keyMultibase,
      unlockClientDid: standing.clientDid,
      ...(delegationKeyId ? { delegationKeyId } : {}),
      ...(delegationExpires ? { delegationExpires } : {}),
      ...(bound.unlockKeyAgreementKeyId
        ? { unlockKeyAgreementKeyId: bound.unlockKeyAgreementKeyId }
        : {}),
      ...(bound.unlockKeyAgreementKeyMultibase
        ? {
            unlockKeyAgreementKeyMultibase: bound.unlockKeyAgreementKeyMultibase
          }
        : {})
    }
  }
}

/**
 * Whether a keyring hit can self-enroll this browser: the record carries the
 * standing members (bridge delegation and ladder seed), the pointer names a
 * did:webvh, a WAS server is configured, and the fetch exposed the enrollment
 * persist closure. The login path gates on this before running
 * `selfEnrollStandingClient`.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}
 * @returns {boolean}
 */
export function canSelfEnroll({
  found
}: {
  found: KeyringFetchResult
}): boolean {
  return !!(
    WAS_SERVER_URL &&
    found.standing?.ladderSeed &&
    found.standingClient &&
    found.enrollClientKeys &&
    found.pointer &&
    isWebvhDid(found.pointer.did)
  )
}

/**
 * Self-enrolls this fresh browser as an ordinary enrolled client, from
 * nothing but the credential's keyring hit: runs wallet-core's composed
 * continuation (the reveal-and-commit and add log entries through the
 * record's bridge delegation, the first roster read through the credential's
 * standing wrap, and the new client's own roster escrow), pins the roster
 * epoch, and persists the freshly minted key set under the credential's
 * unlock identity -- so this login, and every later one, proceeds as an
 * ordinary enrolled client. Loud by construction: the world-readable
 * hash-chained log extends before a single byte is read.
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   a hit `canSelfEnroll` accepted
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<object>}   the persisted key set and its persist closure
 */
export async function selfEnrollStandingClient({
  found,
  idb
}: {
  found: KeyringFetchResult
  idb?: IDBFactory
}): Promise<{
  clientKeys: ClientKeyRecord
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
}> {
  const { standing, standingClient, pointer, enrollClientKeys } = found
  if (
    !standing?.ladderSeed ||
    !standingClient ||
    !pointer ||
    !enrollClientKeys
  ) {
    throw new Error('This keyring hit cannot self-enroll a client.')
  }
  const result = await selfEnrollClientCore({
    pointer,
    ladderSeed: standing.ladderSeed,
    credentialKeyAgreementKey: standingClient.agents.keyAgreementKey,
    logStore: unlockLogStore({
      pointer,
      delegation: standing.delegation,
      zcapClient: standingClient.agents.zcapClient
    }),
    // A fresh browser normally has no pin yet -- this first contact is the
    // pin's trust-on-first-use establishment; later logins verify against it.
    accountLogPinStore: sessionLogPinStore({ idb })
  })
  await saveUserKeyEpochPin({
    accountDid: result.did,
    epochId: result.latestEpochId,
    idb
  })
  const persistClientKeys = await enrollClientKeys({
    clientSeed: result.clientSeed,
    userKey: result.userKey,
    webvhUpdateKeys: result.webvhUpdateKeys,
    controller: found.controller
  })
  const clientKeys: ClientKeyRecord = {
    clientSeed: result.clientSeed,
    userKey: result.userKey,
    webvhUpdateKeys: result.webvhUpdateKeys,
    controller: found.controller
  }
  return { clientKeys, persistClientKeys }
}

/**
 * The best-effort passphrase-shaped wrapper: runs `establishStandingUnlock`
 * for a passphrase (low-entropy, so its `keyAgreement` key publishes as a
 * hash commitment), adopts the new record's persist closure and unlock
 * method on the live session, and records the standing fields in the
 * registry's passphrase entry. Warns and returns on failure -- a
 * plain-layout record is a working login, never a broken account. Shared by
 * the passphrase signup tail, the Settings add-a-passphrase and
 * change-passphrase flows.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.passphrase {string}
 * @param [options.email] {string}   the account email, carried in the
 *   re-wrapped record
 * @param [options.credential] {UnlockCredential}   an already-derived
 *   credential for the passphrase
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function establishPassphrasePosture({
  session,
  passphrase,
  email,
  credential,
  idb
}: {
  session: Session
  passphrase: string
  email?: string
  credential?: UnlockCredential
  idb?: IDBFactory
}): Promise<void> {
  // A session that cannot act as an enrolled client on a promoted account
  // (a no-WAS deployment, a guest, an unpromoted account) has no posture to
  // establish; skip quietly rather than warn on every such signup.
  if (!enrolledClientContext({ session })) {
    return
  }
  try {
    const established = await establishStandingUnlock({
      session,
      secret: passphrase,
      kdf: KEYRING_KDF,
      lowEntropy: true,
      email,
      credential,
      idb
    })
    session.profile.persistClientKeys = established.persistClientKeys
    session.profile.unlockMethod = {
      type: 'passphrase',
      unlockSpaceId: established.unlockSpaceId,
      manageCapability: established.manageCapability
    }
    const record =
      (await getUnlockMethods({ session, idb })) ?? emptyUnlockMethodsRegistry()
    await putUnlockMethods({
      session,
      record: upsertPassphraseUnlockMethod({
        record,
        unlockSpaceId: established.unlockSpaceId,
        manageCapability: established.manageCapability,
        standing: established.standingFields
      }),
      idb
    })
  } catch (err) {
    console.warn(
      'Could not establish the passphrase as a standing credential; a fresh ' +
        'browser will need the connect-another-wallet ceremony:',
      err
    )
  }
}
