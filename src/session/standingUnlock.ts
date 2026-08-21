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
 *    the freshly minted update-key ladder seed -- and, when the account
 *    document already points at a companion generation, the companion-Space
 *    sibling delegation (GET+PUT over the auxiliary Space's items subtree,
 *    to the same signing DID). An account with no pointed generation has no
 *    auxiliary Space id to target yet; the record then binds without a
 *    sibling and a later re-mint adds one once the pointer exists.
 * 4. The re-bind: the unlock record is rewritten in the standing layout
 *    (`wrapUnlockRecord` -- shell, bridge, sibling, ladder, binding MAC),
 *    superseding the plain pointer record of the pre-promotion bind.
 *
 * The caller records the returned standing fields in the unlock-methods
 * registry entry, which is what lets the revocation cascade re-mint the
 * delegations without the credential and the login health check watch their
 * expiry.
 *
 * The delegated log store a self-enrolling browser writes through
 * (`unlockLogStore`) lives here too, shared with the recovery continuation's.
 */
import type { IZcap } from '@interop/data-integrity-core'
import { PreconditionFailedError, WasClient } from '@interop/was-client'
import { resourcePath, toUrl } from '@interop/was-client/paths'
import {
  generateLadderSeed,
  ladderRung,
  publishUnlockKey,
  selfEnrollClientCore,
  type UnlockLogStore
} from '@interop/wallet-core/unlock'
import type { ClientKeyRecord } from '@interop/wallet-core/keys'
import {
  accountLogPinId,
  companionDidParts,
  companionLogStore,
  delegatedClientsPointer,
  didKeyZcapClient,
  ensureGenerationDelegationCurrent,
  isWebvhDid,
  mintCredentialCompanionGeneration,
  mintDelegatedClientsDelegation,
  mintGenerationDelegation,
  setDelegatedClientsPointer
} from '@interop/wallet-core/webvh'
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
  fetchKeyring,
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
import {
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import {
  emptyUnlockMethodsRegistry,
  getUnlockMethods,
  putUnlockMethods,
  refreshStandingDelegationFields,
  upsertPassphraseUnlockMethod,
  type StandingUnlockFields
} from '@/session/unlockMethods'
import { mintSpaceId } from '@/stores/wasRemoteStore'

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
      // Built with the paths helpers so a sub-path deployment fetches the
      // resource the bridge delegation's target names (the root-anchored
      // form was drift).
      const response = await fetch(
        toUrl({
          serverUrl: pointer.host,
          path: resourcePath(pointer.spaceId, ID_COLLECTION.id, resourceId)
        })
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
      try {
        await was.request({
          path: resourcePath(pointer.spaceId, ID_COLLECTION.id, resourceId),
          method: 'PUT',
          headers,
          body: new TextEncoder().encode(serialized),
          capability: delegation
        })
      } catch (err) {
        // `was.request` is the raw signed request and applies no error
        // mapping, so a failed precondition surfaces as a bare HTTP 412;
        // rethrow it under the `PreconditionFailedError` name the
        // `WebvhIdStore` seam contract requires for the ceremony's rebase.
        const status = (err as { status?: unknown })?.status
        if (status === 412) {
          throw new PreconditionFailedError(
            `"${resourceId}" has moved on (stale precondition).`,
            { status: 412, cause: err }
          )
        }
        throw err
      }
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
  ladderSeed: Uint8Array
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
    store: sessionRosterStore({ profile: session.profile }),
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

  // 3. The authorization bridge to the credential-derived signing DID --
  // and, when the account document points at a companion generation, the
  // companion-Space sibling delegation to the same DID. The auxiliary Space
  // id is read off the document's delegated-clients service entry (the
  // sibling delegation's target is the id's one carrier, so an account with
  // no pointed generation binds without a sibling; a later re-mint adds one
  // once the pointer exists). Best-effort: a sibling-less standing record
  // still self-enrolls, it just cannot reach the companion log.
  const delegation = await delegateLogWrite({
    zcapClient,
    pointer,
    recoveryClientDid: standing.clientDid
  })
  let delegatedClients: IZcap | undefined
  try {
    const { doc } = await verifiedAccountLog({
      profile: session.profile,
      pointer
    })
    const companionDid = delegatedClientsPointer({ doc })
    if (companionDid) {
      delegatedClients = await mintDelegatedClientsDelegation({
        zcapClient,
        wasServerUrl: pointer.host,
        companionSpaceId: companionDidParts({ did: companionDid }).spaceId,
        controller: standing.clientDid
      })
    }
  } catch (err) {
    console.warn(
      'Could not mint the companion-Space sibling delegation; the record ' +
        'binds without one:',
      err
    )
  }

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
    ...(delegatedClients ? { delegatedClients } : {}),
    ladderSeed,
    credential,
    idb
  })

  const delegationKeyId = delegationProofKeyId(delegation)
  const delegationExpires = (delegation as { expires?: string }).expires
  const delegatedClientsKeyId = delegatedClients
    ? delegationProofKeyId(delegatedClients)
    : undefined
  const delegatedClientsExpires = delegatedClients
    ? (delegatedClients as { expires?: string }).expires
    : undefined
  return {
    unlockSpaceId: bound.unlockSpaceId,
    manageCapability: bound.manageCapability,
    persistClientKeys: bound.persistClientKeys,
    ladderSeed,
    standingFields: {
      rosterKid: standing.recipientKid,
      keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
      updateKeyMultibase: rung0.keyMultibase,
      unlockClientDid: standing.clientDid,
      ...(delegationKeyId ? { delegationKeyId } : {}),
      ...(delegationExpires ? { delegationExpires } : {}),
      ...(delegatedClientsKeyId ? { delegatedClientsKeyId } : {}),
      ...(delegatedClientsExpires ? { delegatedClientsExpires } : {}),
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
 * Establishes the companion-generation posture for one standing unlock
 * credential, from a live enrolled session holding its secret: ensure a
 * generation exists and the account document points at it (minting the typed
 * auxiliary Space, the credential-signed genesis, and the embedded generation
 * delegation when none is pointed -- companion log first, pointer second),
 * then mint the companion-Space sibling delegation and re-seal it into the
 * credential's unlock record beside the existing bridge. The re-bind
 * preserves the record's ladder seed verbatim (`rebindStandingRecord`) --
 * load-bearing, since the genesis just committed that seed's
 * generation-bound rung 0 -- and the registry entry records the sibling's
 * signer and expiry.
 *
 * This is what makes the credential's DEFAULT transient login possible on a
 * fresh browser. No shipped login ceremony triggers it yet; today's one
 * driver is the non-production e2e seam.
 *
 * @param options {object}
 * @param options.session {Session}   a live enrolled session
 * @param options.secret {string | Uint8Array}   the credential's unlock
 *   secret
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<void>}
 */
export async function establishCompanionGeneration({
  session,
  secret,
  kdf,
  idb
}: {
  session: Session
  secret: string | Uint8Array
  kdf: UnlockKdf
  idb?: IDBFactory
}): Promise<void> {
  const { remoteStore, pointer, clientWebvhKeys, keyAgent } =
    requireEnrolledClientContext({
      session,
      action: 'Establishing the companion-generation posture'
    })
  const { zcapClient } = session.profile

  const found = await fetchKeyring({ secret, kdf, idb })
  const foundStanding = found?.standing
  const ladderSeed = foundStanding?.ladderSeed
  if (!found || !foundStanding || !ladderSeed || !found.standingClient) {
    throw new Error(
      'This credential holds no standing unlock record; establish the ' +
        'standing posture before the companion generation.'
    )
  }
  if (!found.rebindStandingRecord) {
    throw new Error(
      "This credential's unlock record cannot be re-sealed from here."
    )
  }

  const was = new WasClient({ serverUrl: pointer.host, zcapClient })

  // The generation: reuse the pointed one when the document already carries
  // the delegated-clients pointer; mint and point otherwise, in the standing
  // order (the companion log publishes first, the pointer follows).
  const { doc } = await verifiedAccountLog({
    profile: session.profile,
    pointer
  })
  let companionDid = delegatedClientsPointer({ doc })
  if (!companionDid) {
    // Space creation accepts did:key controllers only, so the auxiliary
    // Space follows the account Space's own order: created (and written)
    // under this client's bare did:key, then its controller promoted to the
    // account did:webvh -- before any delegation roots in its root zcap.
    const companionSpaceId = mintSpaceId()
    const bootstrapWas = new WasClient({
      serverUrl: pointer.host,
      zcapClient: didKeyZcapClient({ keyAgent })
    })
    const minted = await mintCredentialCompanionGeneration({
      was: bootstrapWas,
      wasServerUrl: pointer.host,
      spaceId: companionSpaceId,
      controller: keyAgent.id,
      ladderSeed
    })
    await bootstrapWas
      .space(companionSpaceId)
      .configure({ controller: pointer.did, force: true })
    await setDelegatedClientsPointer({
      idStore: remoteStore.webvhIdStore(),
      updateKeys: clientWebvhKeys,
      companionDid: minted.did,
      expectedDid: pointer.did,
      pinStore: session.profile.persistence.logPins,
      logId: accountLogPinId({ spaceId: pointer.spaceId })
    })
    invalidateVerifiedLog({ profile: session.profile })
    companionDid = minted.did
  }

  // The embedded generation delegation, installed when the companion document
  // carries none yet (the fresh-genesis case) and renewed near expiry
  // otherwise -- signed by this enrolled client's promoted key either way.
  const companion = companionDidParts({ did: companionDid })
  await ensureGenerationDelegationCurrent({
    store: companionLogStore({
      was,
      spaceId: companion.spaceId,
      generationId: companion.generationId
    }),
    ladderSeed,
    generationId: companion.generationId,
    mintGenerationDelegation: async ({ companionDid: generationDid }) =>
      mintGenerationDelegation({
        zcapClient,
        wasServerUrl: pointer.host,
        spaceId: pointer.spaceId,
        companionDid: generationDid
      }),
    expectedDid: companionDid
  })

  // The sibling delegation, re-sealed into the record beside the existing
  // bridge; the registry entry records its signer and expiry for the health
  // check and the revocation cascade's re-mint walk.
  const delegatedClients = await mintDelegatedClientsDelegation({
    zcapClient,
    wasServerUrl: pointer.host,
    companionSpaceId: companion.spaceId,
    controller: found.standingClient.clientDid
  })
  await found.rebindStandingRecord({
    delegation: foundStanding.delegation,
    delegatedClients
  })
  const delegatedClientsKeyId = delegationProofKeyId(delegatedClients)
  await refreshStandingDelegationFields({
    session,
    unlockSpaceId: found.unlockSpaceId,
    ...(delegatedClientsKeyId ? { delegatedClientsKeyId } : {}),
    ...((delegatedClients as { expires?: string }).expires
      ? {
          delegatedClientsExpires: (delegatedClients as { expires?: string })
            .expires
        }
      : {})
  })
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
 * @returns {Promise<{ ladderSeed?: Uint8Array }>}   the established
 *   posture's ladder seed, absent when the establishment skipped or failed
 *   (a passphrase change threads it into the old credential's retirement as
 *   the surviving seed)
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
}): Promise<{ ladderSeed?: Uint8Array }> {
  // A session that cannot act as an enrolled client on a promoted account
  // (a no-WAS deployment, a guest, an unpromoted account) has no posture to
  // establish; skip quietly rather than warn on every such signup.
  if (!enrolledClientContext({ session })) {
    return {}
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
      (await getUnlockMethods({ session })) ?? emptyUnlockMethodsRegistry()
    await putUnlockMethods({
      session,
      record: upsertPassphraseUnlockMethod({
        record,
        unlockSpaceId: established.unlockSpaceId,
        manageCapability: established.manageCapability,
        standing: established.standingFields
      })
    })
    return { ladderSeed: established.ladderSeed }
  } catch (err) {
    console.warn(
      'Could not establish the passphrase as a standing credential; a fresh ' +
        'browser will need the connect-another-wallet ceremony:',
      err
    )
    return {}
  }
}
