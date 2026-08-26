/**
 * The standing-configuration establishment ceremony: what turns a passphrase or
 * passkey bind into a STANDING unlock credential -- one a fresh browser can
 * later self-enroll with, holding nothing but the credential (FW-154's
 * one-codepath model, the recovery-code configuration minus spend-on-use). Run from
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
 *    document already points at an annex generation, the annex-Space
 *    sibling delegation (GET+PUT over the auxiliary Space's items subtree,
 *    to the same signing DID). An account with no pointed generation has no
 *    auxiliary Space id to target yet; the record then binds without a
 *    sibling and a later re-mint adds one once the pointer exists.
 * 4. The re-bind: the unlock record is rewritten in the standing layout
 *    (`wrapUnlockRecord` -- shell, bridge, sibling, ladder, binding MAC),
 *    superseding the credential's previous record (the plain layout
 *    survives only on no-WAS deployments, where this ceremony never runs).
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
import { WasClient } from '@interop/was-client'
import {
  publishUnlockKey,
  type UnlockLogStore
} from '@interop/wallet-core/unlock'
import type { ClientKeyRecord } from '@interop/wallet-core/keys'
import {
  accountLogPinId,
  delegatedWebvhLogStore,
  didKeyZcapClient,
  isWebvhDid,
  type ClientWebvhUpdateKeys
} from '@interop/wallet-core/webvh'
import {
  commitClientAnnexRung,
  clientAnnexDidParts,
  delegatedClientsPointer,
  ensurePointedClientAnnexGeneration,
  generateLadderSeed,
  ladderRung,
  mintDelegatedClientsDelegation,
  mintGenerationDelegation,
  selfEnrollClientCore
} from '@interop/wallet-core/clientAnnex'
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
import { requireEnrolledClientContext } from '@/session/enrolledContext'
import {
  clientAnnexReachOf,
  ensureGenerationDelegation
} from '@/session/annexReach'
import { sessionRosterStore } from '@/session/rosterStore'
import {
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import {
  refreshStandingDelegationFields,
  type StandingUnlockFields
} from '@/session/unlockMethods'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:unlock')

/**
 * The narrow store a credential's self-enrollment continuation writes
 * through: the shared delegated log store aimed at the account log --
 * public fetches for the world-readable resource (carrying the response
 * ETag as the ceremony's compare-and-swap token), and the delegated PUT (the
 * record's bridge zcap, invoked by the credential-derived did:key client) for
 * `did.jsonl`. Shared by the standing self-enrollment and the recovery
 * continuation.
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
  return delegatedWebvhLogStore({
    host: pointer.host,
    spaceId: pointer.spaceId,
    collectionId: ID_COLLECTION.id,
    delegation,
    zcapClient,
    publicRead: true
  })
}

/**
 * Runs the whole establishment described in the module doc for one unlock
 * secret, from a live enrolled session. Idempotent under re-run: the roster
 * escrow no-ops on a standing wrap, the document edit no-ops on a standing
 * entry, and the re-bind supersedes the previous record.
 *
 * The callers are the Settings ceremonies (add-a-passkey,
 * add-a-passphrase, the passphrase change); a WAS signup establishes
 * through the credential-anchored establishment instead, before any Space
 * exists. A failed establishment here leaves the credential's record in
 * the plain layout -- a state the transient login cannot enter -- so a
 * failure fails the surrounding ceremony rather than being swallowed.
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
 * @param [options.ladderSeed] {Uint8Array}   a caller-minted update-key
 *   ladder seed; supplying one lets the caller clean up a torn establishment
 *   by an actual retirement (it holds rung 0 and the attribution seed even
 *   when this ceremony throws before returning). A fresh seed is minted when
 *   absent
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
  ladderSeed: mintedLadderSeed,
  idb
}: {
  session: Session
  secret: string | Uint8Array
  kdf: UnlockKdf
  lowEntropy: boolean
  email?: string
  credential?: UnlockCredential
  ladderSeed?: Uint8Array
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
  const ladderSeed = mintedLadderSeed ?? generateLadderSeed()
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
    expectedDid: pointer.did,
    pinStore: session.profile.persistence.logPins,
    logId: accountLogPinId({ spaceId: pointer.spaceId })
  })
  invalidateVerifiedLog({ profile: session.profile })

  // 3. The authorization bridge to the credential-derived signing DID --
  // and, when the account document points at an annex generation, the
  // annex-Space sibling delegation to the same DID. The auxiliary Space
  // id is read off the document's delegated-clients service entry (the
  // sibling delegation's target is the id's one carrier, so an account with
  // no pointed generation binds without a sibling; a later re-mint adds one
  // once the pointer exists). Best-effort: a sibling-less standing record
  // still self-enrolls, it just cannot reach the annex log.
  const delegation = await delegateLogWrite({
    zcapClient,
    pointer,
    recoveryClientDid: standing.clientDid
  })
  let delegatedClients: IZcap | undefined
  let clientAnnexDid: string | undefined
  try {
    const { doc } = await verifiedAccountLog({
      profile: session.profile,
      pointer
    })
    clientAnnexDid = delegatedClientsPointer({ doc })
    if (clientAnnexDid) {
      delegatedClients = await mintDelegatedClientsDelegation({
        zcapClient,
        wasServerUrl: pointer.host,
        clientAnnexSpaceId: clientAnnexDidParts({ did: clientAnnexDid })
          .spaceId,
        controller: standing.clientDid
      })
    }
  } catch (err) {
    log.warn(
      'Could not mint the annex-Space sibling delegation; the record binds without one',
      { err }
    )
  }

  // 3b. The annex rung commit -- the bind ceremony's half of the
  // mid-generation lockout hybrid: the bound credential's rung-0 hash joins
  // the pointed generation's `nextKeyHashes` in one atomic hash-restating
  // entry signed by the LOGIN credential's committed rung 0
  // (`profile.ladderSeed`; on a passphrase change still the OLD credential's
  // seed here, by the caller's reassignment ordering). Without it a freshly
  // bound credential is locked out of transient login until the next
  // generation swap. Best-effort: an acting rung the generation does not
  // commit is the honest skip (nothing licenses a bind to mint a
  // generation), and the lockout consequence stands as documented.
  const actingLadderSeed = session.profile.ladderSeed
  if (clientAnnexDid && actingLadderSeed) {
    try {
      const reach = clientAnnexReachOf({ session, pointer, clientAnnexDid })
      await commitClientAnnexRung({
        store: reach.logStore(),
        boundLadderSeed: ladderSeed,
        actingLadderSeed,
        generationId: reach.generationId,
        expectedDid: clientAnnexDid,
        pinStore: session.profile.persistence.logPins,
        logId: reach.logId
      })
    } catch (err) {
      log.warn(
        (err as { name?: string }).name === 'ClientAnnexRungUncommittedError'
          ? "The login credential's rung is not committed in the pointed generation; the bound credential waits for the next generation swap"
          : "Could not commit the bound credential's annex rung",
        { err }
      )
    }
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
 * Establishes the annex-generation inventory for one standing unlock
 * credential, from a live enrolled session holding its secret: ensure a
 * generation exists and the account document points at it (minting the typed
 * auxiliary Space, the credential-signed genesis, and the embedded generation
 * delegation when none is pointed -- annex log first, pointer second),
 * then mint the annex-Space sibling delegation and re-seal it into the
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
export async function establishClientAnnexGeneration({
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
      action: 'Establishing the annex-generation inventory'
    })
  const { zcapClient } = session.profile

  const found = await fetchKeyring({ secret, kdf, idb })
  const foundStanding = found?.standing
  const ladderSeed = foundStanding?.ladderSeed
  if (!found || !foundStanding || !ladderSeed || !found.standingClient) {
    throw new Error(
      'This credential holds no standing unlock record; establish the ' +
        'standing configuration before the annex generation.'
    )
  }
  if (!found.rebindStandingRecord) {
    throw new Error(
      "This credential's unlock record cannot be re-sealed from here."
    )
  }

  // The generation: reuse the pointed one when the document already carries
  // the delegated-clients pointer; mint and point otherwise through the
  // shared stage-3 fold (mint, embed the delegation while the auxiliary
  // Space still answers to its creation controller, flip the controller,
  // append the pointer entry last). Space creation accepts did:key
  // controllers only, so the fold creates the auxiliary Space under this
  // client's bare did:key; the pointer entry signs with this enrolled
  // client's own document update keys, and the embedded delegation with its
  // promoted key.
  const account = await verifiedAccountLog({
    profile: session.profile,
    pointer
  })
  const pointed = await ensurePointedClientAnnexGeneration({
    account: { did: pointer.did, doc: account.doc, log: account.log },
    wasServerUrl: pointer.host,
    accountSpaceId: pointer.spaceId,
    ladderSeed,
    was: new WasClient({
      serverUrl: pointer.host,
      zcapClient: didKeyZcapClient({ keyAgent })
    }),
    mintController: keyAgent.id,
    mintGenerationDelegation: async ({ clientAnnexDid: generationDid }) =>
      mintGenerationDelegation({
        zcapClient: session.profile.zcapClient,
        wasServerUrl: pointer.host,
        spaceId: pointer.spaceId,
        clientAnnexDid: generationDid
      }),
    idStore: remoteStore.webvhIdStore(),
    updateKeys: clientWebvhKeys,
    pinStore: session.profile.persistence.logPins
  })
  const clientAnnexDid = pointed.clientAnnexDid
  if (pointed.generationMinted) {
    invalidateVerifiedLog({ profile: session.profile })
  }

  // The embedded generation delegation on an ALREADY-POINTED generation:
  // installed when the annex document carries none yet and renewed near
  // expiry otherwise -- signed by this enrolled client's promoted key. A
  // generation the fold just minted carries a fresh delegation already.
  const clientAnnex = clientAnnexReachOf({ session, pointer, clientAnnexDid })
  if (!pointed.generationMinted) {
    await ensureGenerationDelegation({
      session,
      pointer,
      reach: clientAnnex,
      ladderSeed
    })
  }

  // The sibling delegation, re-sealed into the record beside the existing
  // bridge; the registry entry records its signer and expiry for the health
  // check and the revocation cascade's re-mint walk.
  const delegatedClients = await mintDelegatedClientsDelegation({
    zcapClient,
    wasServerUrl: pointer.host,
    clientAnnexSpaceId: clientAnnex.spaceId,
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
    keyAgreementKeyMultibase: found.standingClient.keyAgreementKeyMultibase,
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
 * Thrown when wallet-core's self-enrollment core returned without stating
 * whether the persist hook fired (`committed` absent from the return) -- a
 * build skew: a stale hook-less wallet-core body running under new app code
 * would silently reinstate the publish-then-persist phantom window, so the
 * run is refused instead of trusted. The returned key set is persisted
 * before the refusal (a stale core has already published the client), so
 * the browser IS connected and the next login proceeds enrolled.
 */
export class SelfEnrollmentSkewError extends Error {
  constructor() {
    super(
      'The self-enrollment core did not state whether the persist hook ' +
        'fired; refusing a possibly hook-less run (stale wallet-core build).'
    )
    this.name = 'SelfEnrollmentSkewError'
  }
}

/**
 * Self-enrolls this fresh browser as an ordinary enrolled client, from
 * nothing but the credential's keyring hit: runs wallet-core's composed
 * continuation (the reveal-and-commit and add log entries through the
 * record's bridge delegation, the first roster read through the credential's
 * standing wrap, and the new client's own roster escrow), persists the key
 * set under the credential's unlock identity, and only then pins the roster
 * epoch -- so this login, and every later one, proceeds as an ordinary
 * enrolled client. Loud by construction: the world-readable hash-chained log
 * extends before a single byte is read.
 *
 * The persist order is persist-before-publish end to end. The REQUIRED
 * `onCommitted` seam fires between the reveal entry and the add entry
 * (inside the conflict retry, so it re-fires per attempt): the pending-shape
 * client-key record -- seeds, controller, `pointerDid`, and the `pending`
 * group (`ceremony: 'self-enrollment'`, the built-on head), no `userKey` --
 * becomes durable BEFORE the pivot entry publishes the client, so a tab
 * closing anywhere after the add entry leaves a record the next login's
 * resume finishes rather than a phantom client only Disconnect could
 * remove. After the core returns, the completion overwrites the record with
 * the enrolled shape (the user key in, `pending` cleared), and only then
 * the epoch pin is written (the FW-254 persist-before-pin order, kept for
 * the completion). A rejecting pin write (quota, a blocked upgrade) is not
 * a login failure once the key set is persisted: it is logged and the login
 * proceeds, and the next login's roster read establishes the pin from the
 * verified roster.
 *
 * With `resume`, the mint is skipped and the recorded key set replays: the
 * core detects the standing entries from the log, publishes only what is
 * missing, refuses a served log that never reached the recorded head
 * (`BuiltOnHeadNotReachedError`), and converges on the same durable state a
 * fresh run would -- never minting a second client. The pending record is
 * completed on the RETURN, whatever `committed` says (a resume that met an
 * already-complete continuation is a full success).
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   a hit `canSelfEnroll` accepted
 *   (fresh), or a pending-record hit the resume gate accepted (`resume`)
 * @param [options.idb] {IDBFactory}
 * @param [options.resume] {object}   the pending record's replayed contents:
 *   `{ clientSeed, webvhUpdateKeys, builtOnHead }`
 * @returns {Promise<object>}   the persisted key set and its persist closure
 */
export async function selfEnrollStandingClient({
  found,
  idb,
  resume
}: {
  found: KeyringFetchResult
  idb?: IDBFactory
  resume?: {
    clientSeed: Uint8Array
    webvhUpdateKeys: ClientWebvhUpdateKeys
    builtOnHead: { scid: string; versionId: string }
  }
}): Promise<{
  clientKeys: ClientKeyRecord
  persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
}> {
  const { standing, standingClient, pointer, enrollClientKeys } = found
  if (!standing?.ladderSeed || !standingClient || !pointer) {
    throw new Error('This keyring hit cannot self-enroll a client.')
  }
  if (!resume && !enrollClientKeys) {
    throw new Error('This keyring hit cannot self-enroll a client.')
  }
  const recordPersister = found.persistClientKeys
  if (resume && !recordPersister) {
    throw new Error('This keyring hit cannot resume a pending enrollment.')
  }
  let hookFires = 0
  let enrolledPersister:
    ((changes: PersistableClientKeys) => Promise<void>) | undefined
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
    accountLogPinStore: sessionLogPinStore({ idb }),
    ...(resume ? { resume } : {}),
    // The persist-before-publish seam: the pending-shape record becomes
    // durable on the head the add entry is about to be built on, before that
    // entry publishes a client only this tab could re-derive. Idempotent per
    // attempt (the conflict retry re-fires it); on a resume the seeds handed
    // back are the record's own, so the write restates what already stands.
    onCommitted: async ({ builtOnHead, clientSeed, webvhUpdateKeys }) => {
      hookFires += 1
      if (hookFires > 1) {
        log.info('Self-enrollment persist hook re-fired on a conflict retry', {
          attempt: hookFires
        })
      }
      const pending = {
        ceremony: 'self-enrollment' as const,
        builtOnHead
      }
      if (resume && recordPersister) {
        await recordPersister({ pending, pointerDid: pointer.did })
        return
      }
      enrolledPersister = await enrollClientKeys!({
        clientSeed,
        webvhUpdateKeys,
        controller: found.controller,
        pointerDid: pointer.did,
        pending
      })
    }
  })
  // The build-skew guard: a core that cannot say whether the hook fired is a
  // stale hook-less build, and proceeding would silently reinstate the
  // phantom window the seam closes. The returned key set is persisted FIRST:
  // with a stale core both entries and the escrow already landed, so
  // discarding the seeds here would strand a phantom client the document
  // lists (and each retry would mint another).
  if (typeof (result as { committed?: unknown }).committed !== 'boolean') {
    try {
      if (resume && recordPersister) {
        await recordPersister({
          userKey: result.userKey,
          webvhUpdateKeys: result.webvhUpdateKeys,
          pointerDid: result.did,
          pending: null
        })
      } else {
        await enrollClientKeys!({
          clientSeed: result.clientSeed,
          userKey: result.userKey,
          webvhUpdateKeys: result.webvhUpdateKeys,
          controller: found.controller,
          pointerDid: result.did
        })
      }
    } catch (err) {
      log.error(
        'The skew-refused self-enrollment could not persist its key set; the published client is answerable only through Disconnect',
        { err }
      )
    }
    throw new SelfEnrollmentSkewError()
  }
  // The completion, persisted BEFORE the pin: the enrolled shape -- the user
  // key in, `pointerDid` stated, `pending` cleared. A resume writes through
  // the record's own persist closure; a fresh run overwrites the pending
  // record whole through the enroll path (which also covers a fresh run
  // whose hook never fired because the continuation already stood).
  let persistClientKeys: (changes: PersistableClientKeys) => Promise<void>
  if (resume && recordPersister) {
    await recordPersister({
      userKey: result.userKey,
      webvhUpdateKeys: result.webvhUpdateKeys,
      pointerDid: result.did,
      pending: null
    })
    persistClientKeys = recordPersister
  } else {
    persistClientKeys =
      enrolledPersister ??
      (await enrollClientKeys!({
        clientSeed: result.clientSeed,
        userKey: result.userKey,
        webvhUpdateKeys: result.webvhUpdateKeys,
        controller: found.controller,
        pointerDid: result.did
      }))
    if (enrolledPersister) {
      await persistClientKeys({
        userKey: result.userKey,
        webvhUpdateKeys: result.webvhUpdateKeys,
        pointerDid: result.did,
        pending: null
      })
    }
  }
  try {
    await saveUserKeyEpochPin({
      accountDid: result.did,
      epochId: result.latestEpochId,
      idb
    })
  } catch (err) {
    log.warn(
      'The self-enrolled client could not pin the user key roster epoch; the next login establishes it from the verified roster',
      { err }
    )
  }
  const clientKeys: ClientKeyRecord = {
    clientSeed: result.clientSeed,
    userKey: result.userKey,
    webvhUpdateKeys: result.webvhUpdateKeys,
    controller: found.controller,
    pointerDid: result.did
  }
  return { clientKeys, persistClientKeys }
}

/**
 * The standing fields of a credential whose keyring hit is already in hand --
 * what `establishStandingUnlock` would have returned for it, rebuilt from the
 * record's own members rather than from a fresh establishment. The recorded
 * `updateKeyMultibase` is ladder rung 0 by convention (the credential's
 * CURRENT rung is recovered from the log, with the recorded one as the
 * attribution anchor).
 *
 * @param options {object}
 * @param options.found {KeyringFetchResult}   the login credential's hit
 * @returns {Promise<StandingUnlockFields>}
 */
export async function standingFieldsOfKeyringHit({
  found
}: {
  found: KeyringFetchResult
}): Promise<StandingUnlockFields> {
  const standingClient = found.standingClient
  const delegation = found.standing?.delegation
  const delegatedClients = found.standing?.delegatedClients
  const ladderSeed = found.standing?.ladderSeed
  const rung0 = ladderSeed
    ? await ladderRung({ ladderSeed, index: 0 })
    : undefined
  const delegationKeyId = delegation
    ? delegationProofKeyId(delegation)
    : undefined
  const delegationExpires = delegation
    ? (delegation as { expires?: string }).expires
    : undefined
  const delegatedClientsKeyId = delegatedClients
    ? delegationProofKeyId(delegatedClients)
    : undefined
  const delegatedClientsExpires = delegatedClients
    ? (delegatedClients as { expires?: string }).expires
    : undefined
  return {
    ...(standingClient
      ? {
          rosterKid: standingClient.recipientKid,
          keyAgreementKeyMultibase: standingClient.keyAgreementKeyMultibase,
          unlockClientDid: standingClient.clientDid
        }
      : {}),
    ...(rung0 ? { updateKeyMultibase: rung0.keyMultibase } : {}),
    ...(delegationKeyId ? { delegationKeyId } : {}),
    ...(delegationExpires ? { delegationExpires } : {}),
    ...(delegatedClientsKeyId ? { delegatedClientsKeyId } : {}),
    ...(delegatedClientsExpires ? { delegatedClientsExpires } : {}),
    ...(found.unlockKeyAgreementKeyId
      ? { unlockKeyAgreementKeyId: found.unlockKeyAgreementKeyId }
      : {}),
    ...(found.unlockKeyAgreementKeyMultibase
      ? {
          unlockKeyAgreementKeyMultibase: found.unlockKeyAgreementKeyMultibase
        }
      : {})
  }
}
