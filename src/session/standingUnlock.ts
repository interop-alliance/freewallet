/**
 * The standing-configuration establishment ceremony: what turns a passphrase or
 * passkey bind into a STANDING unlock credential -- one a fresh browser can
 * later self-enroll with, holding nothing but the credential (FW-154's
 * one-codepath model, the recovery-code configuration minus spend-on-use).
 * Run from a live session of either ceremony kind. On a remembered session
 * the stages run in the recovery-anchor order (decryption material before
 * authorization):
 *
 * 1. The credential's user-key wrap lands in the `key-map/user-key.jsonl`
 *    roster first (escrow: every epoch, so a later self-enrollment decrypts
 *    pre-bind history), kept alive by rotation fan-out from then on.
 * 2. The authorization bridge: a pre-minted PUT-on-`did.jsonl` delegation to
 *    the credential-derived signing DID, sealed into the unlock record beside
 *    the update-key ladder seed -- and, when the account document already
 *    points at an annex generation, the annex-Space sibling delegation
 *    (GET+PUT over the auxiliary Space's items subtree, to the same signing
 *    DID). An account with no pointed generation has no auxiliary Space id
 *    to target yet; the record then binds without a sibling and a later
 *    re-mint adds one once the pointer exists.
 * 3. The re-bind: the unlock record is rewritten in the standing layout
 *    (`wrapUnlockRecord` -- shell, bridge, sibling, ladder, binding MAC),
 *    superseding the credential's previous record (the plain layout
 *    survives only on no-WAS deployments, where this ceremony never runs).
 *    The record is inert until the entry below publishes its ladder VM, and
 *    it is what makes the seed durable before anything names it.
 * 4. The document entry: the credential's `keyAgreement` key -- verbatim for
 *    a high-entropy credential (a passkey PRF output), a hash commitment for
 *    a low-entropy-derived one (a passphrase; publishing the key verbatim
 *    would turn the server-gated guessing oracle into a world-readable
 *    offline one) -- and the hash of ladder rung 0 in `nextKeyHashes`.
 *
 * A standing member's rung-0 commitment is stable for its whole standing run:
 * `publishUnlockKey` refuses a bind naming a different hash. So a re-run of
 * a torn establishment must reach the entry with the seed that bound the
 * member, and both branches write the record (the seed's one durable home)
 * before the entry. A run given no seed reads one back from the record a
 * prior run sealed for this account before minting a fresh one.
 *
 * On a transient session the acting authority is the login credential's
 * ladder, and the order changes for one reason: a ladder-signed roster
 * append is licensed only at the inventory-changing version its own entry
 * mints. So the record is written remotely first and stays inert (its ladder
 * VM is in no document yet), the bound credential's annex rung-0 hash is
 * committed under the acting credential's rung as a blocking stage, the bind
 * entry publishes, and only then does the escrow append. Nothing lands on
 * this browser.
 *
 * On both kinds the new record's bridge and sibling are signed by that
 * credential's OWN ladder VM, so a later strike of any other credential's
 * inventory can rot only the record the same ceremony deletes.
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
import { equalBytes } from '@noble/ciphers/utils.js'
import { WasClient, type ServiceDescription } from '@interop/was-client'
import {
  publishUnlockKey,
  type UnlockLogStore
} from '@interop/wallet-core/unlock'
import type { ClientKeyRecord } from '@interop/wallet-core/keys'
import {
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
  ladderVmZcapClient,
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
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import type { Session } from '@/types/auth'
import {
  bindUnlockSecret,
  deriveUnlockCredential,
  fetchKeyring,
  fetchTransientKeyring,
  unlockManagementGrantee,
  type KeyringFetchResult,
  type PersistableClientKeys,
  type UnlockCredential
} from '@/session/keyring'
import { WAS_SERVER_URL } from '@/app.config'
import {
  accountCeremonyContext,
  requireEnrolledCeremonyContext,
  type AccountCeremonyContext
} from '@/session/accountCeremonyContext'
import {
  clientAnnexReachOf,
  ensureGenerationDelegation,
  standingClientAnnexReachOf
} from '@/session/annexReach'
import {
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import {
  refreshStandingDelegationFields,
  type StandingUnlockFields
} from '@/session/unlockMethods'
import { createLogger } from '@/lib/log'
import { wasServiceDescription } from '@/lib/wasService'
import { zcapExpires } from '@/lib/zcap'

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
 * @param options.pinStore {ResourceLogPinStore}   the caller's chain-head
 *   pins; the store carries the account log's slot, so every read and
 *   publish through it is checked against the pin and advances it
 * @param options.serviceDescription {ServiceDescription}   the server's
 *   discovered service description, so the store's client skips discovery
 * @returns {UnlockLogStore}
 */
export function unlockLogStore({
  pointer,
  delegation,
  zcapClient,
  pinStore,
  serviceDescription
}: {
  pointer: AccountPointer
  delegation: IZcap
  zcapClient: ZcapClient
  pinStore: ResourceLogPinStore
  serviceDescription: ServiceDescription
}): UnlockLogStore {
  return delegatedWebvhLogStore({
    host: pointer.host,
    spaceId: pointer.spaceId,
    collectionId: ID_COLLECTION.id,
    delegation,
    zcapClient,
    pinStore,
    serviceDescription
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
 * @param options.session {Session}   the live session running the ceremony
 * @param [options.context] {AccountCeremonyContext | null}   this session's
 *   ceremony context, resolved by the caller; the enrolled kind keeps the
 *   roster-first order and binds a local client-key record, the ladder kind
 *   binds the record remotely first and escrows after its bind entry
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
 *   when this ceremony throws before returning). When absent, the seed a
 *   prior run sealed into the credential's standing record for this account
 *   is reused, and a fresh one is minted only when no such record stands
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<object>}   the new record's unlock Space id, management
 *   zcap, persist closure (absent on the ladder kind, which writes nothing
 *   local), and the standing fields the registry entry records
 */
export async function establishStandingUnlock({
  session,
  context,
  secret,
  kdf,
  lowEntropy,
  email,
  credential: derived,
  ladderSeed: mintedLadderSeed,
  idb
}: {
  session: Session
  context?: AccountCeremonyContext | null
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
  persistClientKeys?: (changes: PersistableClientKeys) => Promise<void>
  standingFields: StandingUnlockFields
  ladderSeed: Uint8Array
  delegatedClients?: IZcap
}> {
  const ctx =
    context ??
    (await accountCeremonyContext({ session })) ??
    requireEnrolledCeremonyContext({
      session,
      action: 'Establishing a standing unlock credential'
    })
  const { pointer, controller: accountController } = ctx
  const { userKey } = session.profile
  const controller = session.profile.accountController ?? accountController
  const credential = derived ?? (await deriveUnlockCredential({ secret, kdf }))
  const { standing } = credential
  const sealed = await sealedLadderSeed({
    credential,
    pointer,
    accountLogPinStore: session.persistence.logPins
  })
  if (mintedLadderSeed && sealed && !equalBytes(mintedLadderSeed, sealed)) {
    // The record write below is a plain overwrite and precedes the entry's
    // refusal, so a caller-minted seed that differs from the sealed one
    // refuses here, before the sealed seed (the one a standing member may
    // name) is destroyed.
    throw new Error(
      "The credential's unlock record already seals a different ladder " +
        'seed for this account; the establishment refuses to overwrite it.'
    )
  }
  const ladderSeed = mintedLadderSeed ?? sealed ?? generateLadderSeed()
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  // Invariant 17: every record's bridge and sibling are signed by that
  // record's OWN credential's ladder VM, so a strike of any other
  // credential's inventory can never rot this record. The signer is inert
  // until the bind entry below publishes that VM.
  const boundZcapClient = await ladderVmZcapClient({
    accountDid: pointer.did,
    ladderSeed
  })

  /**
   * The bridge delegation and, where the account points at an annex
   * generation, the annex-Space sibling delegation -- both to the
   * credential's own derived signing DID and both signed by its own ladder
   * VM. Best-effort on the sibling: a sibling-less standing record still
   * self-enrolls, it just cannot reach the annex log.
   */
  const mintDelegations = async (): Promise<{
    delegation: IZcap
    delegatedClients?: IZcap
    clientAnnexDid?: string
  }> => {
    const delegation = await delegateLogWrite({
      zcapClient: boundZcapClient,
      pointer,
      recoveryClientDid: standing.clientDid
    })
    let delegatedClients: IZcap | undefined
    let clientAnnexDid: string | undefined
    try {
      const { doc } = await verifiedAccountLog({
        session,
        pointer
      })
      clientAnnexDid = delegatedClientsPointer({ doc })
      if (clientAnnexDid) {
        delegatedClients = await mintDelegatedClientsDelegation({
          zcapClient: boundZcapClient,
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
    return {
      delegation,
      ...(delegatedClients ? { delegatedClients } : {}),
      ...(clientAnnexDid ? { clientAnnexDid } : {})
    }
  }

  /**
   * The bound credential's rung-0 hash into the pointed generation's
   * `nextKeyHashes`, in one atomic hash-restating entry signed by the ACTING
   * credential's committed rung. Without it a freshly bound credential is
   * locked out of transient login until the next generation swap.
   *
   * Best-effort on the enrolled branch (an acting rung the generation does
   * not commit is the honest skip). Blocking on the ladder branch, where the
   * ceremony's own later strike is signed by this rung.
   */
  const commitAnnexRung = async ({
    clientAnnexDid
  }: {
    clientAnnexDid: string
  }): Promise<void> => {
    const actingLadderSeed = session.profile.ladderSeed
    if (!actingLadderSeed) {
      throw new ClientAnnexRungCommitSkipped()
    }
    const serviceDescription = await wasServiceDescription()
    const reach =
      ctx.kind === 'ladder' && ctx.sibling
        ? standingClientAnnexReachOf({
            pointer,
            clientAnnexDid,
            standing: {
              standingClient: session.profile.standingUnlock!.standingClient,
              delegatedClients: ctx.sibling
            },
            pinStore: session.persistence.logPins,
            serviceDescription
          })
        : clientAnnexReachOf({
            session,
            pointer,
            clientAnnexDid,
            serviceDescription
          })
    await commitClientAnnexRung({
      store: reach.logStore(),
      boundLadderSeed: ladderSeed,
      actingLadderSeed,
      generationId: reach.generationId,
      expectedDid: clientAnnexDid
    })
  }

  let bound: {
    unlockSpaceId: string
    manageCapability?: IZcap
    persistClientKeys?: (changes: PersistableClientKeys) => Promise<void>
    unlockKeyAgreementKeyId?: string
    unlockKeyAgreementKeyMultibase?: string
  }
  let delegation: IZcap
  let delegatedClients: IZcap | undefined

  if (ctx.kind === 'ladder') {
    // The ladder branch's order (the transient recovery's shape). The record
    // is written FIRST and is inert -- its ladder VM stands in no document
    // yet -- so a tear before the bind entry leaves an orphan a retry with
    // the same secret overwrites. The escrow follows the entry rather than
    // preceding it: a ladder-signed roster append is licensed only at the
    // inventory-changing version its own entry mints.
    const minted = await mintDelegations()
    delegation = minted.delegation
    delegatedClients = minted.delegatedClients
    bound = await ctx.bindRecord({
      credential,
      controller,
      pointer,
      delegation,
      ...(delegatedClients ? { delegatedClients } : {}),
      ladderSeed,
      ...(email ? { email } : {}),
      delegateManagementTo: unlockManagementGrantee({ pointer, controller })
    })
    if (minted.clientAnnexDid) {
      // Blocking here: the strike entry a later retirement publishes is
      // signed by this rung, so a bind that skipped the commit would leave
      // the ceremony with no rung to sign with.
      await commitAnnexRung({ clientAnnexDid: minted.clientAnnexDid })
    }
    await publishUnlockKey({
      idStore: ctx.idStore,
      signer: ctx.signer,
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
      ladderSeed,
      expectedDid: pointer.did
    })
    invalidateVerifiedLog({ profile: session.profile })
    // The escrow, anchored at the entry just published: the new credential's
    // standing key into every epoch. Signed by the ACTING credential's
    // ladder VM, which the post-entry document still lists.
    await addUserKeyRosterRecipient({
      store: ctx.rosterStore,
      recipient: {
        id: standing.recipientKid,
        publicKeyMultibase: standing.keyAgreementKeyMultibase
      },
      ownerKeyAgreementKey: ctx.standingKeyAgreementKey
    })
  } else {
    const { clientSeed } = session.profile
    if (!clientSeed) {
      throw new Error(
        "Establishing a standing unlock credential requires this client's " +
          'seed in the session.'
      )
    }
    // 1. Decryption material first: the credential's wrap into every roster
    // epoch. Idempotent -- a wrap already standing is returned as-is.
    await addUserKeyRosterRecipient({
      store: ctx.rosterStore,
      recipient: {
        id: standing.recipientKid,
        publicKeyMultibase: standing.keyAgreementKeyMultibase
      },
      ownerKeyAgreementKey: ctx.clientKeyAgreementKey
    })

    // 2. The bridge and sibling delegations, signed by the bound
    // credential's own ladder VM (invariant 17). Inert until the entry
    // below publishes that VM.
    const minted = await mintDelegations()
    delegation = minted.delegation
    delegatedClients = minted.delegatedClients

    // 3. The record in the standing layout, BEFORE the entry: the seed's one
    // durable home. A tear here leaves an inert record a re-run with the
    // same secret reads its seed back from and overwrites; a tear after the
    // entry leaves a member whose commitment only that seed can extend.
    bound = await bindUnlockSecret({
      clientSeed,
      controller,
      secret,
      kdf,
      email,
      userKey,
      webvhUpdateKeys: ctx.clientWebvhKeys,
      pointer,
      delegateManagementTo: unlockManagementGrantee({ pointer, controller }),
      delegation,
      ...(delegatedClients ? { delegatedClients } : {}),
      ladderSeed,
      credential,
      idb
    })

    // 4. The document entry: the keyAgreement publication (commitment for a
    // low-entropy credential, verbatim for a high-entropy one) and the hash
    // of ladder rung 0 in `nextKeyHashes`.
    await publishUnlockKey({
      idStore: ctx.idStore,
      signer: ctx.signer,
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
      ladderSeed,
      expectedDid: pointer.did
    })
    invalidateVerifiedLog({ profile: session.profile })

    // 4b. The annex rung commit, best-effort: nothing licenses a bind to
    // mint a generation, and the lockout consequence stands as documented.
    if (minted.clientAnnexDid) {
      try {
        await commitAnnexRung({ clientAnnexDid: minted.clientAnnexDid })
      } catch (err) {
        log.warn(
          err instanceof ClientAnnexRungCommitSkipped
            ? 'The login credential carries no ladder seed; the bound credential waits for the next generation swap'
            : (err as { name?: string }).name ===
                'ClientAnnexRungUncommittedError'
              ? "The login credential's rung is not committed in the pointed generation; the bound credential waits for the next generation swap"
              : "Could not commit the bound credential's annex rung",
          { err }
        )
      }
    }
  }

  const delegationKeyId = delegationProofKeyId(delegation)
  const delegationExpires = zcapExpires(delegation)
  const delegatedClientsKeyId = delegatedClients
    ? delegationProofKeyId(delegatedClients)
    : undefined
  const delegatedClientsExpires = delegatedClients
    ? zcapExpires(delegatedClients)
    : undefined
  return {
    unlockSpaceId: bound.unlockSpaceId,
    ...(bound.manageCapability
      ? { manageCapability: bound.manageCapability }
      : {}),
    ...(bound.persistClientKeys
      ? { persistClientKeys: bound.persistClientKeys }
      : {}),
    ladderSeed,
    // The bound credential's own sibling delegation into the client annex,
    // handed back so a caller retiring ANOTHER credential can reach the annex
    // log through this one: its own sibling stops verifying the moment its
    // ladder VM leaves the document.
    ...(delegatedClients ? { delegatedClients } : {}),
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
 * The bind's annex-commit stage had no acting ladder seed to sign with. The
 * enrolled branch logs and carries on; the ladder branch never raises it,
 * since a session on that branch holds a seed by construction.
 */
class ClientAnnexRungCommitSkipped extends Error {
  constructor() {
    super('The acting session carries no ladder seed for the annex commit.')
    this.name = 'ClientAnnexRungCommitSkipped'
  }
}

/**
 * The ladder seed a prior run of the establishment sealed into the
 * credential's unlock record for this account, when a standing record is
 * there. The read is the transient fetch (nothing browser-local is written),
 * and a record naming another account (a secret reused across accounts) or a
 * plain-layout one yields nothing: the bind overwrites those by design.
 *
 * @param options {object}
 * @param options.credential {UnlockCredential}
 * @param options.pointer {AccountPointer}   the account being bound to
 * @param options.accountLogPinStore {ResourceLogPinStore}
 * @returns {Promise<Uint8Array | undefined>}
 */
async function sealedLadderSeed({
  credential,
  pointer,
  accountLogPinStore
}: {
  credential: UnlockCredential
  pointer: AccountPointer
  accountLogPinStore: ResourceLogPinStore
}): Promise<Uint8Array | undefined> {
  if (!WAS_SERVER_URL) {
    return undefined
  }
  const found = await fetchTransientKeyring({ credential, accountLogPinStore })
  const ladderSeed = found?.standing?.ladderSeed
  if (!ladderSeed || found?.pointer?.did !== pointer.did) {
    return undefined
  }
  log.info(
    "Reusing the ladder seed a prior run sealed into the credential's unlock record"
  )
  return ladderSeed
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
    requireEnrolledCeremonyContext({
      session,
      action: 'Establishing the annex-generation inventory'
    })
  const { zcapClient } = session.profile

  const found = await fetchKeyring({
    secret,
    kdf,
    idb,
    accountLogPinStore: session.persistence.logPins
  })
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
    session,
    pointer
  })
  const serviceDescription = await wasServiceDescription()
  const pointed = await ensurePointedClientAnnexGeneration({
    account: { did: pointer.did, doc: account.doc, log: account.log },
    wasServerUrl: pointer.host,
    ladderSeed,
    was: new WasClient({
      serverUrl: pointer.host,
      zcapClient: didKeyZcapClient({ keyAgent }),
      serviceDescription
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
    signer: { kind: 'client', updateKeys: clientWebvhKeys }
  })
  const clientAnnexDid = pointed.clientAnnexDid
  if (pointed.generationMinted) {
    invalidateVerifiedLog({ profile: session.profile })
  }

  // The embedded generation delegation on an ALREADY-POINTED generation:
  // installed when the annex document carries none yet and renewed near
  // expiry otherwise -- signed by this enrolled client's promoted key. A
  // generation the fold just minted carries a fresh delegation already.
  const clientAnnex = clientAnnexReachOf({
    session,
    pointer,
    clientAnnexDid,
    serviceDescription
  })
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
    ...(zcapExpires(delegatedClients)
      ? {
          delegatedClientsExpires: zcapExpires(delegatedClients)
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
 * is written browser-local BEFORE the pivot entry publishes the client, so a
 * tab closing anywhere after the add entry leaves a record the next login's
 * resume finishes rather than a phantom client only Disconnect could
 * remove. After the core returns, the completion overwrites the record with
 * the enrolled shape (the user key in, `pending` cleared).
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
 * @param options.pinStore {ResourceLogPinStore}   the login's chain-head
 *   pins, which the ceremony's log store carries: this login's first contact
 *   establishes the account log's slot, every later read in the same login
 *   checks against it, and it dies with the tab
 * @param [options.resume] {object}   the pending record's replayed contents:
 *   `{ clientSeed, webvhUpdateKeys, builtOnHead }`
 * @returns {Promise<object>}   the persisted key set and its persist closure
 */
export async function selfEnrollStandingClient({
  found,
  pinStore,
  resume
}: {
  found: KeyringFetchResult
  pinStore: ResourceLogPinStore
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
  const serviceDescription = await wasServiceDescription()
  const result = await selfEnrollClientCore({
    pointer,
    ladderSeed: standing.ladderSeed,
    credentialKeyAgreementKey: standingClient.agents.keyAgreementKey,
    serviceDescription,
    logStore: unlockLogStore({
      pointer,
      delegation: standing.delegation,
      zcapClient: standingClient.agents.zcapClient,
      pinStore,
      serviceDescription
    }),
    ...(resume ? { resume } : {}),
    // The persist-before-publish seam: the pending-shape record is written
    // browser-local, stamped with the head the add entry is about to be
    // built on, before that entry publishes a client only this tab could
    // re-derive. Idempotent per attempt (the conflict retry re-fires it); on
    // a resume the seeds handed back are the record's own, so the write
    // restates what already stands.
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
  const delegationExpires = delegation ? zcapExpires(delegation) : undefined
  const delegatedClientsKeyId = delegatedClients
    ? delegationProofKeyId(delegatedClients)
    : undefined
  const delegatedClientsExpires = delegatedClients
    ? zcapExpires(delegatedClients)
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
