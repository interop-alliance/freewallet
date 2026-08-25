/**
 * The credential-anchored signup's establishment ceremony: everything between
 * a derived unlock credential and an account a transient login can enter, with
 * no durable client minted anywhere. One function
 * (`establishCredentialAnchoredAccount`) serves the fresh signup and the
 * login-time re-run alike -- every stage is an ensure, so a signup torn at
 * any point converges by running the whole thing again (the account log is
 * adopted by ladder attribution, never re-created: `createDID` timestamps the
 * genesis entry, so a naive re-create would mint a different SCID).
 *
 * The stage order, with the two load-bearing ordering rules folded in:
 *
 * 1. The interim bridge and the FIRST bind: the standing-layout unlock
 *    record -- ladder seed sealed in, pointer still DID-less, the bridge
 *    delegated by the ladder VM's bare did:key (functional until promotion;
 *    superseded by the re-bind) -- is durably written BEFORE the Space is
 *    created and before the genesis entry publishes rung 0 (the transposed
 *    persist-before-publish rule: a published rung nobody can re-derive is
 *    the orphan brick).
 * 2. Wallet-core's `ensureCredentialAnchoredAccountGenesis` under the ladder
 *    VM's bare did:key as bootstrap controller: Space + collections, the
 *    one-entry ladder-anchored did:webvh genesis (ladder VM and the
 *    credential's `keyAgreement` commitment folded in), the roster's epoch[0]
 *    wrapped to the credential's standing KAK with a ladder-signed entry
 *    proof, and the collection epochs. Promotion deferred (`promoteController: false`).
 *    The ceremony installs collection epochs only when the roster's
 *    current epoch IS the candidate key it was handed; an adopted roster
 *    keyed to an earlier run's key skips that stage (reported as
 *    `epochsSkipped`), leaving the heal branch below as the one installer.
 *    The ceremony collects its roster and epoch failures; the establishment
 *    treats them as fatal here, before anything names the DID, so the tear
 *    is the heal-able kind (a DID-less record) rather than a registry sealed
 *    under a key only this tab ever held.
 * 3. The annex generation: minted under the bootstrap did:key, the
 *    generation delegation embedded (ladder-VM-signed) while the auxiliary
 *    Space is still bootstrap-controlled, the Space's controller flipped to
 *    the account DID, and the account document's `#DelegatedClients` pointer
 *    appended as a second rung-0-signed entry.
 * 4. The re-bind: the full pointer (DID in), the ladder-VM-signed bridge and
 *    annex-Space sibling, and the management delegation to the account
 *    DID -- durably written BEFORE promotion, so the next login signs under
 *    the promoted controller only once the record says to.
 * 5. The unlock-methods registry entry, written under the bootstrap did:key
 *    (the last window where a root invocation works). Best-effort.
 * 6. The Space-controller promotion onto the account DID, last.
 *
 * The caller (the signup, or the transient login's unpromoted-account heal)
 * then enters the account through the ordinary transient composition.
 */
import { WasClient } from '@interop/was-client'
import type { IZcap } from '@interop/data-integrity-core'
import {
  ensurePromotedSpaceController,
  type AccountGenesisResult
} from '@interop/wallet-core/genesis'
import {
  accountLogPinId,
  didKeyZcapClient,
  keyAgreementCommitment,
  verifyAccountLog,
  wasWebvhIdStore
} from '@interop/wallet-core/webvh'
import {
  clientAnnexDidParts,
  clientAnnexLogStore,
  delegatedClientsPointer,
  ensureCredentialAnchoredAccountGenesis,
  ensureGenerationDelegationCurrent,
  ladderRung,
  ladderVmAgent,
  ladderVmZcapClient,
  mintCredentialClientAnnexGeneration,
  mintDelegatedClientsDelegation,
  mintGenerationDelegation,
  setDelegatedClientsPointer
} from '@interop/wallet-core/clientAnnex'
import type { UnlockKeyAgreementPublication } from '@interop/wallet-core/unlock'
import {
  ensureWalletSpaceEpochs,
  mintUserKey,
  readUserKeyRoster,
  type SealableEncryptionDescriptorStore,
  type UserKey,
  type WalletSpaceEpochsResult
} from '@interop/wallet-core/keys'
import {
  delegateLogWrite,
  delegationProofKeyId
} from '@interop/wallet-core/recovery'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type { ZcapClient } from '@interop/ezcap'
import { WAS_SERVER_URL } from '@/app.config'
import {
  bindCredentialAnchoredUnlockSecret,
  type UnlockCredential
} from '@/session/keyring'
import type { TransientSessionPersistence } from '@/session/persistence'
import { accountRosterStore } from '@/session/rosterStore'
import type { StandingUnlockFields } from '@/session/unlockMethods'
import { mintSpaceId } from '@/stores/wasRemoteStore'
import { createLogger, stageTimer } from '@/lib/log'

const log = createLogger('fw:session:genesis')

/**
 * What the establishment hands back for the callers' tails: the published
 * DID, the record's unlock Space id and management zcap, and the standing
 * fields a registry entry records.
 */
export interface CredentialAnchoredEstablishment {
  did: string
  unlockSpaceId: string
  manageCapability?: IZcap
  standingFields: StandingUnlockFields
}

/**
 * Runs the whole credential-anchored establishment for one unlock credential
 * (see the module doc). Idempotent under re-run from durable state alone.
 *
 * @param options {object}
 * @param options.credential {UnlockCredential}   the derived unlock
 *   credential (one KDF run for the whole signup)
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed --
 *   freshly minted on a signup, recovered from the record on a heal re-run
 * @param options.pointer {AccountPointer}   the account pointer (`spaceId` +
 *   `host`; `did` present only on a heal whose record already names one)
 * @param options.lowEntropy {boolean}   whether the credential is
 *   low-entropy (a passphrase publishes its `keyAgreement` key as a hash
 *   commitment; a passkey PRF output publishes verbatim)
 * @param [options.email] {string}   carried inside the wrapped record
 * @param [options.priorCreatedAt] {string}   the previous bind's freshness
 *   stamp; the re-bind's stamp advances past it
 * @param options.persistence {TransientSessionPersistence}   the visit's
 *   in-memory handle (chain-head pins for every log read here)
 * @param [options.beforePromotion] {Function}   runs after the re-bind and
 *   BEFORE the controller promotion -- the last window where a root
 *   invocation under the bootstrap did:key works (the signup's registry
 *   write). Best-effort: a throw is warned, never fatal
 * @returns {Promise<CredentialAnchoredEstablishment>}
 * @throws {Error}   when the genesis's roster or epoch stage did not land
 *   (the underlying failure as `cause`); the record stays DID-less, so the
 *   next login's heal re-runs the establishment
 */
export async function establishCredentialAnchoredAccount({
  credential,
  ladderSeed,
  pointer,
  lowEntropy,
  email,
  priorCreatedAt,
  persistence,
  beforePromotion
}: {
  credential: UnlockCredential
  ladderSeed: Uint8Array
  pointer: AccountPointer
  lowEntropy: boolean
  email?: string
  priorCreatedAt?: string
  persistence: TransientSessionPersistence
  beforePromotion?: (context: {
    was: WasClient
    zcapClient: ZcapClient
    did: string
    userKey: UserKey
    establishment: CredentialAnchoredEstablishment
  }) => Promise<void>
}): Promise<CredentialAnchoredEstablishment> {
  if (!WAS_SERVER_URL) {
    throw new TypeError(
      'The credential-anchored establishment requires a configured WAS server.'
    )
  }
  const mark = stageTimer({
    log,
    ceremony: 'credential-anchored-establishment'
  })
  const host = pointer.host
  const spaceId = pointer.spaceId
  const { standing } = credential
  const bootstrapAgent = await ladderVmAgent({ ladderSeed })
  const bootstrapZcap = didKeyZcapClient({ keyAgent: bootstrapAgent })
  const bootstrapWas = new WasClient({
    serverUrl: host,
    zcapClient: bootstrapZcap
  })
  const idStore = wasWebvhIdStore({ was: bootstrapWas, spaceId })
  const keyAgreement: UnlockKeyAgreementPublication = lowEntropy
    ? {
        commitment: await keyAgreementCommitment({
          keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase
        })
      }
    : { publicKeyMultibase: standing.keyAgreementKeyMultibase }

  // 1. The interim bridge and the first bind (skipped when a heal's record
  // already carries the ladder seed -- the caller passes `priorCreatedAt`
  // from it, and the record is superseded by the re-bind below either way).
  const interimBridge = await delegateLogWrite({
    zcapClient: bootstrapZcap,
    pointer,
    recoveryClientDid: standing.clientDid
  })
  const firstBind = await bindCredentialAnchoredUnlockSecret({
    controller: bootstrapAgent.id,
    email,
    pointer: { spaceId, host },
    delegation: interimBridge,
    ladderSeed,
    priorCreatedAt,
    credential
  })
  mark('interim-bridge-and-first-bind')

  // The roster store the genesis (and the recovery read below) drive: signed
  // log appends under the LADDER VM's key -- the ceremony-tail license's
  // first-entry shape -- invoked as the bootstrap did:key.
  const rosterStoreFor = ({
    did
  }: {
    did: string
  }): SealableEncryptionDescriptorStore =>
    accountRosterStore({
      zcapClient: bootstrapZcap,
      keyAgent: bootstrapAgent,
      pointer: { did, spaceId, host },
      pinStore: persistence.logPins
    })

  // 2. The genesis ceremony under the bootstrap did:key. The candidate user
  // key seeds a fresh roster; an adopted (heal) roster keeps its own.
  const candidateUserKey = await mintUserKey()
  const genesis = await ensureCredentialAnchoredAccountGenesis({
    was: bootstrapWas,
    wasServerUrl: host,
    spaceId,
    ladderSeed,
    keyAgreement,
    standingRecipient: {
      id: standing.recipientKid,
      publicKeyMultibase: standing.keyAgreementKeyMultibase
    },
    userKey: candidateUserKey,
    idStore,
    rosterStoreFor,
    ...(pointer.did !== undefined ? { expectedDid: pointer.did } : {}),
    accountLogPinStore: persistence.logPins,
    promoteController: false
  })
  // Space provisioning, did:web keys, the did:webvh genesis entry, the
  // roster, and the collection epochs, all inside the shared ceremony.
  mark('genesis')
  const did = genesis.did
  const fullPointer: AccountPointer = { spaceId, host, did }
  // The ceremony collects its roster and epoch failures instead of
  // throwing; here they are fatal. A roster that never landed leaves the
  // candidate key held in this tab's memory alone, and a registry sealed
  // under it would be unreadable forever (the transient entry's empty-roster
  // heal mints a different key). Refusing BEFORE the re-bind keeps the
  // record DID-less, which is exactly what routes the next login into the
  // establishment re-run that converges.
  assertGenesisLanded({ failed: genesis.failed, epochs: genesis.epochs })
  if (!genesis.rosterDescriptor) {
    throw new Error('The user-key roster genesis did not land.')
  }

  // A heal re-run that adopted a roster seeded by the torn earlier run: the
  // real user key is recovered from the credential's own standing wrap, and
  // the collection epochs are completed under it. The ceremony skipped its
  // own epochs stage on this mismatch, so a collection the earlier run never
  // reached is still un-epoch'd here and gets epoch[0] under the roster's
  // key (an epoch installed under the candidate would have been adopted
  // as-is, keying the collection to a key nobody holds).
  let userKey: UserKey = candidateUserKey
  if (genesis.rosterDescriptor.currentEpoch !== candidateUserKey.id) {
    const read = await readUserKeyRoster({
      store: rosterStoreFor({ did }),
      clientKeyAgreementKey: standing.agents.keyAgreementKey
    })
    if (!read) {
      throw new Error(
        'The adopted user-key roster could not be read back with this ' +
          'credential.'
      )
    }
    userKey = read.userKey
    const epochs = await ensureWalletSpaceEpochs({
      was: bootstrapWas,
      spaceId,
      userKey
    })
    assertGenesisLanded({ failed: [], epochs })
    mark('heal-adopted-roster-epochs')
  }

  // 3. The annex generation, so the very next login can enroll a
  // transient client: reuse the pointed one; mint, embed the delegation,
  // flip the auxiliary Space's controller, and point otherwise.
  const verified = await verifyAccountLog({
    did,
    spaceId,
    host,
    pinStore: persistence.logPins
  })
  mark('verify-account-log')
  const ladderZcap = await ladderVmZcapClient({ accountDid: did, ladderSeed })
  let clientAnnexDid = delegatedClientsPointer({ doc: verified.doc })
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  const rung1 = await ladderRung({ ladderSeed, index: 1 })
  if (!clientAnnexDid) {
    const clientAnnexSpaceId = mintSpaceId()
    const minted = await mintCredentialClientAnnexGeneration({
      was: bootstrapWas,
      wasServerUrl: host,
      spaceId: clientAnnexSpaceId,
      controller: bootstrapAgent.id,
      ladderSeed
    })
    mark('annex-generation-mint')
    // The delegation embeds while the auxiliary Space still answers to the
    // bootstrap did:key; the controller flip follows, then the pointer.
    await ensureGenerationDelegationCurrent({
      store: clientAnnexLogStore({
        was: bootstrapWas,
        spaceId: clientAnnexSpaceId,
        generationId: minted.generationId
      }),
      ladderSeed,
      generationId: minted.generationId,
      mintGenerationDelegation: async ({ clientAnnexDid: generationDid }) =>
        mintGenerationDelegation({
          zcapClient: ladderZcap,
          wasServerUrl: host,
          spaceId,
          clientAnnexDid: generationDid
        }),
      expectedDid: minted.did
    })
    mark('generation-delegation')
    await bootstrapWas
      .space(clientAnnexSpaceId)
      .configure({ controller: did, force: true })
    mark('annex-controller-flip')
    // The second rung-0-signed account-log entry: the ratified
    // `#DelegatedClients` service pointer, under the ladder's own update
    // authority (rung 0 active, rung 1 staged).
    await setDelegatedClientsPointer({
      idStore,
      updateKeys: { updateSeed: rung0.seed, stagedSeed: rung1.seed },
      clientAnnexDid: minted.did,
      expectedDid: did,
      pinStore: persistence.logPins,
      logId: accountLogPinId({ spaceId })
    })
    mark('delegated-clients-pointer')
    clientAnnexDid = minted.did
  }
  const clientAnnex = clientAnnexDidParts({ did: clientAnnexDid })

  // 4. The final bridge and sibling, ladder-VM-signed (they must survive
  // promotion, which the interim did:key-signed bridge cannot), and the
  // re-bind: full pointer, both delegations, the management zcap to the
  // account DID.
  const bridge = await delegateLogWrite({
    zcapClient: ladderZcap,
    pointer: fullPointer,
    recoveryClientDid: standing.clientDid
  })
  const sibling = await mintDelegatedClientsDelegation({
    zcapClient: ladderZcap,
    wasServerUrl: host,
    clientAnnexSpaceId: clientAnnex.spaceId,
    controller: standing.clientDid
  })
  const rebind = await bindCredentialAnchoredUnlockSecret({
    controller: bootstrapAgent.id,
    email,
    pointer: fullPointer,
    delegation: bridge,
    delegatedClients: sibling,
    ladderSeed,
    delegateManagementTo: did,
    priorCreatedAt: firstBind.createdAt,
    credential
  })
  mark('bridge-sibling-rebind')

  const delegationKeyId = delegationProofKeyId(bridge)
  const delegatedClientsKeyId = delegationProofKeyId(sibling)
  const establishment: CredentialAnchoredEstablishment = {
    did,
    unlockSpaceId: rebind.unlockSpaceId,
    ...(rebind.manageCapability
      ? { manageCapability: rebind.manageCapability }
      : {}),
    standingFields: {
      rosterKid: standing.recipientKid,
      keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
      updateKeyMultibase: rung0.keyMultibase,
      unlockClientDid: standing.clientDid,
      ...(delegationKeyId ? { delegationKeyId } : {}),
      ...((bridge as { expires?: string }).expires
        ? { delegationExpires: (bridge as { expires?: string }).expires }
        : {}),
      ...(delegatedClientsKeyId ? { delegatedClientsKeyId } : {}),
      ...((sibling as { expires?: string }).expires
        ? {
            delegatedClientsExpires: (sibling as { expires?: string }).expires
          }
        : {}),
      ...(rebind.unlockKeyAgreementKeyId
        ? { unlockKeyAgreementKeyId: rebind.unlockKeyAgreementKeyId }
        : {}),
      ...(rebind.unlockKeyAgreementKeyMultibase
        ? {
            unlockKeyAgreementKeyMultibase:
              rebind.unlockKeyAgreementKeyMultibase
          }
        : {})
    }
  }

  // 5. The caller's pre-promotion tail (the signup's registry write): the
  // last window where a root invocation under the bootstrap did:key works.
  // Best-effort -- the account is complete without it.
  if (beforePromotion) {
    try {
      await beforePromotion({
        was: bootstrapWas,
        zcapClient: bootstrapZcap,
        did,
        userKey,
        establishment
      })
    } catch (err) {
      log.warn('The pre-promotion tail failed (continuing)', { err })
    }
    mark('pre-promotion-tail')
  }

  // 6. The promotion, last: from here on the ladder's authority is exactly
  // its licensed document inventory (delegation and log-anchored signing), and
  // the bootstrap did:key stops verifying.
  await ensurePromotedSpaceController({
    was: bootstrapWas,
    wasAsClient: bootstrapWas,
    spaceId,
    did
  })
  mark('promotion')

  return establishment
}

/**
 * Refuses a genesis whose roster or epoch stages did not land: the ceremony
 * reports them on `failed` (a stage that could not run) and on
 * `epochs.failed` (a collection the fan-out could not epoch) rather than
 * throwing, and on a credential-anchored account no login-time sweep ever
 * finishes them -- the establishment re-run is the only mender, so the
 * establishment must stop here for it to be reached.
 *
 * @param options {object}
 * @param options.failed {Array}   the ceremony's collected stage failures
 * @param [options.epochs] {WalletSpaceEpochsResult}   the collection
 *   epoch fan-out's result, when the stage ran
 * @throws {Error}   carrying the first underlying failure as `cause`
 */
function assertGenesisLanded({
  failed,
  epochs
}: {
  failed: AccountGenesisResult['failed']
  epochs?: WalletSpaceEpochsResult
}): void {
  const stage = failed.find(
    entry => entry.stage === 'roster' || entry.stage === 'epochs'
  )
  if (stage) {
    throw new Error(
      `The credential-anchored genesis's ${stage.stage} stage failed.`,
      { cause: stage.error }
    )
  }
  const collection = epochs?.failed[0]
  if (collection) {
    throw new Error(
      'The credential-anchored genesis could not install a key epoch on ' +
        `collection "${collection.collectionId}".`,
      { cause: collection.error }
    )
  }
}
