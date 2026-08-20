/**
 * The transient login: the public-terminal composition over the transient
 * unlock-record fetch and the capability-bound replica-less storage posture.
 * Nothing here performs a durable local write -- the whole flow rides one
 * in-memory persistence handle (trust-on-first-use pins, per-visit writer id)
 * and dies with the tab.
 *
 * Two exports drive it. `routeUnlockLogin` is the post-KDF posture decision
 * both keyring login entry points run: a browser already holding this
 * credential's client-key record proceeds durable (the mechanical ratchet --
 * silent until the remember-this-browser UX lands), a browser holding none
 * defaults to the transient posture, and an explicit `rememberBrowser` input
 * forces either side (true runs the durable standing self-enrollment; false
 * on a remembered browser refuses rather than forking postures, per
 * `decisions/0001`). `transientSessionFromKeyringHit` is the composition
 * itself: verify the account log, enroll a per-visit key into the companion
 * generation through the record's sibling delegation (the loud entry
 * `decisions/0002` requires before any authority is exercised), take the
 * generation delegation as embedded, read the user key from the credential's
 * standing roster wrap (no escrow -- a transient client never joins the
 * roster), and assemble the session on the replica-less remote-direct
 * storage posture, invoking as `<companionDid>#<vm>` under the delegation.
 *
 * Failure states are typed, not designed (the honest login copy over them is
 * a separate concern): each precondition refuses with
 * `TransientLoginUnavailableError` before any ceremony byte is written, and
 * network errors rethrow unchanged so a flap stays distinguishable from a
 * generation lapse.
 */
import { agentsFromSeed } from '@interop/wallet-core/identity'
import type { UnlockKdf } from '@interop/wallet-core/keyring'
import {
  clientSigningKeyMultibase,
  delegatedClientsDelegationSpaceId,
  delegatedClientsPointer,
  delegatedWebvhLogStore,
  embeddedGenerationDelegation,
  enrollTransientClient,
  isWebvhDid,
  verifyAccountLog,
  webvhZcapClient,
  type CompanionWriteStore
} from '@interop/wallet-core/webvh'
import {
  ensureUserKeyRoster,
  ensureWalletSpaceEpochs,
  mintUserKey,
  readUserKeyRoster,
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner
} from '@interop/wallet-core/keys'
import { didKeyZcapClient, ladderVmAgent } from '@interop/wallet-core/webvh'
import { ensurePromotedSpaceController } from '@interop/wallet-core/genesis'
import { webvhResourceLogController } from '@interop/wallet-core/resourceLog'
import { WasClient } from '@interop/was-client'
import { WAS_SERVER_URL } from '@/app.config'
import { hasClientKeyRecord } from '@/lib/sessionKey'
import { establishClientlessAccount } from '@/session/clientlessGenesis'
import {
  transientSessionPersistence,
  type TransientSessionPersistence
} from '@/session/persistence'
import { initSessionFromSeed } from '@/session/initSession'
import {
  deriveUnlockCredential,
  fetchTransientKeyring,
  type TransientKeyringFetchResult,
  type UnlockCredential
} from '@/session/keyring'
import type { Session } from '@/types/auth'

/**
 * Why a transient login cannot proceed. Typed reasons, no copy: the login
 * page maps them (for now, onto the existing not-enrolled guidance).
 *
 * - `no-was-server`: the transient posture presupposes a remote WAS server.
 * - `remote-direct`: the partitioned CHAPI popup keeps its own posture.
 * - `no-standing`: the unlock record carries no standing authority (a plain
 *   pointer record -- pre-promotion, or bound before standing credentials).
 * - `no-delegated-clients`: a standing record without the companion-Space
 *   sibling delegation (a recovery-code record, or one minted before the
 *   sibling existed).
 * - `unpromoted-account`: the account pointer names no did:webvh.
 * - `no-companion-generation`: the account document carries no
 *   delegated-clients pointer, or the pointed generation's log is gone (a
 *   GC'd generation nothing re-minted).
 * - `no-generation-delegation`: the generation would need its delegation
 *   minted, which takes a durable signer this session does not hold.
 * - `no-user-key-roster`: the account has no user key roster to read.
 */
export type TransientLoginUnavailableReason =
  | 'no-was-server'
  | 'remote-direct'
  | 'no-standing'
  | 'no-delegated-clients'
  | 'unpromoted-account'
  | 'no-companion-generation'
  | 'no-generation-delegation'
  | 'no-user-key-roster'

/**
 * A transient login refused before any ceremony byte was written: the
 * credential, the record, or the account is not in the posture the transient
 * flow needs. Carries the typed `reason` above.
 */
export class TransientLoginUnavailableError extends Error {
  reason: TransientLoginUnavailableReason

  constructor({
    reason,
    message
  }: {
    reason: TransientLoginUnavailableReason
    message?: string
  }) {
    super(message ?? `A transient login is unavailable here (${reason}).`)
    this.name = 'TransientLoginUnavailableError'
    this.reason = reason
  }
}

/**
 * A login that asked NOT to be remembered on a browser that already holds
 * this credential's client-key record. Honoring it would mean either a
 * dual-posture fork (`decisions/0001` forbids one) or a destructive wipe, so
 * the routing refuses; the remember-this-browser UX turns this refusal into
 * a loud coerce-and-notify.
 */
export class AlreadyRememberedError extends Error {
  constructor() {
    super('This browser already remembers the account for this credential.')
    this.name = 'AlreadyRememberedError'
  }
}

/**
 * The post-KDF posture decision both keyring login entry points run, BEFORE
 * any fetch: durable (today's `fetchKeyring` path) or transient. The check is
 * create-nothing -- the credential is derived once (threaded onward so the
 * KDF never re-runs) and the client-key record probe never creates the
 * session database.
 *
 * The decision table: no WAS server or a remote-direct (CHAPI popup) session
 * is always durable (the transient posture is unreachable there);
 * `rememberBrowser: true` is durable (the programmatic standing
 * self-enrollment entry); a browser holding this credential's client-key
 * record is durable (the ratchet -- with `rememberBrowser: false` refused as
 * `AlreadyRememberedError` rather than silently coerced); everything else --
 * a non-remembered browser -- is transient, the default.
 *
 * @param options {object}
 * @param [options.secret] {string | Uint8Array}   the unlock secret, when no
 *   derived credential is supplied
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @param [options.credential] {UnlockCredential}   an already-derived
 *   credential for the same secret
 * @param [options.idb] {IDBFactory}   first-party IndexedDB for the probe
 * @param [options.remoteDirectStorage] {boolean}   the CHAPI popup posture
 * @param [options.rememberBrowser] {boolean}   the explicit posture input;
 *   absent means route on the record probe
 * @returns {Promise<object>}   `{ posture: 'durable', credential? }` or
 *   `{ posture: 'transient', credential, persistence }` -- the transient arm
 *   carries the visit's in-memory persistence handle so every later stage
 *   (the record fetch's account-log pins included) shares it
 */
export async function routeUnlockLogin({
  secret,
  kdf,
  credential,
  idb,
  remoteDirectStorage = false,
  rememberBrowser
}: {
  secret?: string | Uint8Array
  kdf: UnlockKdf
  credential?: UnlockCredential
  idb?: IDBFactory
  remoteDirectStorage?: boolean
  rememberBrowser?: boolean
}): Promise<
  | { posture: 'durable'; credential?: UnlockCredential }
  | {
      posture: 'transient'
      credential: UnlockCredential
      persistence: TransientSessionPersistence
    }
> {
  if (!WAS_SERVER_URL || remoteDirectStorage) {
    if (rememberBrowser === false) {
      throw new TransientLoginUnavailableError({
        reason: WAS_SERVER_URL ? 'remote-direct' : 'no-was-server'
      })
    }
    return { posture: 'durable', ...(credential ? { credential } : {}) }
  }
  if (rememberBrowser === true) {
    return { posture: 'durable', ...(credential ? { credential } : {}) }
  }
  const derived =
    credential ??
    (await deriveUnlockCredential({
      secret: secret as string | Uint8Array,
      kdf
    }))
  const remembered = await hasClientKeyRecord({
    spaceId: derived.unlock.spaceId,
    idb
  })
  if (remembered) {
    if (rememberBrowser === false) {
      throw new AlreadyRememberedError()
    }
    return { posture: 'durable', credential: derived }
  }
  return {
    posture: 'transient',
    credential: derived,
    persistence: transientSessionPersistence()
  }
}

/**
 * Wraps a companion write store so a generation whose log is gone surfaces
 * as the typed refusal instead of a plain "did.jsonl is missing" error --
 * and BEFORE anything is written: the enrollment's first act is this read.
 *
 * @param store {CompanionWriteStore}
 * @returns {CompanionWriteStore}
 */
function refuseMissingGeneration(
  store: CompanionWriteStore
): CompanionWriteStore {
  return {
    async getIdResourceRaw(options) {
      const result = await store.getIdResourceRaw(options)
      if (result === undefined) {
        throw new TransientLoginUnavailableError({
          reason: 'no-companion-generation',
          message:
            'The delegated-clients generation this account points at is ' +
            'not published (collected, or never minted).'
        })
      }
      return result
    },
    putIdResource: store.putIdResource.bind(store)
  }
}

/**
 * The transient composition, from a transient keyring hit to a live session:
 *
 * 1. Precondition refusals (typed, before any request beyond the record
 *    fetch): standing authority, the `delegatedClients` sibling, a promoted
 *    pointer.
 * 2. Verify the account log under the visit's in-memory pins and require the
 *    delegated-clients pointer (the current companion generation).
 * 3. Mint a per-visit key set in memory and enroll it into the generation
 *    through the sibling delegation, signed by the credential's static rung
 *    0 (`enrollTransientClient`; the GC-race re-read is built in). The
 *    generation delegation is taken as embedded -- a generation that would
 *    need one minted refuses instead (its mint takes a durable signer).
 * 4. Read the user key from the credential's STANDING roster wrap: the
 *    roster request signs as `<companionDid>#<vm>` under the generation
 *    delegation, and the unwrap uses the credential's own key-agreement key.
 *    Deliberately no escrow -- a transient client never joins the roster.
 * 5. Assemble the session on the replica-less storage posture
 *    (`initSessionFromSeed` with the transient option: companion signing,
 *    the delegation as `profile.invocationCapability`, no KMS, no second
 *    roster read, no sweeps).
 *
 * @param options {object}
 * @param options.found {TransientKeyringFetchResult}   the transient keyring
 *   hit
 * @param options.type {'passphrase' | 'passkey'}   the method that unlocked
 * @param [options.email] {string}   caller-supplied email, when any
 * @param options.persistence {TransientSessionPersistence}   the visit's
 *   in-memory handle (the same one the record fetch's settle rode)
 * @param [options.credential] {UnlockCredential}   the derived unlock
 *   credential, when the caller holds one -- what arms the torn
 *   companion-native-signup heal (the establishment re-run needs the unlock
 *   identity, not just the record)
 * @param [options.healAttempted] {boolean}   internal: the re-entry marker of
 *   the unpromoted-account heal, so a heal that did not converge refuses
 *   instead of looping
 * @returns {Promise<{ session: Session, userExists: boolean }>}
 */
export async function transientSessionFromKeyringHit({
  found,
  type,
  email,
  persistence,
  credential,
  healAttempted = false
}: {
  found: TransientKeyringFetchResult
  type: 'passphrase' | 'passkey'
  email?: string
  persistence: TransientSessionPersistence
  credential?: UnlockCredential
  healAttempted?: boolean
}): Promise<{ session: Session; userExists: boolean }> {
  const standing = found.standing
  if (!standing?.ladderSeed) {
    throw new TransientLoginUnavailableError({ reason: 'no-standing' })
  }
  const pointer = found.pointer
  if (!pointer || !isWebvhDid(pointer.did)) {
    // The torn companion-native signup's heal: a standing record whose
    // pointer names no did:webvh yet can only be a client-less establishment
    // that died before its re-bind -- the durable flow's records carry no
    // ladder seed until AFTER promotion. Re-running the establishment
    // converges (every stage is an ensure; the published log, if any, is
    // adopted by ladder attribution), and the login then re-enters through
    // the refreshed record. Needs the credential in hand -- the ordinary
    // login path supplies it.
    if (!healAttempted && credential && pointer && standing.ladderSeed) {
      await establishClientlessAccount({
        credential,
        ladderSeed: standing.ladderSeed,
        pointer,
        lowEntropy: type === 'passphrase',
        email: email ?? found.email,
        priorCreatedAt: found.createdAt,
        persistence
      })
      const refreshed = await fetchTransientKeyring({
        credential,
        accountLogPinStore: persistence.logPins
      })
      if (refreshed) {
        return transientSessionFromKeyringHit({
          found: refreshed,
          type,
          email,
          persistence,
          credential,
          healAttempted: true
        })
      }
    }
    throw new TransientLoginUnavailableError({ reason: 'unpromoted-account' })
  }
  const delegatedClients = standing.delegatedClients
  if (!delegatedClients) {
    throw new TransientLoginUnavailableError({ reason: 'no-delegated-clients' })
  }
  const accountDid = pointer.did
  // Aliased for the hoisted `readAccountDocument` closure below, where the
  // guard's narrowing of `pointer` does not reach.
  const accountSpaceId = pointer.spaceId
  const accountHost = pointer.host
  const companionSpaceId = delegatedClientsDelegationSpaceId({
    delegation: delegatedClients
  })
  if (!companionSpaceId) {
    throw new TransientLoginUnavailableError({
      reason: 'no-delegated-clients',
      message:
        "The sibling delegation's target does not address a companion Space."
    })
  }
  const ladderSeed = standing.ladderSeed

  // The account log, verified under the visit's in-memory pins
  // (trust-on-first-use for this visit; nothing durable protects or is
  // protected here). The verified log is retained: the roster read below
  // resolves its controller view from it.
  let verified = await verifyAccountLog({
    did: accountDid,
    spaceId: pointer.spaceId,
    host: pointer.host,
    pinStore: persistence.logPins
  })
  if (!delegatedClientsPointer({ doc: verified.doc })) {
    throw new TransientLoginUnavailableError({
      reason: 'no-companion-generation'
    })
  }

  // The per-visit key set: 32 random bytes, held in memory only. Its did:key
  // is the session identity (and any presentation's holder); only WAS
  // invocations take the companion spelling.
  const seed = crypto.getRandomValues(new Uint8Array(32))
  const { keyAgent } = await agentsFromSeed({ seed })
  const transientKeyMultibase = clientSigningKeyMultibase({ keyAgent })

  // The loud entry before any authority: the enrollment reads the account
  // document (re-verified through the same closure on the GC-race re-read),
  // writes one atomic companion-log entry through the sibling delegation, and
  // hands back the generation document. A first read was just made, so the
  // closure serves it once and re-verifies thereafter.
  let firstDoc: typeof verified.doc | undefined = verified.doc
  async function readAccountDocument() {
    if (firstDoc) {
      const doc = firstDoc
      firstDoc = undefined
      return doc
    }
    verified = await verifyAccountLog({
      did: accountDid,
      spaceId: accountSpaceId,
      host: accountHost,
      pinStore: persistence.logPins
    })
    return verified.doc
  }
  const { companionDid, doc: companionDoc } = await enrollTransientClient({
    readAccountDocument,
    storeForGenerationId: generationId =>
      refuseMissingGeneration(
        delegatedWebvhLogStore({
          host: pointer.host,
          spaceId: companionSpaceId,
          collectionId: generationId,
          delegation: delegatedClients,
          zcapClient: found.standingClient.agents.zcapClient
        })
      ),
    ladderSeed,
    transientKeyMultibase,
    // The delegation is taken as embedded, never minted from here: its mint
    // needs a durable client's signature (or the ladder VM's, on a
    // client-less account). A generation about to receive its first VM with
    // no delegation entry refuses -- crucially BEFORE the entry publishes.
    mintGenerationDelegation: async () => {
      throw new TransientLoginUnavailableError({
        reason: 'no-generation-delegation'
      })
    },
    pinStore: persistence.logPins
  })
  const generationDelegation = embeddedGenerationDelegation({
    doc: companionDoc
  })
  if (!generationDelegation) {
    throw new TransientLoginUnavailableError({
      reason: 'no-generation-delegation'
    })
  }

  // The user key, from the credential's standing roster wrap: the request
  // signs with the companion spelling under the generation delegation, the
  // unwrap uses the credential's own key-agreement key, and no escrow runs
  // (the roster keys enrolled clients and standing credentials only).
  const transientZcapClient = webvhZcapClient({ keyAgent, did: companionDid })
  const rosterStore = userKeyRosterDescriptorStore({
    storageServerUrl: pointer.host,
    zcapClient: transientZcapClient,
    spaceId: pointer.spaceId,
    resolveController: async () =>
      webvhResourceLogController({ did: accountDid, log: verified.log }),
    pinStore: persistence.logPins,
    signer: userKeyRosterLogSigner({ keyAgent }),
    capability: generationDelegation
  })
  const readRoster = () =>
    readUserKeyRoster({
      store: rosterStore,
      clientKeyAgreementKey: found.standingClient.agents.keyAgreementKey
    })
  let rosterRead
  try {
    rosterRead = await readRoster()
  } catch (err) {
    // A client-less establishment torn between its record re-bind and the
    // controller promotion leaves the generation delegation unverifiable:
    // the Space still answers to the bootstrap did:key, so the delegated
    // read above fails. Completing the promotion is the one ladder-derived
    // repair that fixes it; when the attempt itself fails (any other cause
    // -- the account was never client-less, the network flapped), the
    // original error stands unchanged.
    try {
      const bootstrapAgent = await ladderVmAgent({ ladderSeed })
      const bootstrapWas = new WasClient({
        serverUrl: pointer.host,
        zcapClient: didKeyZcapClient({ keyAgent: bootstrapAgent })
      })
      await ensurePromotedSpaceController({
        was: bootstrapWas,
        wasAsClient: bootstrapWas,
        spaceId: pointer.spaceId,
        did: accountDid
      })
    } catch {
      throw err
    }
    rosterRead = await readRoster()
  }
  if (!rosterRead) {
    // The tear-3 heal (promoted account, no roster): the client-less
    // establishment died between the genesis and the roster's epoch[0], so
    // the user key died in memory and nothing anywhere delivers one. The
    // explicit carve-out from the sweeps-skipped rule: mint a fresh user
    // key, land epoch[0] with a ladder-signed entry proof (the ceremony-tail
    // license's first-entry shape), wrapped to the credential's standing
    // key-agreement key, and complete the collection epochs -- every write
    // invoked as the companion VM under the generation delegation, since the
    // promoted Space answers to nothing else this session holds. Nothing
    // encrypted existed yet (the epoch gate in the ceremony guarantees it),
    // so the fresh key orphans nothing.
    const bootstrapAgent = await ladderVmAgent({ ladderSeed })
    const healStore = userKeyRosterDescriptorStore({
      storageServerUrl: pointer.host,
      zcapClient: transientZcapClient,
      spaceId: pointer.spaceId,
      resolveController: async () =>
        webvhResourceLogController({ did: accountDid, log: verified.log }),
      pinStore: persistence.logPins,
      signer: userKeyRosterLogSigner({ keyAgent: bootstrapAgent }),
      capability: generationDelegation
    })
    const freshUserKey = await mintUserKey()
    await ensureUserKeyRoster({
      store: healStore,
      userKey: freshUserKey,
      clientKeyAgreementKey: found.standingClient.agents.keyAgreementKey
    })
    await ensureWalletSpaceEpochs({
      was: new WasClient({
        serverUrl: pointer.host,
        zcapClient: transientZcapClient
      }),
      spaceId: pointer.spaceId,
      userKey: freshUserKey,
      capability: generationDelegation
    })
    rosterRead = await readRoster()
    if (!rosterRead) {
      throw new TransientLoginUnavailableError({ reason: 'no-user-key-roster' })
    }
  }
  await persistence.epochPins.saveFromDescriptor({
    accountDid,
    epochId: rosterRead.latestEpochId,
    descriptor: rosterRead.descriptor
  })

  const { session, userExists } = await initSessionFromSeed({
    seed,
    userKey: rosterRead.userKey,
    accountPointer: pointer,
    email: email ?? found.email,
    persistence,
    transient: {
      companionDid,
      invocationCapability: generationDelegation
    }
  })
  // Stamp what the durable tail stamps, minus what a transient session does
  // not hold (no management zcap was minted).
  session.profile.accountController = found.controller
  session.profile.unlockMethod = {
    type,
    unlockSpaceId: found.unlockSpaceId
  }
  return { session, userExists }
}
