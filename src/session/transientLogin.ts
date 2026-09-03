/**
 * The transient login: the public-terminal composition over the transient
 * unlock-record fetch and the capability-bound replica-less storage variant.
 * Nothing here performs a browser-local write -- the whole flow rides one
 * in-memory persistence strategy (a per-visit writer id, and the pin stores
 * every session keeps in memory) and dies with the tab.
 *
 * Two exports drive it. `routeUnlockLogin` is the post-KDF routing decision
 * both keyring login entry points run: a browser already holding this
 * credential's client-key record proceeds remembered (the mechanical ratchet
 * -- silent until the remember-this-browser UX lands), a browser holding none
 * defaults to the transient session, and an explicit `rememberBrowser` input
 * forces either side (true runs the remembered standing self-enrollment;
 * false on a remembered browser refuses rather than forking the routing
 * decision, per `decisions/0001`). `transientSessionFromKeyringHit` is the
 * composition itself: verify the account log, ensure the credential can reach
 * a live client annex generation with a current generation delegation (the
 * ladder-signed mint-or-renew, a no-op on a healthy account), enroll a
 * per-visit key into that generation through the record's sibling delegation
 * (the loud entry `decisions/0002` requires before any authority is
 * exercised), take the
 * generation delegation as embedded, read the user key from the credential's
 * standing roster wrap (no escrow -- a transient client never joins the
 * roster), and assemble the session on the replica-less remote-direct
 * storage variant, invoking as `<clientAnnexDid>#<vm>` under the delegation.
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
  delegatedWebvhLogStore,
  isWebvhDid,
  verifyAccountLog,
  webvhZcapClient
} from '@interop/wallet-core/webvh'
import {
  clientAnnexDidParts,
  delegatedClientsDelegationSpaceId,
  delegatedClientsPointer,
  embeddedGenerationDelegation,
  enrollTransientClient,
  ensureCredentialClientAnnexGeneration,
  type ClientAnnexGenerationEnsureOutcome,
  type ClientAnnexWriteStore
} from '@interop/wallet-core/clientAnnex'
import {
  readUserKeyRoster,
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner,
  type SealableEncryptionDescriptorStore
} from '@interop/wallet-core/keys'
import {
  didKeyZcapClient,
  type ICapabilityAgent,
  type PublishedWebvhLog
} from '@interop/wallet-core/webvh'
import { ladderVmAgent } from '@interop/wallet-core/clientAnnex'
import { webvhResourceLogController } from '@interop/wallet-core/resourceLog'
import { WasClient } from '@interop/was-client'
import { WAS_SERVER_URL } from '@/app.config'
import { hasClientKeyRecord } from '@/lib/sessionKey'
import { isStorageUnreachable } from '@/lib/storageErrors'
import { createLogger } from '@/lib/log'
import {
  mendCredentialAnchoredAccount,
  passphraseRegistryUpsertHook,
  type CredentialAnchoredMendReport
} from '@/session/credentialAnchoredGenesis'
import {
  inMemorySessionPersistence,
  transientSessionStores,
  type TransientSessionStores
} from '@/session/persistence'
import { initSessionFromSeed } from '@/session/initSession'
import { unlockLogStore } from '@/session/standingUnlock'
import {
  deriveUnlockCredential,
  fetchTransientKeyring,
  type TransientKeyringFetchResult,
  type UnlockCredential
} from '@/session/keyring'
import { refreshTransientManageCapability } from '@/session/unlockMethods'
import { primeVerifiedAccountLog } from '@/session/verifiedLog'
import type { Session } from '@/types/auth'
import type { IZcap } from '@interop/data-integrity-core'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type { WebvhIdStore } from '@interop/wallet-core/webvh'

/**
 * Why a transient login cannot proceed. Typed reasons, no copy: the login
 * page maps each onto its own refusal copy (`loginErrorKey`).
 *
 * - `no-was-server`: transient login presupposes a remote WAS server.
 * - `no-delegated-clients`: a standing record without the annex-Space
 *   sibling delegation (a recovery-code record, or one minted before the
 *   sibling existed).
 * - `unpromoted-account`: the account pointer names no did:webvh.
 * - `no-clientAnnex-generation`: the account document carries no
 *   delegated-clients pointer, or the pointed generation's log is gone (a
 *   GC'd generation nothing re-minted).
 * - `no-generation-delegation`: the generation would need its delegation
 *   minted, which takes a signer this session does not hold.
 * - `no-user-key-roster`: the account has no user key roster to read.
 * - `no-user-key-wrap`: the roster exists (adopted from another runner or a
 *   rotation) but its current epoch carries no wrap for this credential --
 *   a materially different state from an absent roster, and often
 *   attack-relevant, so it is not folded into `no-user-key-roster`.
 * - `roster-mint-refused`: the roster reads as absent, but the mend's mint
 *   preconditions refused to create one, so a fabricated-absent roster
 *   cannot become a single-recipient genesis. This composition's epoch pins
 *   are empty at this point and it says so, so that precondition never fires
 *   here and the refusal means one
 *   of the rest: the account log did not resolve, the verified document
 *   publishes a key-agreement entry this credential does not own (another
 *   standing credential holds the account, the common arm), or an encrypted
 *   collection already carries an epoch or will not prove that it does not.
 *   A retry never helps.
 *
 * The three annex-family reasons stand only where the ladder-signed mend
 * could not run at all -- an account whose document anchors no ladder VM of
 * this credential's, where the record's own sibling and the pointed
 * generation's embedded delegation are all the visit can use and one of
 * them is missing. The refusal then carries wallet-core's own typed refusal as its
 * `cause`.
 */
export type TransientLoginUnavailableReason =
  | 'no-was-server'
  | 'no-delegated-clients'
  | 'unpromoted-account'
  | 'no-clientAnnex-generation'
  | 'no-generation-delegation'
  | 'no-user-key-roster'
  | 'no-user-key-wrap'
  | 'roster-mint-refused'

const log = createLogger('fw:session:transient')

/**
 * A transient login refused before any ceremony byte was written: the
 * credential, the record, or the account is not in the shape the transient
 * flow needs. Carries the typed `reason` above.
 */
export class TransientLoginUnavailableError extends Error {
  reason: TransientLoginUnavailableReason

  constructor({
    reason,
    message,
    cause
  }: {
    reason: TransientLoginUnavailableReason
    message?: string
    cause?: unknown
  }) {
    super(message ?? `A transient login is unavailable here (${reason}).`, {
      ...(cause !== undefined ? { cause } : {})
    })
    this.name = 'TransientLoginUnavailableError'
    this.reason = reason
  }
}

/**
 * A login that asked NOT to be remembered on a browser that already holds
 * this credential's client-key record. Honoring it would mean either a
 * storage-tier fork (`decisions/0001` forbids one) or a destructive wipe, so
 * the routing refuses; the remember-this-browser UX turns this refusal into
 * a loud coerce-and-notify. A PENDING-shape record counts as remembered too
 * (the probe cannot tell the shapes apart, and the remembered route's resume
 * is that record's one mender); the resume's discard outcome deletes a
 * provably worthless pending record, so the NEXT attempt probes record-less
 * and this refusal stops firing.
 */
export class AlreadyRememberedError extends Error {
  constructor() {
    super('This browser already remembers the account for this credential.')
    this.name = 'AlreadyRememberedError'
  }
}

/**
 * The post-KDF routing decision both keyring login entry points run, BEFORE
 * any fetch: a remembered login (today's `fetchKeyring` path) or a transient
 * one. The check is create-nothing -- the credential is derived once
 * (threaded onward so the KDF never re-runs) and the client-key record probe
 * never creates the session database.
 *
 * The decision table: no WAS server is always remembered (transient login is
 * unreachable there); `rememberBrowser: true` is remembered (the programmatic
 * standing self-enrollment entry); a browser holding this credential's
 * client-key record is remembered (the ratchet -- with
 * `rememberBrowser: false` refused as `AlreadyRememberedError` rather than
 * silently coerced); everything else -- a non-remembered browser -- is
 * transient, the default.
 *
 * The CHAPI popup runs this same table, with the Storage Access API handle
 * threaded in as `idb`: a granted handle probes the FIRST-PARTY record, so a
 * remembered browser takes the remembered route, while a denied one (and
 * every engine offering no unpartitioned-IndexedDB request at all) finds no
 * record in the partitioned bucket and routes transient. That is
 * `decisions/0009-popup-denied-storage-access-goes-transient.md`'s uniform
 * fallback, reached by construction rather than by a popup arm of its own.
 *
 * @param options {object}
 * @param [options.secret] {string | Uint8Array}   the unlock secret, when no
 *   derived credential is supplied
 * @param options.kdf {UnlockKdf}   the unlock method's KDF parameters
 * @param [options.credential] {UnlockCredential}   an already-derived
 *   credential for the same secret
 * @param [options.idb] {IDBFactory}   first-party IndexedDB for the probe
 * @param [options.rememberBrowser] {boolean}   forces the remembered or
 *   transient route; absent means route on the record probe
 * @returns {Promise<object>}   `{ login: 'remembered', credential? }` or
 *   `{ login: 'transient', credential, persistence }` -- the transient arm
 *   carries the visit's in-memory store family so every later stage (the
 *   record fetch's account-log pins included) shares it; the composition
 *   folds the annex identity over these stores into the session's
 *   persistence strategy
 */
export async function routeUnlockLogin({
  secret,
  kdf,
  credential,
  idb,
  rememberBrowser
}: {
  secret?: string | Uint8Array
  kdf: UnlockKdf
  credential?: UnlockCredential
  idb?: IDBFactory
  rememberBrowser?: boolean
}): Promise<
  | { login: 'remembered'; credential?: UnlockCredential }
  | {
      login: 'transient'
      credential: UnlockCredential
      persistence: TransientSessionStores
    }
> {
  if (!WAS_SERVER_URL) {
    if (rememberBrowser === false) {
      throw new TransientLoginUnavailableError({ reason: 'no-was-server' })
    }
    return { login: 'remembered', ...(credential ? { credential } : {}) }
  }
  if (rememberBrowser === true) {
    return { login: 'remembered', ...(credential ? { credential } : {}) }
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
    return { login: 'remembered', credential: derived }
  }
  return {
    login: 'transient',
    credential: derived,
    persistence: transientSessionStores()
  }
}

/**
 * Wraps an annex write store so a generation whose log is gone surfaces as
 * the typed refusal instead of a plain "did.jsonl is missing" error.
 *
 * Without a threaded head the read is the enrollment's first act, so the
 * refusal lands before anything is written. On the threaded path the first
 * act is the compare-and-swap PUT instead: a collected generation fails it
 * (412 to a conflict), and the retry's fresh read under the pin is what
 * surfaces the refusal. A host serving no ETag degrades to the unconditional
 * PUT `putLogResource` already documents, which no lost race can refuse.
 *
 * @param store {ClientAnnexWriteStore}
 * @returns {ClientAnnexWriteStore}
 */
function refuseMissingGeneration(
  store: ClientAnnexWriteStore
): ClientAnnexWriteStore {
  return {
    async getIdResourceRaw(options) {
      const result = await store.getIdResourceRaw(options)
      if (result === undefined) {
        throw new TransientLoginUnavailableError({
          reason: 'no-clientAnnex-generation',
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
 * The composition's client-annex generation-readiness stage: one converging
 * ensure over the five durable states that make the annex unreachable from
 * a credential-only visit (no `#DelegatedClients` pointer, a collected or
 * never-minted generation, a stale generation delegation, a missing or
 * misaimed sibling delegation, and a bridge delegation that is expired,
 * inside its renewal window, or signed by a key the account document no
 * longer lists under `capabilityDelegation`). It is run on every visit, not
 * only a broken one: on a healthy account it is a pure no-op report, and running it is
 * what gives the renew-precedes-mint behavior the grant path depends on.
 *
 * Everything it writes is ladder-signed, so an account whose document does
 * not anchor this credential's ladder VM (one with enrolled clients,
 * or one anchored on another credential's ladder) is refused by wallet-core
 * before anything is written. That refusal is resolved as a value rather
 * than thrown: such an account may still be perfectly reachable through the
 * record's own sibling delegation and the pointed generation's embedded
 * delegation -- today's path -- and the caller falls back to it, refusing
 * with its own typed reason only when that path cannot proceed either.
 *
 * @param options {object}
 * @param options.found {TransientKeyringFetchResult}   the keyring hit
 * @param options.standing {object}   its standing members, with the ladder
 *   seed the caller already required
 * @param options.pointer {AccountPointer}   the account pointer
 * @param options.account {object}   the verified account log view
 * @param options.persistence {TransientSessionStores}   the visit's stores
 * @returns {Promise<object>}   `{ outcome }` on a completed ensure, or
 *   `{ unavailable }` carrying wallet-core's typed refusal
 */
async function ensureClientAnnexGenerationReady({
  found,
  standing,
  pointer,
  account,
  persistence
}: {
  found: TransientKeyringFetchResult
  standing: {
    delegation: IZcap
    delegatedClients?: IZcap
    ladderSeed: Uint8Array
  }
  pointer: AccountPointer
  account: Parameters<
    typeof ensureCredentialClientAnnexGeneration
  >[0]['account']
  persistence: TransientSessionStores
}): Promise<{
  outcome?: ClientAnnexGenerationEnsureOutcome
  unavailable?: unknown
}> {
  const zcapClient = found.standingClient.agents.zcapClient
  try {
    const outcome = await ensureCredentialClientAnnexGeneration({
      wasServerUrl: pointer.host,
      spaceId: pointer.spaceId,
      account,
      ladderSeed: standing.ladderSeed,
      standingClient: { did: found.standingClient.clientDid, zcapClient },
      bootstrapWasFor: ({ keyAgent }) =>
        new WasClient({
          serverUrl: pointer.host,
          zcapClient: didKeyZcapClient({ keyAgent })
        }),
      // The bridge the record carries today. The ensure renews it in place
      // when it has expired, entered its renewal window, or lost its
      // signer, and hands the usable one back on the outcome.
      delegation: standing.delegation,
      // The account log through whichever bridge delegation is usable:
      // pointer entries publish with `logOnly: true`, which is all a bridge
      // can do.
      idStoreFor: ({ delegation }) =>
        unlockLogStore({
          pointer,
          delegation,
          zcapClient
        }) as WebvhIdStore,
      onRebindRecord: async ({ delegation, delegatedClients }) => {
        const rebind = found.rebindStandingRecord
        if (!rebind) {
          // Invariant, not a user state: every standing hit carries the
          // re-bind closure, and a fresh bridge or sibling nothing re-seals
          // into the record would strand the credential that just minted it.
          throw new Error(
            'Invariant violated: the transient keyring hit carries no record ' +
              're-bind closure, so a fresh sibling delegation cannot be sealed.'
          )
        }
        await rebind({ delegation, delegatedClients })
      },
      ...(standing.delegatedClients
        ? { delegatedClients: standing.delegatedClients }
        : {}),
      pinStore: persistence.logPins
    })
    return { outcome }
  } catch (err) {
    if ((err as Error).name === 'ClientAnnexGenerationUnavailableError') {
      return { unavailable: err }
    }
    throw err
  }
}

/**
 * The transient composition, from a transient keyring hit to a live session:
 *
 * 1. Precondition refusals (typed, before any request beyond the record
 *    fetch): standing authority and a promoted pointer.
 * 2. Verify the account log under the visit's in-memory pins, then run the
 *    client-annex generation-readiness stage
 *    (`ensureClientAnnexGenerationReady`): the
 *    ladder-signed ensure that mints or renews what the visit needs (the
 *    record's own bridge delegation included, re-sealed into the record),
 *    with
 *    the pointed-generation-and-record-sibling fallback behind it and the
 *    typed refusals behind that.
 * 3. Mint a per-visit key set in memory and enroll it into the generation
 *    through the sibling delegation, signed by the credential's static rung
 *    0 (`enrollTransientClient`; the GC-race re-read is built in). The
 *    generation delegation is taken as embedded -- the readiness stage above
 *    is what installs and renews it.
 * 4. Read the user key from the credential's STANDING roster wrap: the
 *    roster request signs as `<clientAnnexDid>#<vm>` under the generation
 *    delegation, and the unwrap uses the credential's own key-agreement key.
 *    Deliberately no escrow -- a transient client never joins the roster.
 * 5. Assemble the session on the replica-less storage variant: the annex
 *    identity and the generation delegation are folded over the visit's
 *    stores into the in-memory persistence strategy
 *    (`inMemorySessionPersistence`), and that one strategy tells
 *    `initSessionFromSeed` everything -- annex signing, the delegation as
 *    `profile.invocationCapability`, no KMS, no second roster read, no
 *    sweeps.
 *
 * @param options {object}
 * @param options.found {TransientKeyringFetchResult}   the transient keyring
 *   hit
 * @param options.type {'passphrase' | 'passkey'}   the method that unlocked
 * @param [options.email] {string}   caller-supplied email, when any
 * @param options.persistence {TransientSessionStores}   the visit's
 *   in-memory store family (the same one the record fetch's settle rode)
 * @param [options.credential] {UnlockCredential}   the derived unlock
 *   credential, when the caller holds one -- what arms the torn
 *   credential-anchored-signup heal (the establishment re-run needs the unlock
 *   identity, not just the record)
 * @param [options.popup] {boolean}   this visit runs in the CHAPI popup's
 *   partitioned iframe, which skips the management-zcap registry refresh
 *   below, the guard the login-time registry passes carry
 * @param [options.healAttempted] {boolean}   internal: the re-entry marker of
 *   the unpromoted-account heal, so a heal that did not converge refuses
 *   instead of looping
 * @param [options.repairShaped] {boolean}   internal: carried across the
 *   heal's re-entry when the mend reported `reenterRepairShaped`. The
 *   re-bound record left the registry arm unfired (its root window is
 *   permanently closed), so the re-entry's mend must run the completion arms
 *   under the visit's post-promotion authority even with no tear of its own
 * @param [options.accountLog] {PublishedWebvhLog}   an account-log head this
 *   same visit already read or published (a signup's establishment, entering
 *   the account it just established), reused for the first-contact
 *   verification below in place of the fetch. Only ever a head from within
 *   this visit: the pin check runs on it exactly as on a served one
 * @returns {Promise<{ session: Session, userExists: boolean }>}
 */
export async function transientSessionFromKeyringHit({
  found,
  type,
  email,
  persistence,
  credential,
  popup = false,
  healAttempted = false,
  repairShaped = false,
  accountLog
}: {
  found: TransientKeyringFetchResult
  type: 'passphrase' | 'passkey'
  email?: string
  persistence: TransientSessionStores
  credential?: UnlockCredential
  popup?: boolean
  healAttempted?: boolean
  repairShaped?: boolean
  accountLog?: PublishedWebvhLog
}): Promise<{ session: Session; userExists: boolean }> {
  const standing = found.standing
  if (!standing?.ladderSeed) {
    // Invariant, not a user state: a standing record is the only record a
    // WAS signup produces (the standing layout is written before the Space
    // exists), so a plain pointer record here is a bug in a producer, not
    // a refusal with copy of its own.
    throw new Error(
      'Invariant violated: the unlock record carries no standing authority ' +
        '(a standing record is the only record a WAS signup produces).'
    )
  }
  const pointer = found.pointer
  if (!pointer || !isWebvhDid(pointer.did)) {
    // The torn credential-anchored signup's heal: a standing record whose
    // pointer names no did:webvh yet is the mend ceremony's establishment
    // arm (a re-run of the whole establishment, or a record re-bind when
    // the log already resolves), and the login then re-enters through the
    // refreshed record. Needs the credential in hand -- the ordinary login
    // path supplies it. A report whose arm did not converge (an
    // establishment throw rides the report, it does not escape raw) falls
    // through to the typed refusal, with the arm's error as its cause; the
    // single-shot re-entry marker stays here, on the caller's glue.
    if (!healAttempted && credential && pointer && standing.ladderSeed) {
      const report = await mendCredentialAnchoredAccount({
        credential,
        ladderSeed: standing.ladderSeed,
        pointer,
        controller: found.controller,
        lowEntropy: type === 'passphrase',
        email: email ?? found.email,
        priorCreatedAt: found.createdAt,
        persistence,
        // The visit's epoch pins are empty at this point, so this caller
        // holds no roster-epoch pin: it says so rather than leaving the mint
        // precondition to a dropped option.
        hasRosterEpochPin: async () => false,
        ...(standing.delegatedClients
          ? { delegatedClients: standing.delegatedClients }
          : {}),
        ...(type === 'passphrase'
          ? {
              beforePromotion: passphraseRegistryUpsertHook({
                spaceId: pointer.spaceId
              })
            }
          : {})
      })
      if (report.reenter) {
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
            popup,
            healAttempted: true,
            repairShaped: report.reenterRepairShaped === true
          })
        }
      }
      // A transport-class failure is not an account state: it rethrows
      // unchanged, so a flap surfaces as the storage-unreachable copy rather
      // than as a permanent-sounding refusal a retry is supposed to fix.
      const establishmentError = report.establishment?.error
      if (
        establishmentError !== undefined &&
        isStorageUnreachable(establishmentError)
      ) {
        throw establishmentError
      }
      throw new TransientLoginUnavailableError({
        reason: 'unpromoted-account',
        ...(establishmentError !== undefined
          ? { cause: establishmentError }
          : {})
      })
    }
    throw new TransientLoginUnavailableError({ reason: 'unpromoted-account' })
  }
  const accountDid = pointer.did
  // Aliased for the hoisted `readAccountDocument` closure below, where the
  // guard's narrowing of `pointer` does not reach.
  const accountSpaceId = pointer.spaceId
  const accountHost = pointer.host
  const ladderSeed = standing.ladderSeed
  const accountPointer = pointer

  // The account log, verified under the visit's in-memory pins
  // (trust-on-first-use for this visit; the pin store dies with the tab, as
  // it does on every session). The verified log is retained: the roster read
  // below resolves its controller view from it.
  //
  // A caller entering the account it just established hands over the head
  // that run ended standing on, and this first contact reads it instead of
  // fetching `did.jsonl` again. It is taken only when it names the very DID
  // the record points at (the did:webvh embeds the Space id, so an equal DID
  // is the same log slot); anything else falls back to the fetch. The pin
  // check-and-advance runs on the supplied head either way.
  const seededLog =
    accountLog !== undefined && accountLog.did === accountDid
      ? accountLog
      : undefined
  let verified = await verifyAccountLog({
    did: accountDid,
    spaceId: pointer.spaceId,
    host: pointer.host,
    pinStore: persistence.logPins,
    ...(seededLog !== undefined ? { published: seededLog } : {})
  })

  // The client-annex generation readiness: the ladder-signed ensure first (a
  // no-op on a healthy ladder-anchored account, the mend otherwise), then the
  // fallback for an account whose document anchors no ladder VM of this
  // credential's, where nothing ladder-signed could verify and the record's
  // own sibling plus the pointed generation's embedded delegation are all
  // the visit can use.
  const readiness = await ensureClientAnnexGenerationReady({
    found,
    standing: { ...standing, ladderSeed },
    pointer: accountPointer,
    account: { did: accountDid, doc: verified.doc, log: verified.log },
    persistence
  })
  const healedGenerationDelegation = readiness.outcome?.generationDelegation
  // The bridge this visit may still write the log through: the renewed one
  // when the readiness stage re-minted it, the record's own otherwise.
  const usableBridge = readiness.outcome?.delegation ?? standing.delegation
  if (readiness.outcome?.bridgeResealError !== undefined) {
    // A bridge-only re-seal failure denies this visit nothing: the fresh
    // bridge is minted offline and already served the pointer writes above.
    log.warn(
      'Could not re-seal the renewed bridge delegation into the unlock ' +
        'record; the next visit retries',
      { err: readiness.outcome.bridgeResealError }
    )
  }
  let siblingDelegation: IZcap
  let annexSpaceId: string
  if (readiness.outcome) {
    siblingDelegation = readiness.outcome.delegatedClients
    annexSpaceId = clientAnnexDidParts({
      did: readiness.outcome.clientAnnexDid
    }).spaceId
    if (readiness.outcome.generationMinted || readiness.outcome.spaceMinted) {
      // The pointer moved: the pre-mend document names a generation that is
      // no longer the live one, so the enrollment must read the fresh log.
      verified = await verifyAccountLog({
        did: accountDid,
        spaceId: accountSpaceId,
        host: accountHost,
        pinStore: persistence.logPins
      })
    }
  } else {
    const recordSibling = standing.delegatedClients
    if (!recordSibling) {
      throw new TransientLoginUnavailableError({
        reason: 'no-delegated-clients',
        cause: readiness.unavailable
      })
    }
    const siblingSpaceId = delegatedClientsDelegationSpaceId({
      delegation: recordSibling
    })
    if (!siblingSpaceId) {
      throw new TransientLoginUnavailableError({
        reason: 'no-delegated-clients',
        message:
          "The sibling delegation's target does not address an annex Space.",
        cause: readiness.unavailable
      })
    }
    if (!delegatedClientsPointer({ doc: verified.doc })) {
      throw new TransientLoginUnavailableError({
        reason: 'no-clientAnnex-generation',
        cause: readiness.unavailable
      })
    }
    siblingDelegation = recordSibling
    annexSpaceId = siblingSpaceId
  }

  // The per-visit key set: 32 random bytes, held in memory only. Its did:key
  // is the session identity (and any presentation's holder); only WAS
  // invocations take the annex spelling.
  const seed = crypto.getRandomValues(new Uint8Array(32))
  const { keyAgent } = await agentsFromSeed({ seed })
  const transientKeyMultibase = clientSigningKeyMultibase({ keyAgent })

  // The loud entry before any authority: the enrollment reads the account
  // document (re-verified through the same closure on the GC-race re-read),
  // writes one atomic annex-log entry through the sibling delegation, and
  // hands back the generation document. A first read was just made, so the
  // closure serves it once and re-verifies thereafter.
  //
  // The annex log is threaded the same way: the enrollment's FIRST attempt
  // rides the verified generation head the readiness stage stood on (present
  // only when that stage published nothing to the log), so a healthy visit
  // resolves the pointed generation's log once in all. A lost
  // compare-and-swap re-reads the head fresh under the same pin, exactly as
  // before, and a stage that minted or renewed hands nothing on.
  let firstDoc: typeof verified.doc | undefined = verified.doc
  async function readAccountDocument() {
    if (firstDoc) {
      const doc = firstDoc
      firstDoc = undefined
      return doc
    }
    // A full fetch, and not a conditional one: the server reads
    // `If-None-Match` on `did.jsonl` as a write precondition only, so a
    // conditional GET would buy no 304 and the re-read exists precisely to
    // see a head this visit has not seen.
    verified = await verifyAccountLog({
      did: accountDid,
      spaceId: accountSpaceId,
      host: accountHost,
      pinStore: persistence.logPins
    })
    return verified.doc
  }
  const { clientAnnexDid, doc: clientAnnexDoc } = await enrollTransientClient({
    readAccountDocument,
    storeForGenerationId: generationId =>
      refuseMissingGeneration(
        delegatedWebvhLogStore({
          host: pointer.host,
          spaceId: annexSpaceId,
          collectionId: generationId,
          delegation: siblingDelegation,
          zcapClient: found.standingClient.agents.zcapClient
        })
      ),
    ladderSeed,
    transientKeyMultibase,
    // The delegation is taken as embedded, never minted from here: the
    // readiness stage above installs and renews it (ladder-signed) before
    // the enrollment runs, and a generation about to receive its first VM
    // with no delegation entry refuses -- crucially BEFORE the entry
    // publishes.
    mintGenerationDelegation: async () => {
      throw new TransientLoginUnavailableError({
        reason: 'no-generation-delegation',
        ...(readiness.unavailable !== undefined
          ? { cause: readiness.unavailable }
          : {})
      })
    },
    pinStore: persistence.logPins,
    ...(readiness.outcome?.generationLog !== undefined
      ? { published: readiness.outcome.generationLog }
      : {})
  })
  const generationDelegation =
    embeddedGenerationDelegation({ doc: clientAnnexDoc }) ??
    healedGenerationDelegation
  if (!generationDelegation) {
    throw new TransientLoginUnavailableError({
      reason: 'no-generation-delegation',
      ...(readiness.unavailable !== undefined
        ? { cause: readiness.unavailable }
        : {})
    })
  }

  // The user key, from the credential's standing roster wrap: the request
  // signs with the annex spelling under the generation delegation, the
  // unwrap uses the credential's own key-agreement key, and no escrow runs
  // (the roster keys enrolled clients and standing credentials only).
  const transientZcapClient = webvhZcapClient({ keyAgent, did: clientAnnexDid })
  // The roster store this visit reads and (in the heal below) appends
  // through: always invoked as the annex VM under the generation
  // delegation, anchored at the log this composition already verified, and
  // signed by whichever agent the caller's stage is licensed to sign with.
  const rosterStoreSignedBy = (
    signingAgent: ICapabilityAgent
  ): SealableEncryptionDescriptorStore =>
    userKeyRosterDescriptorStore({
      storageServerUrl: pointer.host,
      zcapClient: transientZcapClient,
      spaceId: pointer.spaceId,
      resolveController: async () =>
        webvhResourceLogController({ did: accountDid, log: verified.log }),
      pinStore: persistence.logPins,
      signer: userKeyRosterLogSigner({ keyAgent: signingAgent }),
      capability: generationDelegation
    })
  const rosterStore = rosterStoreSignedBy(keyAgent)
  const readRoster = () =>
    readUserKeyRoster({
      store: rosterStore,
      clientKeyAgreementKey: found.standingClient.agents.keyAgreementKey
    })
  // A roster read comes back null only for an ABSENT roster head; a roster
  // whose current epoch carries no wrap for this credential THROWS instead.
  // That state is this composition's own refusal (no mend arm can mend it,
  // and the raw throw would otherwise reach the login page's
  // connect-this-browser card, which a transient refusal must never open),
  // so it is mapped here rather than routed into the mend. Matched by name:
  // the refusal is raised inside an app-injected seam, so the raising copy
  // of wallet-core can differ from the one this module imports.
  function refuseUnwrapFailure(err: unknown): void {
    if (
      (err as { name?: unknown } | null)?.name === 'UserKeyRosterUnwrapError'
    ) {
      throw new TransientLoginUnavailableError({
        reason: 'no-user-key-wrap',
        cause: err
      })
    }
  }
  // The mend ceremony's post-promotion arms (the promotion completion, the
  // roster-and-epochs completion, the registry re-fire), invoked with the
  // visit's live authority: writes sign as the ladder VM through the
  // delegated roster store, requests ride the generation delegation, and
  // the registry hook (a passphrase credential's; a passkey entry stays the
  // add-a-passkey ceremony's own write) rides the same delegation.
  const mendPromotedArms = async (
    unlockCredential: UnlockCredential,
    extra: {
      delegatedRead?: { error: unknown; retry: () => Promise<void> }
      repairShaped?: boolean
    }
  ): Promise<CredentialAnchoredMendReport> => {
    const report = await mendCredentialAnchoredAccount({
      credential: unlockCredential,
      ladderSeed,
      pointer: accountPointer,
      controller: found.controller,
      lowEntropy: type === 'passphrase',
      email: email ?? found.email,
      priorCreatedAt: found.createdAt,
      persistence,
      // The visit's epoch pins are empty, so this caller holds no
      // roster-epoch pin and says so explicitly.
      hasRosterEpochPin: async () => false,
      ...(standing.delegatedClients
        ? { delegatedClients: standing.delegatedClients }
        : {}),
      invocation: {
        was: new WasClient({
          serverUrl: accountHost,
          zcapClient: transientZcapClient
        }),
        zcapClient: transientZcapClient,
        capability: generationDelegation
      },
      rosterStore: rosterStoreSignedBy(await ladderVmAgent({ ladderSeed })),
      registry: {
        unlockSpaceId: found.unlockSpaceId,
        delegation: usableBridge,
        delegatedClients: siblingDelegation,
        ...(found.unlockKeyAgreementKeyId
          ? { unlockKeyAgreementKeyId: found.unlockKeyAgreementKeyId }
          : {}),
        ...(found.unlockKeyAgreementKeyMultibase
          ? {
              unlockKeyAgreementKeyMultibase:
                found.unlockKeyAgreementKeyMultibase
            }
          : {})
      },
      ...(type === 'passphrase'
        ? {
            beforePromotion: passphraseRegistryUpsertHook({
              spaceId: accountSpaceId,
              capability: generationDelegation
            })
          }
        : {}),
      ...extra
    })
    const epochsFailed = report.rosterEpochs?.epochsFailed
    if (epochsFailed && epochsFailed.length > 0) {
      // A partial collection fan-out. On a client-less account no login
      // sweep ever revisits a stranded collection, so this line is the only
      // trace that one stayed on an earlier key.
      log.warn('The mend left collection epochs incomplete', {
        collectionIds: epochsFailed.map(({ collectionId }) => collectionId)
      })
    }
    return report
  }
  let rosterRead
  let mendReport: CredentialAnchoredMendReport | undefined
  try {
    rosterRead = await readRoster()
  } catch (err) {
    // A credential-anchored establishment torn between its record re-bind
    // and the controller promotion leaves the generation delegation
    // unverifiable: the Space still answers to the bootstrap did:key, so
    // the delegated read above fails. The mend ceremony's promotion arm
    // completes the promotion and retries the read once; when the
    // promotion or the retried read still fails (any other cause -- the
    // account was never ladder-anchored, the network flapped), the
    // original error is rethrown unchanged. With no credential in hand the
    // arm cannot run at all, and the original error stands.
    refuseUnwrapFailure(err)
    if (!credential) {
      throw err
    }
    mendReport = await mendPromotedArms(credential, {
      delegatedRead: {
        error: err,
        retry: async () => {
          rosterRead = await readRoster()
        }
      }
    })
  }
  if (!rosterRead) {
    // The promoted-account-without-epochs tear (the establishment died
    // between the genesis and the roster's epoch[0], so the user key died
    // in memory): the mend ceremony's roster-and-epochs arm mints a fresh
    // user key behind its preconditions, lands epoch[0] ladder-signed and
    // wrapped to the credential's standing key-agreement key, and installs
    // the collection epochs under the key the roster DELIVERS after the
    // ensure -- the shared mint policy, one home. A roster the promotion
    // arm's invocation already completed skips the second call.
    if (!mendReport?.rosterEpochs) {
      if (!credential) {
        throw new TransientLoginUnavailableError({
          reason: 'no-user-key-roster'
        })
      }
      mendReport = await mendPromotedArms(credential, {})
    }
    const arm = mendReport.rosterEpochs
    if (arm?.outcome === 'no-wrap') {
      // The roster was adopted (another run or a rotation landed first) but
      // its current epoch carries no wrap for this credential: its own
      // refusal, distinct from an absent roster -- a retry cannot help, a
      // re-escrow from another client or a rotation can.
      throw new TransientLoginUnavailableError({
        reason: 'no-user-key-wrap',
        ...(arm.error !== undefined ? { cause: arm.error } : {})
      })
    }
    if (arm?.outcome === 'mint-refused') {
      // The mint preconditions refused. The roster-epoch-pin precondition
      // cannot fire here (this caller passes `hasRosterEpochPin: false`), so
      // this is an unresolvable account log, a key-agreement entry in the
      // document this credential does not own, or a collection already
      // carrying an epoch: each says the account is live beside a roster
      // that reads empty. Minting over any of them would orphan that
      // account's ciphertext, so the refusal is its own -- a retry re-runs
      // the same refused preconditions.
      throw new TransientLoginUnavailableError({
        reason: 'roster-mint-refused',
        ...(arm.error !== undefined ? { cause: arm.error } : {})
      })
    }
    try {
      rosterRead = await readRoster()
    } catch (err) {
      refuseUnwrapFailure(err)
      throw err
    }
    if (!rosterRead) {
      throw new TransientLoginUnavailableError({
        reason: 'no-user-key-roster',
        ...(arm?.error !== undefined ? { cause: arm.error } : {})
      })
    }
  } else if (repairShaped && credential && !mendReport) {
    // The heal's re-entry with `reenterRepairShaped`: the record-downgrade
    // re-bind rewrote the record but left the registry arm unfired (the
    // root window a live establishment writes in is permanently closed), so
    // the completion arms run here under the visit's post-promotion
    // authority even though nothing tore this time. Best-effort: the
    // session is already assemblable, so a failure is logged rather than
    // refused.
    try {
      mendReport = await mendPromotedArms(credential, { repairShaped: true })
    } catch (err) {
      log.warn('The repair-shaped mend re-entry did not complete', { err })
    }
  }
  await persistence.epochPins.saveFromDescriptor({
    accountDid,
    epochId: rosterRead.latestEpochId,
    descriptor: rosterRead.descriptor
  })

  // The session's persistence strategy: the annex identity folded over the
  // visit's stores, so the storage tier and the annex signing arrive as one
  // typed declaration.
  const sessionPersistence = inMemorySessionPersistence({
    stores: persistence,
    clientAnnex: {
      clientAnnexDid,
      invocationCapability: generationDelegation
    }
  })
  const { session, userExists } = await initSessionFromSeed({
    seed,
    userKey: rosterRead.userKey,
    accountPointer: pointer,
    email: email ?? found.email,
    persistence: sessionPersistence
  })
  // Seed the session-lifetime memo with the latest head this composition
  // itself verified (the enrollment's re-read when one happened, the
  // readiness stage's re-verification otherwise, else the first contact
  // above), so the first surface the dashboard mounts reads the document
  // this visit already holds instead of fetching and re-verifying the same
  // log. Skipped when a mend arm ran: its arms read the log for themselves
  // under the same pin and hand nothing back, so `verified` may then sit
  // behind the pin the mend advanced. Every ceremony that extends the
  // account log drops the memo, so nothing this session can run reads it
  // stale.
  if (mendReport === undefined) {
    primeVerifiedAccountLog({
      profile: session.profile,
      pointer: { did: accountDid, spaceId: accountSpaceId, host: accountHost },
      verified
    })
  }
  // Stamp what the remembered tail stamps, minus what a transient session
  // does not hold. The management zcap IS stamped: this visit minted one, and
  // the refresh below is the only thing keeping it alive on an account that
  // never remembers a browser. The standing members ride
  // along: the ladder seed is what lets a mid-session stage sign as the
  // ladder VM (the App Connect grant path's generation-delegation renewal),
  // and the sibling delegation beside it is the authority that renewal's
  // annex write invokes under.
  session.profile.accountController = found.controller
  session.profile.unlockMethod = {
    type,
    unlockSpaceId: found.unlockSpaceId,
    ...(found.manageCapability
      ? { manageCapability: found.manageCapability }
      : {})
  }
  session.profile.ladderSeed = ladderSeed
  session.profile.standingUnlock = {
    delegation: usableBridge,
    delegatedClients: siblingDelegation,
    standingClient: found.standingClient,
    unlockSpaceId: found.unlockSpaceId,
    ...(found.rebindStandingRecord
      ? { rebindRecord: found.rebindStandingRecord }
      : {})
  }
  // The one registry write an ordinary transient login makes: the acting
  // credential's own management zcap, refreshed when the stored copy is
  // absent, expiring, retargeted, or narrower than the fresh mint. Nothing
  // else on the registry is touched, nothing is created, and a failed read
  // warns and skips rather than failing the login.
  //
  // Deliberately not awaited: it is a once-a-year write behind a registry
  // GET, and the session is complete without it, so no login (and no CHAPI
  // popup visit) waits on that round trip. The helper holds its own
  // catch-and-warn, so the floating promise can never reject. A popup skips
  // it outright, the guard the other registry passes carry.
  if (found.manageCapability && !popup) {
    void refreshTransientManageCapability({
      zcapClient: transientZcapClient,
      spaceId: accountSpaceId,
      userKey: rosterRead.userKey,
      capability: generationDelegation,
      unlockSpaceId: found.unlockSpaceId,
      manageCapability: found.manageCapability,
      ...(found.standingClient?.keyAgreementKeyMultibase
        ? {
            keyAgreementKeyMultibase:
              found.standingClient.keyAgreementKeyMultibase
          }
        : {})
    })
  }
  return { session, userExists }
}
