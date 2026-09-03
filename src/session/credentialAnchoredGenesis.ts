/**
 * Freewallet's binding onto the credential-anchored establishment ceremony.
 * The stage order and its load-bearing ordering rules (the transposed
 * persist-before-publish rule, the fatal-before-the-DID genesis landing
 * check, the annex fold's sub-step order, the re-bind-before-promotion
 * rule) are canonical in wallet-core's orchestrator
 * (`establishCredentialAnchoredAccount` in
 * `@interop/wallet-core/clientAnnex`) and its ceremony doc; this module
 * supplies only what is app-specific:
 *
 * - the unlock-record codec (`bindRecord` wraps
 *   `bindCredentialAnchoredUnlockSecret`, carrying the credential and the
 *   email);
 * - the storage wiring under the bootstrap identity (the `WasClient`, the
 *   account `id`-collection store, the ladder-signed roster store builder);
 * - the KMS-authentication thunk (`provideKmsAuthentication`, best-effort
 *   with a local timeout) and the keystore-controller promotion closure it
 *   arms;
 * - the caller's pre-promotion tail (`beforePromotion`, the signup's
 *   registry write), wrapped only to close its own timing span;
 * - logging: the ceremony's collected best-effort failures are warned here,
 *   and its stage timings are collected on one timer. wallet-core's
 *   `onStage` notifier closes the span of every stage it runs, the
 *   KMS-authentication join included; the two stages whose body is a closure
 *   supplied here and whose span the delta would misname -- the pre-promotion
 *   registry write, the keystore promotion -- close their own, and the
 *   concurrent KMS thunk reports a measured span of its own instead of a
 *   delta.
 *
 * One function serves the fresh signup and the login-time re-run alike --
 * every stage is an ensure, so a signup torn at any point converges by
 * running the whole thing again. The sibling binding
 * (`mendCredentialAnchoredAccount` below) wraps wallet-core's mend entry
 * point -- the converging ensure over the tear states the establishment can
 * leave -- with the same hook set, so any door into a torn account runs the
 * shared arms instead of hand-rolling its own heal.
 */
import { WasClient } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  establishCredentialAnchoredAccount as runEstablishment,
  ladderVmAgent,
  mendCredentialAnchoredAccount as runMend,
  KMS_AUTHENTICATION_STAGE,
  type CredentialAnchoredBindRecordHook,
  type CredentialAnchoredEstablishment,
  type CredentialAnchoredMendReport,
  type CredentialAnchoredRegistryContext
} from '@interop/wallet-core/clientAnnex'
import {
  didKeyZcapClient,
  wasWebvhIdStore,
  type KmsAuthenticationBinding
} from '@interop/wallet-core/webvh'
import { plaintextCollection } from '@interop/wallet-core/space'
import type { UserKey } from '@interop/wallet-core/keys'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type { DIDLog } from '@interop/did-method-webvh'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import type { KeystoreAgent } from '@interop/webkms-client'
import type { StageNotifier } from '@interop/wallet-core'
import {
  DID_KEYS_RESOURCE,
  ENCRYPTED_STANDARD_COLLECTIONS,
  KEY_MAP_COLLECTION,
  KMS_SERVER_URL,
  WAS_SERVER_URL
} from '@/app.config'
import { didWebFromSpace } from '@/lib/didWeb'
import {
  ensureKeystore,
  ensureKmsAuthentication,
  findKeystoreAgent,
  promoteKeystoreController
} from '@/lib/kms'
import {
  bindCredentialAnchoredUnlockSecret,
  type UnlockCredential
} from '@/session/keyring'
import { accountRosterStore } from '@/session/rosterStore'
import {
  emptyUnlockMethodsRegistry,
  updateUnlockMethodsWithClient,
  upsertPassphraseUnlockMethod,
  type PassphraseUnlockMethod
} from '@/session/unlockMethods'
import { createLogger, stageMarker, stageSpan, stageTimer } from '@/lib/log'

export type { CredentialAnchoredEstablishment, CredentialAnchoredMendReport }

const log = createLogger('fw:session:genesis')

/**
 * The bound on the KMS half of the stage (keystore ensure, key mint,
 * keys.json write): a hung -- not throwing -- KMS sits between Space
 * creation and the genesis entry, so it must not wedge the signup. On
 * timeout the thunk throws and the genesis ceremony collects it as its
 * non-fatal `kmsAuthentication` stage.
 *
 * The budget starts when the Space is ready rather than covering the wait
 * for it: the stage overlaps Space provisioning, and slow provisioning would
 * otherwise eat the whole budget. It still covers the keystore lookup, the
 * key mint, and the keys.json write, so a timeout can still win with that
 * write in flight, leaving a map the genesis entry never publishes.
 */
const KMS_AUTHENTICATION_TIMEOUT_MS = 30_000

/**
 * Builds the app-specific hook set both wallet-core entry points take (the
 * establishment orchestrator and the mend entry point): the bootstrap
 * identity wiring (`WasClient`, `id`-collection store, ladder-signed roster
 * store builder), the unlock-record codec closure, and -- when a KMS is
 * configured -- the KMS-authentication thunk plus the keystore-promotion
 * closure it arms. One builder, so the two bindings can never drift.
 *
 * @param options {object}
 * @param options.credential {UnlockCredential}
 * @param options.ladderSeed {Uint8Array}
 * @param options.pointer {AccountPointer}
 * @param [options.email] {string}
 * @param options.logPins {ResourceLogPinStore}
 * @param options.ceremony {string}   the label the caller's own timer uses,
 *   so the concurrent KMS stage's measured span is filed under the same
 *   ceremony as the marks around it
 * @param options.mark {Function}   the caller's stage timer. The keystore
 *   promotion IS a hook built here, so it closes its own span rather than
 *   leaving wallet-core to name work only this module knows the shape of
 * @returns {Promise<object>}   the hook members, spreadable into either
 *   wallet-core call
 */
async function establishmentHooks({
  credential,
  ladderSeed,
  pointer,
  email,
  logPins,
  ceremony,
  mark
}: {
  credential: UnlockCredential
  ladderSeed: Uint8Array
  pointer: AccountPointer
  email?: string
  logPins: ResourceLogPinStore
  ceremony: string
  mark: (stage: string) => void
}) {
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

  // The KMS stage's thunk, when a KMS is configured: the ceremony starts it
  // BEFORE the Space is awaited and joins on it before the genesis entry, so
  // the entry can carry the KMS `authentication` VM. The keystore is created
  // (or found, list-first) under the LADDER VM's bare did:key -- the
  // bootstrap identity -- and the key is minted by that same identity; the
  // keystore's controller is promoted to the account DID beside the Space's,
  // through the `promoteKeystore` closure both thunks below arm. The
  // `ensureKmsAuthentication` short-circuit on an existing keys.json keeps a
  // heal re-run from generating a key twice, and the adopt path it takes
  // there creates no keystore: it lists under the bootstrap did:key and
  // refuses when nothing is listed. On a heal re-run of an ALREADY-PROMOTED
  // account the bootstrap key is no longer the Space controller, so the
  // keys.json read comes back empty (an unauthorized read looks like an
  // absence) and the write is refused -- an expected, noisy, non-fatal
  // `kmsAuthentication` failure, healed by a later keystore-creation pass.
  let keystoreAgent: KeystoreAgent | undefined
  const kmsServerUrl = KMS_SERVER_URL
  const provideKmsAuthentication =
    kmsServerUrl === undefined
      ? undefined
      : async ({
          spaceReady
        }: {
          spaceReady: Promise<unknown>
        }): Promise<KmsAuthenticationBinding | undefined> => {
          const endSpan = stageSpan({
            log,
            ceremony,
            stage: KMS_AUTHENTICATION_STAGE
          })
          // The probe reads through a PLAINTEXT codec: it starts before the
          // Space exists, and a 404 from an absent Space must read as the
          // same absence an unwritten keys.json does rather than making the
          // client refuse to guess the collection's encryption.
          const body = ensureKmsAuthentication({
            // The adopt path's lookup creates nothing: it lists keystores
            // under the bootstrap did:key and answers `undefined` on a miss,
            // which the stage reads as "this keystore does not list the
            // served key" and refuses. Verifying a served map must never be
            // what mints a keystore.
            lookupKeystoreAgent: async () => {
              keystoreAgent = await findKeystoreAgent({
                kmsServerUrl,
                keyAgent: bootstrapAgent,
                zcapClient: bootstrapZcap
              })
              return keystoreAgent
            },
            provideKeystoreAgent: async () => {
              keystoreAgent = await ensureKeystore({
                kmsServerUrl,
                keyAgent: bootstrapAgent,
                zcapClient: bootstrapZcap
              })
              return keystoreAgent
            },
            remoteStore: {
              getKeyMap: async () => {
                const result = await plaintextCollection({
                  was: bootstrapWas,
                  spaceId,
                  collectionId: KEY_MAP_COLLECTION.id
                })
                  .resource(DID_KEYS_RESOURCE)
                  .get()
                return result === null ? undefined : result
              },
              webvhIdStore: () => idStore
            },
            did: didWebFromSpace({ wasServerUrl: host, spaceId }),
            spaceReady
          })
          // Keep a late rejection handled once the timeout has won the race,
          // on the Space promise as well as this one: the raced body awaits
          // `spaceReady`, so a Space that never comes up rejects here too.
          body.catch(() => undefined)
          spaceReady.catch(() => undefined)
          // The budget starts once the Space is ready rather than covering
          // the wait for it, so slow Space provisioning cannot eat it. It
          // still covers the keystore lookup, the key mint, and the
          // keys.json write, so a timeout can still win with that write in
          // flight, leaving a map the genesis entry does not publish; the
          // next run adopts it after the same listing check.
          await spaceReady.catch(() => undefined)
          let timer: ReturnType<typeof setTimeout> | undefined
          try {
            return await Promise.race([
              body,
              new Promise<never>((_resolve, reject) => {
                timer = setTimeout(
                  () =>
                    reject(
                      new Error(
                        'The KMS authentication provisioning timed out ' +
                          `(${KMS_AUTHENTICATION_TIMEOUT_MS}ms).`
                      )
                    ),
                  KMS_AUTHENTICATION_TIMEOUT_MS
                )
              })
            ])
          } finally {
            clearTimeout(timer)
            // In the `finally`, so a thunk the timeout won still reports the
            // span it measured: the stage cost is what it cost, failure
            // included. The STAGE MARK is wallet-core's, fired at the join,
            // since a thunk finishing before the Space would mark early and
            // put the lobby feed out of order.
            endSpan()
          }
        }

  // The unlock-record codec: the ceremony supplies the pointer shape, the
  // delegations, and `priorCreatedAt`; the credential and the email ride the
  // closure.
  const bindRecord: CredentialAnchoredBindRecordHook = async bind =>
    bindCredentialAnchoredUnlockSecret({
      ...bind,
      email,
      ladderSeed,
      credential
    })

  return {
    standing: {
      clientDid: standing.clientDid,
      keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
      recipientKid: standing.recipientKid,
      keyAgreementKey: standing.agents.keyAgreementKey
    },
    bindRecord,
    // The roster store the genesis (and the adopted-roster read-back) drive:
    // signed log appends under the LADDER VM's key -- the ceremony-tail
    // license's first-entry shape -- invoked as the bootstrap did:key. The
    // account log the ceremony hands over is the head it just published or
    // adopted, so the store resolves its controller view out of this run's
    // own head instead of fetching `did.jsonl` a second time.
    rosterStoreFor: ({ did, log }: { did: string; log: DIDLog }) =>
      accountRosterStore({
        zcapClient: bootstrapZcap,
        keyAgent: bootstrapAgent,
        pointer: { did, spaceId, host },
        pinStore: logPins,
        log
      }),
    // Built from the agent wallet-core hands over (it owns the bootstrap
    // identity); the app-side `bootstrapWas` above serves only the KMS thunk
    // and the id store, derived from the same seed.
    bootstrapWasFor: ({
      keyAgent
    }: {
      keyAgent: Parameters<typeof didKeyZcapClient>[0]['keyAgent']
    }) =>
      new WasClient({
        serverUrl: host,
        zcapClient: didKeyZcapClient({ keyAgent })
      }),
    idStore,
    ...(provideKmsAuthentication ? { provideKmsAuthentication } : {}),
    // The keystore half of the promotion, only when the KMS stage bound a
    // keystore THIS run: one it created, or one it found still controlled by
    // the bootstrap did:key (the only identity either thunk lists under). A
    // run with no KMS configured, and an adopt whose lookup found nothing,
    // both leave it unbound and skip the promotion.
    promoteKeystore: async ({ did }: { did: string }) => {
      if (keystoreAgent) {
        await promoteKeystoreController({ keystoreAgent, controller: did })
        mark('keystore-promotion')
      }
    }
  }
}

/**
 * Runs the whole credential-anchored establishment for one unlock credential
 * (the module doc; the stage order is wallet-core's). Idempotent under
 * re-run from durable state alone.
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
 *   stamp; its presence SKIPS the first bind (the record already carries the
 *   ladder seed) and the re-bind's stamp advances past it
 * @param options.persistence {object}   the in-memory chain-head pin store
 *   for every log read here (`logPins`), which every caller supplies
 * @param [options.beforePromotion] {Function}   runs after the re-bind and
 *   BEFORE the controller promotion -- the last window where a root
 *   invocation under the bootstrap did:key works (the signup's registry
 *   write). NOT swallowed: a throw fails the establishment, so a hook that
 *   must be best-effort swallows its own failures
 * @param [options.onStage] {StageNotifier}   observational: called as each
 *   stage ends, for a progress surface. A throwing notifier is swallowed
 * @returns {Promise<CredentialAnchoredEstablishment>}   wallet-core's
 *   establishment result, whose `accountLog` is the verified head this run
 *   ends standing on -- what a caller entering the account straight
 *   afterwards hands to the composition instead of re-fetching `did.jsonl`
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
  beforePromotion,
  onStage
}: {
  credential: UnlockCredential
  ladderSeed: Uint8Array
  pointer: AccountPointer
  lowEntropy: boolean
  email?: string
  priorCreatedAt?: string
  persistence: { logPins: ResourceLogPinStore }
  onStage?: StageNotifier
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
  // One `mark` for the whole establishment: it closes each stage's timing
  // span AND feeds the caller's optional progress notifier (the lobby
  // page's step feed), so the two can never report different stage sets.
  const ceremony = 'credential-anchored-establishment'
  const mark = stageMarker({
    log,
    ceremony,
    ...(onStage ? { onStage } : {})
  })
  const hooks = await establishmentHooks({
    credential,
    ladderSeed,
    pointer,
    email,
    logPins: persistence.logPins,
    ceremony,
    mark
  })
  mark('bootstrap-wiring')
  const establishment = await runEstablishment({
    wasServerUrl: pointer.host,
    spaceId: pointer.spaceId,
    ladderSeed,
    ...hooks,
    ...(pointer.did !== undefined ? { expectedDid: pointer.did } : {}),
    lowEntropy,
    ...(priorCreatedAt !== undefined ? { priorCreatedAt } : {}),
    // The pre-promotion hook is the signup's registry write, so its span is
    // named here rather than by wallet-core, which only knows it as "the
    // caller's tail".
    ...(beforePromotion
      ? {
          beforePromotion: async (
            context: Parameters<NonNullable<typeof beforePromotion>>[0]
          ) => {
            await beforePromotion(context)
            mark('registry-write')
          }
        }
      : {}),
    onStage: mark,
    pinStore: persistence.logPins
  })

  // The best-effort stages' collected failures: warned here (wallet-core
  // reports them on the result), never fatal. A keystore-less account is
  // complete; Settings shows the state and a later pass heals it.
  for (const { stage, error } of establishment.failed) {
    if (stage === 'kmsAuthentication') {
      log.warn('KMS authentication provisioning failed (continuing)', {
        err: error
      })
    } else if (stage === 'keystorePromotion') {
      log.warn('Keystore controller promotion failed (continuing)', {
        err: error
      })
    }
  }
  return establishment
}

/**
 * The read-first unlock-methods registry hook shared by the signup's
 * pre-promotion window and the mend entry point's establishment and
 * registry arms. Best-effort by the hook's contract: it upserts the
 * passphrase entry into the standing registry (only a true absent starts
 * fresh -- a re-fired hook on a fresh base would clobber the first run's
 * record), and a THROWN read or write is swallowed with a warn, since the
 * miss stays re-recordable at the next remembered login.
 *
 * A passkey entry has no shared hook: its registry record carries WebAuthn
 * registration members (the credential id, the user handle) only the
 * add-a-passkey ceremony holds, so a passkey heal runs with no registry
 * hook and the entry stays that ceremony's own write.
 *
 * @param options {object}
 * @param options.spaceId {string}   the account Space id the registry lives
 *   in
 * @param [options.capability] {IZcap}   an invocation capability the
 *   registry requests ride (the mend's post-promotion arms); the root
 *   capability is invoked otherwise (the signup's bootstrap window)
 * @returns {Function}   the `beforePromotion` hook
 */
export function passphraseRegistryUpsertHook({
  spaceId,
  capability
}: {
  spaceId: string
  capability?: IZcap
}): (context: {
  zcapClient: ZcapClient
  userKey: UserKey
  establishment: CredentialAnchoredEstablishment
}) => Promise<void> {
  return async ({ zcapClient, userKey, establishment }) => {
    try {
      await updateUnlockMethodsWithClient({
        zcapClient,
        spaceId,
        userKey,
        ...(capability ? { capability } : {}),
        mutate: existing => {
          const record = existing ?? emptyUnlockMethodsRegistry()
          // A mend re-fire synthesizes the establishment context from the
          // standing record, which carries no management zcap (the transient
          // keyring fetch never mints one). The upsert rebuilds the entry
          // from scratch, so an absent capability here would durably strip
          // the standing entry's zcap: carry the existing entry's forward
          // whenever the establishment supplies none and the entry still
          // names the same unlock Space.
          const held = record.methods.find(
            (method): method is PassphraseUnlockMethod =>
              method.type === 'passphrase' &&
              method.unlockSpaceId === establishment.unlockSpaceId
          )?.manageCapability
          const manageCapability = establishment.manageCapability ?? held
          return upsertPassphraseUnlockMethod({
            record,
            unlockSpaceId: establishment.unlockSpaceId,
            ...(manageCapability ? { manageCapability } : {}),
            standing: establishment.standingFields
          })
        }
      })
    } catch (err) {
      log.warn(
        'Could not update the unlock-methods registry; skipping the passphrase entry (re-recordable at the next remembered login)',
        { err }
      )
    }
  }
}

/**
 * Freewallet's binding onto the mend entry point
 * (`mendCredentialAnchoredAccount` in `@interop/wallet-core/clientAnnex`):
 * the converging ensure over the tear states the establishment can leave.
 * The arm order, the mixed return contract (a report, except the
 * failed-delegated-read promotion trigger, which rethrows the original
 * error unchanged), and the caller obligations are wallet-core's; this
 * binding supplies the same app-specific hooks the establishment binding
 * does and threads the mend-specific members through unchanged. The
 * refusal mapping from the report onto `TransientLoginUnavailableError`
 * reasons stays with the callers.
 *
 * @param options {object}
 * @param options.credential {UnlockCredential}   the derived unlock
 *   credential (binding-verified by the keyring layer before its members
 *   are trusted here)
 * @param options.ladderSeed {Uint8Array}   the record's ladder seed
 * @param options.pointer {AccountPointer}   the account pointer
 * @param options.controller {string}   the record's controller
 * @param options.lowEntropy {boolean}
 * @param [options.email] {string}
 * @param [options.priorCreatedAt] {string}   the record's freshness stamp
 * @param options.persistence {object}   the in-memory chain-head pin store
 *   (`logPins`)
 * @param [options.beforePromotion] {Function}   the read-first registry
 *   hook; the establishment arm fires it in its root window, the registry
 *   arm under the post-promotion authority
 * @param [options.delegatedClients] {IZcap}   the record's sibling
 *   delegation
 * @param [options.invocation] {object}   the post-promotion authority
 *   triple (`was`, `zcapClient`, `capability`) the roster and registry arms
 *   ride
 * @param [options.rosterStore] {EncryptionDescriptorStore}   the roster
 *   store under that same authority, ladder-signed
 * @param [options.delegatedRead] {object}   the promotion arm's
 *   failed-delegated-read trigger (`error`, `retry`)
 * @param options.hasRosterEpochPin {Function}   the mint-precondition port:
 *   whether this caller holds a roster-epoch pin for the account. This
 *   wallet holds none across sessions
 *   (`decisions/0012-no-durable-continuity-pins.md`), so every caller
 *   passes `async () => false` explicitly -- "no pin" stays a statement,
 *   never a dropped option
 * @param [options.registry] {object}   the registry arm's context from the
 *   caller's standing record
 * @param [options.userKey] {UserKey}   the session's user key, when held
 * @param [options.repairShaped] {boolean}   fires the completion arms with
 *   no tear of their own
 * @param [options.collectionIds] {string[]}   the encrypted-collection set
 *   the roster arm's completion probe and epoch fan-out cover; defaults to
 *   this wallet's own encrypted standard collections, which is what the
 *   establishment installed epoch[0] on
 * @returns {Promise<CredentialAnchoredMendReport>}
 */
export async function mendCredentialAnchoredAccount({
  credential,
  ladderSeed,
  pointer,
  controller,
  lowEntropy,
  email,
  priorCreatedAt,
  persistence,
  beforePromotion,
  delegatedClients,
  invocation,
  rosterStore,
  delegatedRead,
  hasRosterEpochPin,
  registry,
  userKey,
  repairShaped,
  collectionIds = ENCRYPTED_STANDARD_COLLECTIONS.map(({ id }) => id)
}: {
  credential: UnlockCredential
  ladderSeed: Uint8Array
  pointer: AccountPointer
  controller: string
  lowEntropy: boolean
  email?: string
  priorCreatedAt?: string
  persistence: { logPins: ResourceLogPinStore }
  beforePromotion?: (context: {
    was: WasClient
    zcapClient: ZcapClient
    did: string
    userKey: UserKey
    establishment: CredentialAnchoredEstablishment
  }) => Promise<void>
  delegatedClients?: IZcap
  invocation?: { was: WasClient; zcapClient: ZcapClient; capability: IZcap }
  rosterStore?: EncryptionDescriptorStore
  delegatedRead?: { error: unknown; retry: () => Promise<void> }
  hasRosterEpochPin: () => Promise<boolean>
  registry?: CredentialAnchoredRegistryContext
  userKey?: UserKey
  repairShaped?: boolean
  collectionIds?: string[]
}): Promise<CredentialAnchoredMendReport> {
  if (!WAS_SERVER_URL) {
    throw new TypeError(
      'The credential-anchored mend requires a configured WAS server.'
    )
  }
  const ceremony = 'credential-anchored-mend'
  const mark = stageTimer({ log, ceremony })
  const hooks = await establishmentHooks({
    credential,
    ladderSeed,
    pointer,
    email,
    logPins: persistence.logPins,
    ceremony,
    mark
  })
  mark('bootstrap-wiring')
  const report = await runMend({
    account: { controller, pointer, ladderSeed },
    ...hooks,
    lowEntropy,
    ...(priorCreatedAt !== undefined ? { priorCreatedAt } : {}),
    ...(delegatedClients !== undefined ? { delegatedClients } : {}),
    ...(beforePromotion ? { beforePromotion } : {}),
    ...(invocation ? { invocation } : {}),
    ...(rosterStore ? { rosterStore } : {}),
    ...(delegatedRead ? { delegatedRead } : {}),
    hasRosterEpochPin,
    ...(registry ? { registry } : {}),
    ...(userKey ? { userKey } : {}),
    ...(repairShaped !== undefined ? { repairShaped } : {}),
    collectionIds,
    onStage: mark,
    pinStore: persistence.logPins
  })
  return report
}
