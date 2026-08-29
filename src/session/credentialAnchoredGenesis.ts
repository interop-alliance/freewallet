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
 * - the KMS/did:web thunk (`provideDidWebKeys`, best-effort with a local
 *   timeout) and the keystore-controller promotion closure it arms;
 * - the caller's pre-promotion tail (`beforePromotion`, the signup's
 *   registry write), wrapped only to close its own timing span;
 * - logging: the ceremony's collected best-effort failures are warned here,
 *   and its stage timings are collected on one timer. wallet-core's
 *   `onStage` notifier closes the span of every stage it runs; the three
 *   stages whose body is a closure supplied here -- the KMS/did:web thunk,
 *   the pre-promotion registry write, the keystore promotion -- close their
 *   own, so each reported figure is the stage it is named after rather than
 *   everything that happened since the last name.
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
  type CredentialAnchoredBindRecordHook,
  type CredentialAnchoredEstablishment,
  type CredentialAnchoredMendReport,
  type CredentialAnchoredRegistryContext
} from '@interop/wallet-core/clientAnnex'
import {
  didKeyZcapClient,
  wasWebvhIdStore,
  type DidWebKeyMapV2
} from '@interop/wallet-core/webvh'
import type { UserKey } from '@interop/wallet-core/keys'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import type { KeystoreAgent } from '@interop/webkms-client'
import {
  DID_KEYS_RESOURCE,
  ENCRYPTED_STANDARD_COLLECTIONS,
  KEY_MAP_COLLECTION,
  KMS_SERVER_URL,
  WAS_SERVER_URL
} from '@/app.config'
import { didWebFromSpace, ensureDidWeb } from '@/lib/didWeb'
import { ensureKeystore, promoteKeystoreController } from '@/lib/kms'
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
import { createLogger, stageTimer } from '@/lib/log'

export type { CredentialAnchoredEstablishment, CredentialAnchoredMendReport }

const log = createLogger('fw:session:genesis')

/**
 * The bound on the whole KMS stage (keystore ensure, did:web key mint,
 * keys.json/did.json publication): a hung -- not throwing -- KMS sits between
 * Space creation and the genesis entry, so it must not wedge the signup. On
 * timeout the thunk throws and the genesis ceremony collects it as its
 * non-fatal `didWebKeys` stage.
 */
const DID_WEB_KEYS_TIMEOUT_MS = 30_000

/**
 * Builds the app-specific hook set both wallet-core entry points take (the
 * establishment orchestrator and the mend entry point): the bootstrap
 * identity wiring (`WasClient`, `id`-collection store, ladder-signed roster
 * store builder), the unlock-record codec closure, and -- when a KMS is
 * configured -- the did:web thunk plus the keystore-promotion closure it
 * arms. One builder, so the two bindings can never drift.
 *
 * @param options {object}
 * @param options.credential {UnlockCredential}
 * @param options.ladderSeed {Uint8Array}
 * @param options.pointer {AccountPointer}
 * @param [options.email] {string}
 * @param options.logPins {ResourceLogPinStore}
 * @param options.mark {Function}   the caller's stage timer. Two of the
 *   ceremony's stages ARE hooks built here -- the KMS/did:web thunk and the
 *   keystore promotion -- so each closes its own span rather than leaving
 *   wallet-core to name work only this module knows the shape of
 * @returns {Promise<object>}   the hook members, spreadable into either
 *   wallet-core call
 */
async function establishmentHooks({
  credential,
  ladderSeed,
  pointer,
  email,
  logPins,
  mark
}: {
  credential: UnlockCredential
  ladderSeed: Uint8Array
  pointer: AccountPointer
  email?: string
  logPins: ResourceLogPinStore
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

  // The KMS stage's thunk, when a KMS is configured: the ceremony calls it
  // once the Space exists, before the genesis entry, so the entry can carry
  // the KMS `authentication` VM. The keystore is created (or found,
  // list-first) under the LADDER VM's bare did:key -- the bootstrap identity
  // -- and the did:web keys are minted and keys.json/did.json published by
  // that same identity; the keystore's controller is promoted to the account
  // DID beside the Space's, through the `promoteKeystore` closure this thunk
  // arms. The ensureDidWeb short-circuit on an existing keys.json keeps a
  // heal re-run from generating keys twice, and its lazy keystore
  // acquisition keeps that path off the KMS entirely. On a heal re-run of an
  // ALREADY-PROMOTED account the bootstrap key is no longer the Space
  // controller, so the keys.json read comes back empty (an unauthorized read
  // looks like an absence) and the write is refused -- an expected, noisy,
  // non-fatal `didWebKeys` failure, healed by a later keystore-creation
  // pass. The whole thunk races a timeout: a hung KMS must not wedge the
  // signup between Space creation and the genesis entry.
  let keystoreAgent: KeystoreAgent | undefined
  const kmsServerUrl = KMS_SERVER_URL
  const provideDidWebKeys =
    kmsServerUrl === undefined
      ? undefined
      : async (): Promise<DidWebKeyMapV2 | undefined> => {
          const body = (async () => {
            const keys = await ensureDidWeb({
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
                  const result = await bootstrapWas
                    .space(spaceId)
                    .collection(KEY_MAP_COLLECTION.id)
                    .resource(DID_KEYS_RESOURCE)
                    .get()
                  return result === null ? undefined : result
                },
                webvhIdStore: () => idStore
              },
              did: didWebFromSpace({ wasServerUrl: host, spaceId })
            })
            return keys as DidWebKeyMapV2
          })()
          // Keep a late rejection handled once the timeout has won the race.
          body.catch(() => undefined)
          let timer: ReturnType<typeof setTimeout> | undefined
          try {
            return await Promise.race([
              body,
              new Promise<never>((_resolve, reject) => {
                timer = setTimeout(
                  () =>
                    reject(
                      new Error(
                        'The did:web key provisioning timed out ' +
                          `(${DID_WEB_KEYS_TIMEOUT_MS}ms).`
                      )
                    ),
                  DID_WEB_KEYS_TIMEOUT_MS
                )
              })
            ])
          } finally {
            clearTimeout(timer)
            // In the `finally`, so a thunk the timeout won still closes its
            // own span: the stage cost is what it cost, failure included,
            // and leaving it unmarked would fold it into the genesis stage
            // that follows.
            mark('did-web-keys')
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
    // license's first-entry shape -- invoked as the bootstrap did:key.
    rosterStoreFor: ({ did }: { did: string }) =>
      accountRosterStore({
        zcapClient: bootstrapZcap,
        keyAgent: bootstrapAgent,
        pointer: { did, spaceId, host },
        pinStore: logPins
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
    ...(provideDidWebKeys ? { provideDidWebKeys } : {}),
    // The keystore half of the promotion, only when the KMS thunk bound a
    // keystore THIS run (a heal that short-circuited off an existing
    // keys.json never bound one).
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
  persistence: { logPins: ResourceLogPinStore }
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
  const hooks = await establishmentHooks({
    credential,
    ladderSeed,
    pointer,
    email,
    logPins: persistence.logPins,
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
    if (stage === 'didWebKeys') {
      log.warn('did:web provisioning failed (continuing)', { err: error })
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
  const mark = stageTimer({
    log,
    ceremony: 'credential-anchored-mend'
  })
  const hooks = await establishmentHooks({
    credential,
    ladderSeed,
    pointer,
    email,
    logPins: persistence.logPins,
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
