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
 *   `bindCredentialAnchoredUnlockSecret`, carrying the credential, the
 *   email, and the durable caller's keyring-freshness-pin floor);
 * - the storage wiring under the bootstrap identity (the `WasClient`, the
 *   account `id`-collection store, the ladder-signed roster store builder);
 * - the KMS/did:web thunk (`provideDidWebKeys`, best-effort with a local
 *   timeout) and the keystore-controller promotion closure it arms;
 * - the caller's pre-promotion tail (`beforePromotion`, the signup's
 *   registry write) passed through unchanged;
 * - logging: the ceremony's collected best-effort failures are warned here.
 *
 * One function serves the fresh signup and the login-time re-run alike --
 * every stage is an ensure, so a signup torn at any point converges by
 * running the whole thing again.
 */
import { WasClient } from '@interop/was-client'
import {
  establishCredentialAnchoredAccount as runEstablishment,
  ladderVmAgent,
  type CredentialAnchoredEstablishment
} from '@interop/wallet-core/clientAnnex'
import {
  didKeyZcapClient,
  wasWebvhIdStore,
  type DidWebKeyMapV2
} from '@interop/wallet-core/webvh'
import type { UserKey } from '@interop/wallet-core/keys'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type { ZcapClient } from '@interop/ezcap'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import type { KeystoreAgent } from '@interop/webkms-client'
import {
  DID_KEYS_RESOURCE,
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
import { createLogger, stageTimer } from '@/lib/log'

export type { CredentialAnchoredEstablishment }

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
 * @param options.persistence {object}   the chain-head pin store for every
 *   log read here (`logPins`): the transient visit's in-memory handle on the
 *   default signup and the heal, or a durable handle when a remembered
 *   caller wants its own publication to seed the browser's durable pin
 * @param [options.freshnessPinFloor] {object}   present when the caller holds
 *   durable state (the remembered and passkey signups): threaded into both
 *   binds so their stamps additionally advance past the local
 *   keyring-freshness pin (read-only; `idb` overrides the IndexedDB
 *   factory). The transient callers omit it -- even the read durably
 *   creates the session database
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
  freshnessPinFloor,
  beforePromotion
}: {
  credential: UnlockCredential
  ladderSeed: Uint8Array
  pointer: AccountPointer
  lowEntropy: boolean
  email?: string
  priorCreatedAt?: string
  persistence: { logPins: ResourceLogPinStore }
  freshnessPinFloor?: { idb?: IDBFactory }
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
            mark('did-web-keys')
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
          }
        }

  const establishment = await runEstablishment({
    wasServerUrl: host,
    spaceId,
    ladderSeed,
    standing: {
      clientDid: standing.clientDid,
      keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
      recipientKid: standing.recipientKid,
      keyAgreementKey: standing.agents.keyAgreementKey
    },
    // The unlock-record codec: the ceremony supplies the pointer shape, the
    // delegations, and `priorCreatedAt`; the credential, the email, and the
    // durable caller's freshness-pin floor ride the closure.
    bindRecord: async bind =>
      bindCredentialAnchoredUnlockSecret({
        ...bind,
        email,
        ladderSeed,
        ...(freshnessPinFloor ? { freshnessPinFloor } : {}),
        credential
      }),
    // The roster store the genesis (and the adopted-roster read-back) drive:
    // signed log appends under the LADDER VM's key -- the ceremony-tail
    // license's first-entry shape -- invoked as the bootstrap did:key.
    rosterStoreFor: ({ did }) =>
      accountRosterStore({
        zcapClient: bootstrapZcap,
        keyAgent: bootstrapAgent,
        pointer: { did, spaceId, host },
        pinStore: persistence.logPins
      }),
    // Built from the agent the orchestrator hands over (it owns the
    // bootstrap identity); the app-side `bootstrapWas` above serves only the
    // KMS thunk and the id store, derived from the same seed.
    bootstrapWasFor: ({ keyAgent }) =>
      new WasClient({
        serverUrl: host,
        zcapClient: didKeyZcapClient({ keyAgent })
      }),
    idStore,
    ...(pointer.did !== undefined ? { expectedDid: pointer.did } : {}),
    lowEntropy,
    ...(priorCreatedAt !== undefined ? { priorCreatedAt } : {}),
    ...(provideDidWebKeys ? { provideDidWebKeys } : {}),
    // The keystore half of the promotion, only when the KMS thunk bound a
    // keystore THIS run (a heal that short-circuited off an existing
    // keys.json never bound one).
    promoteKeystore: async ({ did }) => {
      if (keystoreAgent) {
        await promoteKeystoreController({ keystoreAgent, controller: did })
        mark('keystore-promotion')
      }
    },
    ...(beforePromotion ? { beforePromotion } : {}),
    pinStore: persistence.logPins
  })
  mark('establishment')

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
