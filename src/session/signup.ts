/**
 * The two new-account provisioning sequences behind the signup page: one for a
 * passkey account, one for a passphrase account. On a WAS deployment BOTH run
 * the credential-anchored establishment (`establishCredentialAnchoredAccount`)
 * -- the standing-layout unlock record is durably written before the Space
 * exists, so no signup can leave a plain pointer record behind. The
 * non-remembered passphrase default then enters through the transient
 * composition; a remembered passphrase signup and every passkey signup follow
 * the establishment with the ordinary durable login, whose self-enrollment
 * makes this browser an enrolled client. Only a no-WAS deployment keeps the
 * plain durable flow (no unlock Space exists there, so there is nothing to be
 * standing in). The page keeps the wizard state and the error copy; the
 * orderings live here.
 */
import { base64urlnopad } from '@scure/base'
import { KEYRING_KDF, type AccountPointer } from '@interop/wallet-core/keyring'
import { mintAccountKeySet as mintSharedAccountKeySet } from '@interop/wallet-core/genesis'
import { generateLadderSeed } from '@interop/wallet-core/clientAnnex'
import { setClientLabel } from '@interop/wallet-core/keys'
import { clientSigningKeyMultibase } from '@interop/wallet-core/webvh'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import {
  DATE_FMT,
  DEFAULT_CLIENT_LABEL,
  PASSKEY_KDF,
  WAS_SERVER_URL
} from '@/app.config'
import {
  initSessionFromSeed,
  loginWithPassphrase,
  loginWithPasskey
} from '@/session/initSession'
import {
  bindPassphrase,
  deriveUnlockCredential,
  fetchTransientKeyring,
  type UnlockCredential
} from '@/session/keyring'
import {
  establishCredentialAnchoredAccount,
  passphraseRegistryUpsertHook
} from '@/session/credentialAnchoredGenesis'
import {
  transientSessionStores,
  type TransientSessionStores
} from '@/session/persistence'
import { transientSessionFromKeyringHit } from '@/session/transientLogin'
import {
  provisionNewWallet,
  seedWelcomeContent
} from '@/session/provisionNewWallet'
import {
  enrollPasskey,
  updateUnlockMethods,
  updateUnlockMethodsWithClient,
  upsertPasskeyUnlockMethod,
  type PasskeyUnlockMethod
} from '@/session/unlockMethods'
import {
  forcedEstablishmentTearBeforePromotion,
  forcedSignupTearAfterEstablishment
} from '@/lib/e2eSeams'
import { registerPasskey } from '@/lib/passkey'
import { sessionLogPinStore } from '@/lib/sessionKey'
import { mintSpaceId } from '@/stores/wasRemoteStore'
import type { Session } from '@/types/auth'
import { createLogger, stageTimer } from '@/lib/log'

const log = createLogger('fw:session:signup')

/**
 * This client's freshly minted key set for a brand-new account: the client
 * seed (random, local, never derived from any secret and never leaving the
 * browser), the account's user key (its roster identity -- recipient zero of every
 * encrypted collection, cached locally under the unlock layer), this client's
 * did:webvh update-key seeds (the identity log can only ever be extended with
 * client-held keys), and the account pointer the keyring record carries in
 * place of the retired data seed: where the account lives. The Space id is an
 * independent random identifier minted here (nothing about the account derives
 * from any key). Built before session creation so the storage clients bind to
 * the minted id. Only the no-WAS durable flow mints here now -- a WAS signup
 * mints inside the credential-anchored establishment and the durable login's
 * self-enrollment.
 *
 * The mint itself is wallet-core's shared `mintAccountKeySet` (both wallet
 * apps mint the same set); this wrapper only maps it onto the local names and
 * folds the Space id into the account pointer.
 *
 * @returns {Promise<{ seed: Uint8Array, userKey: object, webvhUpdateKeys: object,
 *   pointer?: AccountPointer }>}
 */
async function mintAccountKeySet() {
  const { spaceId, clientSeed, userKey, updateKeys } =
    await mintSharedAccountKeySet()
  const pointer: AccountPointer | undefined = WAS_SERVER_URL
    ? { spaceId, host: WAS_SERVER_URL }
    : undefined
  return {
    seed: clientSeed,
    userKey,
    webvhUpdateKeys: updateKeys,
    pointer
  }
}

/**
 * The establishment half of the credential-anchored passphrase signup: one
 * KDF run, the create-nothing existing-account probe (`fetchTransientKeyring`
 * -- the durable probe would self-enroll this browser), and the whole
 * credential-anchored establishment with the passphrase registry hook. Shared
 * by the non-remembered default (which then enters transiently) and the
 * remembered signup (which then runs the durable login) -- the remembered
 * caller invokes THIS half only, never the transient composition, so no
 * per-visit annex client is ever minted and abandoned for it.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param [options.email] {string}
 * @param options.logPins {ResourceLogPinStore}   the chain-head pin store
 *   every log read here rides: the visit's in-memory one on the default
 *   signup, the durable one on a remembered signup (so the browser's pin is
 *   seeded by its own publication)
 * @param [options.freshnessPinFloor] {object}   threaded into the
 *   establishment's binds when the caller holds durable state (the
 *   remembered signup); the default caller omits it
 * @returns {Promise<object>}   `{ userExists: true }` when the probe located
 *   an account, else `{ userExists: false, credential }` with the derived
 *   credential for the entry half
 */
async function establishPassphraseAnchoredAccount({
  passphrase,
  email,
  logPins,
  freshnessPinFloor
}: {
  passphrase: string
  email?: string
  logPins: ResourceLogPinStore
  freshnessPinFloor?: { idb?: IDBFactory }
}): Promise<
  { userExists: true } | { userExists: false; credential: UnlockCredential }
> {
  const mark = stageTimer({ log, ceremony: 'credential-anchored-signup' })
  // One 600k-iteration derivation for the whole signup.
  const credential = await deriveUnlockCredential({
    secret: passphrase,
    kdf: KEYRING_KDF
  })
  mark('kdf')
  const probe = await fetchTransientKeyring({
    credential,
    accountLogPinStore: logPins
  })
  mark('existing-account-probe')
  if (probe) {
    return { userExists: true }
  }

  const spaceId = mintSpaceId()
  const pointer: AccountPointer = { spaceId, host: WAS_SERVER_URL }
  const ladderSeed = generateLadderSeed()
  await establishCredentialAnchoredAccount({
    credential,
    ladderSeed,
    pointer,
    lowEntropy: true,
    email,
    persistence: { logPins },
    ...(freshnessPinFloor ? { freshnessPinFloor } : {}),
    // The registry entry, in the last root-invocation window: the shared
    // read-first hook (the mend entry point's arms re-fire the same one).
    // Best-effort by the hook's own contract -- a re-fired hook upserts
    // into the standing registry, only a true absent starts fresh, and a
    // thrown read or write skips with a warn (re-recordable later). The
    // e2e tear seam fires after the registry write so the torn state it
    // leaves is exactly a re-bound, registry-carrying account whose
    // controller promotion never ran.
    beforePromotion: async context => {
      await passphraseRegistryUpsertHook({ spaceId })(context)
      if (forcedEstablishmentTearBeforePromotion()) {
        throw new Error('e2e: the signup tore before the controller promotion.')
      }
    }
  })
  mark('establishment')
  return { userExists: false, credential }
}

/**
 * The transient-entry half of the credential-anchored passphrase signup:
 * re-fetch the record just established and enter the account exactly as any
 * later public-terminal login would, through the ordinary transient
 * composition, then kick off the welcome-content seeding.
 *
 * @param options {object}
 * @param options.credential {UnlockCredential}   the establishment half's
 *   derived credential
 * @param [options.email] {string}
 * @param options.persistence {TransientSessionStores}
 *   the visit's in-memory store family (shared with the establishment
 *   half's pins)
 * @returns {Promise<{ session: Session, userExists: false }>}
 */
async function enterEstablishedAccountTransiently({
  credential,
  email,
  persistence
}: {
  credential: UnlockCredential
  email?: string
  persistence: TransientSessionStores
}): Promise<{ session: Session; userExists: false }> {
  const found = await fetchTransientKeyring({
    credential,
    accountLogPinStore: persistence.logPins
  })
  if (!found) {
    throw new Error(
      'The freshly established unlock record could not be fetched back.'
    )
  }
  const { session } = await transientSessionFromKeyringHit({
    found,
    type: 'passphrase',
    email,
    persistence,
    credential
  })
  // Kick off the welcome-content seeding without awaiting it: the signup is
  // already long, so the seed runs behind the dashboard navigation, tracked
  // by `welcomeSeedReady` (the dashboard shows an indicator until it
  // settles). Best-effort throughout: the helper swallows failures and
  // bounds its own duration, so the promise never rejects.
  session.welcomeSeedReady = seedWelcomeContent({ session })
  return { session, userExists: false }
}

/**
 * Best-effort tail of a durable (remembered or passkey) WAS signup: label the
 * first enrolled client in `key-map/client-labels.json` (every later client
 * gets its label at enrollment approval; this one has no approving screen, so
 * the wallet names itself -- the Connected wallets panel would otherwise show
 * "Unnamed wallet") and kick off the welcome-content seeding un-awaited onto
 * `session.welcomeSeedReady`. Waits for storage provisioning first, since
 * both writes need the collections; a provisioning failure is the login
 * page's to surface, so it is swallowed here and the writes are skipped.
 *
 * @param options {object}
 * @param options.session {Session}   the freshly self-enrolled durable
 *   session
 * @returns {Promise<void>}
 */
async function finishDurableSignup({
  session
}: {
  session: Session
}): Promise<void> {
  try {
    await session.storageReady
  } catch {
    return
  }
  const { storage, profile } = session
  if (storage.remoteStore && profile.keyAgent) {
    try {
      await setClientLabel({
        store: storage.remoteStore.clientLabelsStore(),
        signingKeyMultibase: clientSigningKeyMultibase({
          keyAgent: profile.keyAgent
        }),
        label: DEFAULT_CLIENT_LABEL
      })
    } catch (err) {
      log.warn("Could not label this first client's wallet", { err })
    }
  }
  session.welcomeSeedReady = seedWelcomeContent({ session })
}

/**
 * Creates a new wallet under a passphrase, or reports that this passphrase
 * already has one.
 *
 * On a WAS deployment every signup runs the credential-anchored
 * establishment (the standing-layout record before the Space, the
 * ladder-anchored genesis, the registry hook). The non-remembered default
 * then enters through the transient composition, leaving zero local residue;
 * an explicit `rememberBrowser: true` -- the programmatic
 * remember-this-browser entry (the e2e seam today, the signup form's
 * checkbox when it lands) -- instead follows the establishment with the
 * ordinary durable login, whose self-enrollment makes this browser an
 * enrolled client (two loud log entries, the roster read through the
 * credential's standing wrap, the client-key record persisted). The
 * remembered result always reports `userExists: false` on success: the inner
 * login's `userExists: true` describes the account the signup itself just
 * created and must not route the page to "this profile already exists".
 *
 * A no-WAS deployment keeps the plain durable flow: probe (the durable
 * `loginWithPassphrase` probe -- resolving the passphrase through the
 * keyring and reading `userExists` prevents a re-signup with an existing
 * passphrase from overwriting that account's keyring), bind BEFORE the local
 * collections exist, then provision. There is no unlock Space, no transient
 * login, and nothing to be standing in there.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param [options.email] {string}
 * @param [options.rememberBrowser] {boolean}   `true` runs the durable
 *   remembered signup; absent or `false`, a WAS-configured signup ends in a
 *   transient session
 * @returns {Promise<{ session?: Session, userExists: boolean }>}
 */
export async function signUpWithPassphrase({
  passphrase,
  email,
  rememberBrowser
}: {
  passphrase: string
  email?: string
  rememberBrowser?: boolean
}): Promise<{ session?: Session; userExists: boolean }> {
  if (WAS_SERVER_URL && rememberBrowser === true) {
    // The remembered signup: the establishment half only (never the
    // transient composition -- that would mint and abandon a per-visit
    // annex client), under the DURABLE pin store so the browser's
    // chain-head pin is seeded by its own publication, with the
    // keyring-freshness-pin floor threaded into the binds.
    const outcome = await establishPassphraseAnchoredAccount({
      passphrase,
      email,
      logPins: sessionLogPinStore({}),
      freshnessPinFloor: {}
    })
    if (outcome.userExists) {
      return { userExists: true }
    }
    if (forcedSignupTearAfterEstablishment()) {
      // The torn-signup e2e seam: simulate a tab death between the
      // establishment and the durable-login half. Never true in production.
      throw new Error(
        'e2e seam: the remembered signup was torn after the establishment.'
      )
    }
    // The ordinary durable login: its `canSelfEnroll` path self-enrolls
    // this browser from the record just established.
    const { session } = await loginWithPassphrase({
      passphrase,
      email,
      credential: outcome.credential,
      rememberBrowser: true
    })
    if (!session) {
      throw new Error(
        'The remembered signup could not log in to the account it just ' +
          'established.'
      )
    }
    await finishDurableSignup({ session })
    return { session, userExists: false }
  }
  if (WAS_SERVER_URL) {
    // The credential-anchored default: establishment, then the transient
    // entry, both over the visit's in-memory store family.
    const persistence = transientSessionStores()
    const outcome = await establishPassphraseAnchoredAccount({
      passphrase,
      email,
      logPins: persistence.logPins
    })
    if (outcome.userExists) {
      return { userExists: true }
    }
    return enterEstablishedAccountTransiently({
      credential: outcome.credential,
      email,
      persistence
    })
  }
  // The no-WAS durable flow. Probe for an existing account first.
  // loginWithPassphrase resolves the passphrase through the keyring and
  // reports whether this identity already has a wallet; probing (rather than
  // binding a raw seed straight away) is what prevents a re-signup with an
  // existing passphrase from overwriting that account's keyring and
  // orphaning the wallet. The probe session is discarded after reading
  // `userExists`, so it must not provision. One 600k-iteration derivation
  // for the whole signup: the probe login and the bind both run on this
  // identity.
  const credential = await deriveUnlockCredential({
    secret: passphrase,
    kdf: KEYRING_KDF
  })
  const probe = await loginWithPassphrase({
    passphrase,
    email,
    provisionStorage: false,
    credential,
    rememberBrowser: true
  })
  if (probe.userExists) {
    return { userExists: true }
  }

  // This is a new user. Session creation does not provision
  // (`provisionStorage: false`); `provisionNewWallet` runs the ordered
  // provisioning sequence only after the bind succeeds.
  const { seed, userKey, webvhUpdateKeys, pointer } = await mintAccountKeySet()
  const { session } = await initSessionFromSeed({
    seed,
    userKey,
    webvhUpdateKeys,
    accountPointer: pointer,
    email,
    provisionStorage: false
  })
  const { persistClientKeys } = await bindPassphrase({
    clientSeed: seed,
    controller: session.user.id,
    passphrase,
    // Carried inside the wrapped record so any unlock method (a passkey
    // login has no form to ask on) recovers the account email.
    email,
    userKey,
    webvhUpdateKeys,
    pointer,
    credential
  })
  session.profile.persistClientKeys = persistClientKeys

  // Provision collections, record the initial history, and seed the
  // welcome credential.
  await provisionNewWallet({ session })

  return { session, userExists: false }
}

/**
 * The credential-anchored passkey signup: WebAuthn `create` first (the PRF
 * output in hand for the whole sequence), then the credential-anchored
 * establishment under the PRF-derived credential (`lowEntropy: false` -- the
 * PRF key publishes verbatim), then the ordinary durable passkey login whose
 * self-enrollment makes this browser an enrolled client. Always durable:
 * registering a passkey is itself a durable ceremony.
 *
 * The registry hook here is NOT best-effort (a throw fails the
 * establishment): an absent passkey entry has no rebuild
 * (`rebuildBarePasskeyEntry` mends only a present-but-bare entry -- an
 * absent one needs the WebAuthn credential id no login carries), and a lost
 * `webAuthnUserId` would re-mint a random one and register a second resident
 * credential on the next passkey add. The hook is read-first like the
 * passphrase one (a heal re-run must upsert, not clobber), minting
 * `{ version: 1, webAuthnUserId, methods: [] }` only on a true absent.
 *
 * The stated residue: a failure between WebAuthn `create` and the
 * establishment leaves an orphan resident credential on the authenticator
 * (WebAuthn has no delete API); a retry registers another. The thrown error
 * reaches the signup page's generic handling.
 *
 * @param options {object}
 * @param options.userHandle {Uint8Array}   the freshly minted 16-byte
 *   WebAuthn user id
 * @param [options.email] {string}
 * @param options.locale {string}
 * @param options.userName {string}
 * @param options.promptForPrfRetry {function}
 * @returns {Promise<{ session: Session }>}
 */
async function signUpCredentialAnchoredWithPasskey({
  userHandle,
  email,
  locale,
  userName,
  promptForPrfRetry
}: {
  userHandle: Uint8Array
  email?: string
  locale: string
  userName: string
  promptForPrfRetry: () => Promise<boolean>
}): Promise<{ session: Session }> {
  const mark = stageTimer({ log, ceremony: 'credential-anchored-signup' })
  // The ONE WebAuthn ceremony of the whole signup: the durable login below
  // takes the derived credential and skips its own PRF assertion. A
  // brand-new wallet has no authenticator credentials yet, so there is
  // nothing to exclude.
  const registration = await registerPasskey({
    userHandle,
    userName,
    promptForPrfRetry
  })
  mark('webauthn-create')
  const credential = await deriveUnlockCredential({
    secret: registration.prfOutput,
    kdf: PASSKEY_KDF
  })
  mark('kdf')

  const spaceId = mintSpaceId()
  const pointer: AccountPointer = { spaceId, host: WAS_SERVER_URL }
  const ladderSeed = generateLadderSeed()
  await establishCredentialAnchoredAccount({
    credential,
    ladderSeed,
    pointer,
    lowEntropy: false,
    email,
    persistence: { logPins: sessionLogPinStore({}) },
    freshnessPinFloor: {},
    beforePromotion: async ({ zcapClient, userKey, establishment }) => {
      // The passkey registry entry, in the last root-invocation window --
      // fatal on failure (see the function doc). Read-first: a heal re-run
      // upserts into the standing registry and keeps its recorded
      // `webAuthnUserId`; only a true absent mints the record from the
      // user id registered above.
      const now = new Date()
      const entry: PasskeyUnlockMethod = {
        type: 'passkey',
        label: `Passkey created ${now.toLocaleDateString(locale, DATE_FMT)}`,
        createdAt: now.toISOString(),
        credentialId: base64urlnopad.encode(registration.credentialId),
        transports: registration.transports,
        backupEligibility: registration.backupEligibility,
        backupState: registration.backupState,
        unlockSpaceId: establishment.unlockSpaceId,
        ...(establishment.manageCapability
          ? { manageCapability: establishment.manageCapability }
          : {}),
        ...establishment.standingFields
      }
      await updateUnlockMethodsWithClient({
        zcapClient,
        spaceId,
        userKey,
        mutate: existing =>
          upsertPasskeyUnlockMethod({
            record: existing ?? {
              version: 1,
              webAuthnUserId: base64urlnopad.encode(userHandle),
              methods: []
            },
            entry
          })
      })
    }
  })
  mark('establishment')

  // The ordinary durable passkey login: its `canSelfEnroll` path self-enrolls
  // this browser from the record just established. The derived credential
  // skips a second WebAuthn ceremony.
  const { session } = await loginWithPasskey({
    credential,
    rememberBrowser: true
  })
  if (!session) {
    throw new Error(
      'The passkey signup could not log in to the account it just ' +
        'established.'
    )
  }
  mark('durable-login')

  // Mark this as a passkey-only account so the dashboard can prompt the
  // user to add a second unlock method -- through the durable session's
  // persistence handle (the establishment holds no durable handle).
  // Non-fatal.
  try {
    await session.profile.persistence.passkeyNotices.save({
      controller: session.user.id,
      backupEligibility: registration.backupEligibility,
      backupState: registration.backupState
    })
  } catch (err) {
    log.warn('Could not save the passkey-safety notice', { err })
  }

  await finishDurableSignup({ session })
  return { session }
}

/**
 * Creates a new wallet under a passkey. On a WAS deployment the whole signup
 * is the credential-anchored fold (see
 * `signUpCredentialAnchoredWithPasskey`); a no-WAS deployment keeps the
 * plain durable flow -- register and bind BEFORE the local collections
 * exist, provision, then record the registry entry. There is no `userExists`
 * probe on either path: a fresh credential cannot collide with an existing
 * account, so there is nothing to probe.
 *
 * @param options {object}
 * @param [options.email] {string}
 * @param options.locale {string}   active i18n language code
 * @param options.userName {string}   WebAuthn user name for the ceremony
 * @param options.promptForPrfRetry {function}   resolves the user's choice
 *   when the authenticator needs a second (assertion) ceremony for the PRF
 * @returns {Promise<{ session: Session }>}
 */
export async function signUpWithPasskey({
  email,
  locale,
  userName,
  promptForPrfRetry
}: {
  email?: string
  locale: string
  userName: string
  promptForPrfRetry: () => Promise<boolean>
}): Promise<{ session: Session }> {
  // The account's WebAuthn user id, minted once per account: every later
  // passkey registers under it, so authenticator pickers show one account.
  const userHandle = crypto.getRandomValues(new Uint8Array(16))
  if (WAS_SERVER_URL) {
    return signUpCredentialAnchoredWithPasskey({
      userHandle,
      email,
      locale,
      userName,
      promptForPrfRetry
    })
  }

  const { seed, userKey, webvhUpdateKeys, pointer } = await mintAccountKeySet()
  const { session } = await initSessionFromSeed({
    seed,
    userKey,
    webvhUpdateKeys,
    accountPointer: pointer,
    email,
    provisionStorage: false
  })

  // Register the passkey and bind its PRF output to the client key set
  // BEFORE creating the local collections: an account whose keyring failed
  // to publish must not be created. A brand-new wallet has no authenticator
  // credentials yet, so there is nothing to exclude.
  const { registration, entry, persistClientKeys } = await enrollPasskey({
    clientSeed: seed,
    userKey,
    webvhUpdateKeys,
    pointer,
    controller: session.user.id,
    userHandle,
    userName,
    locale,
    // Carried inside the wrapped record so any unlock method recovers the
    // account email.
    email,
    delegateManagementTo: session.user.id,
    promptForPrfRetry
  })
  session.profile.persistClientKeys = persistClientKeys

  // Provision collections, record the initial history, and seed the
  // welcome credential.
  await provisionNewWallet({ session })

  // Write the initial unlock-methods registry only now: it lives beside the
  // data collections `provisionNewWallet` just created. Non-fatal -- the
  // passkey already logs in. Read first: a registry that already exists
  // keeps its WebAuthn user id (the id is minted once per account -- a
  // re-minted one would register a second resident credential on the next
  // passkey add) and its other entries; the passkey entry is upserted into
  // it. Only a true absent mints the record from the user id registered
  // above. A THROWN read skips the write rather than starting from an empty
  // base, which would be the same clobber.
  try {
    await updateUnlockMethods({
      session,
      mutate: existing =>
        upsertPasskeyUnlockMethod({
          record: existing ?? {
            version: 1,
            webAuthnUserId: base64urlnopad.encode(userHandle),
            methods: []
          },
          entry
        })
    })
  } catch (err) {
    log.warn('Could not record the new passkey in the registry', { err })
  }

  // Mark this as a passkey-only account so the dashboard can prompt the
  // user to add a second unlock method. Non-fatal.
  try {
    await session.profile.persistence.passkeyNotices.save({
      controller: session.user.id,
      backupEligibility: registration.backupEligibility,
      backupState: registration.backupState
    })
  } catch (err) {
    log.warn('Could not save the passkey-safety notice', { err })
  }

  return { session }
}
