/**
 * The two new-account provisioning sequences behind the signup page: one for a
 * passkey account, one for a passphrase account. Both mint this client's key
 * set locally, bind it under the chosen unlock secret BEFORE any data Space
 * exists, provision the wallet, and only then backfill the published did:webvh
 * into the account pointer and promote the Space controller onto it. The page
 * keeps the wizard state and the error copy; the orderings live here.
 */
import { base64urlnopad } from '@scure/base'
import { KEYRING_KDF, type AccountPointer } from '@interop/wallet-core/keyring'
import { mintAccountKeySet as mintSharedAccountKeySet } from '@interop/wallet-core/genesis'
import { generateLadderSeed } from '@interop/wallet-core/clientAnnex'
import { PASSKEY_KDF, WAS_SERVER_URL } from '@/app.config'
import { initSessionFromSeed, loginWithPassphrase } from '@/session/initSession'
import {
  bindPassphrase,
  bindUnlockSecret,
  deriveUnlockCredential,
  fetchTransientKeyring,
  unlockManagementGrantee
} from '@/session/keyring'
import { establishCredentialAnchoredAccount } from '@/session/credentialAnchoredGenesis'
import { transientSessionPersistence } from '@/session/persistence'
import { transientSessionFromKeyringHit } from '@/session/transientLogin'
import { provisionNewWallet } from '@/session/provisionNewWallet'
import {
  establishPassphraseStanding,
  establishStandingUnlock
} from '@/session/standingUnlock'
import {
  emptyUnlockMethodsRegistry,
  enrollPasskey,
  updateUnlockMethods,
  updateUnlockMethodsWithClient,
  upsertPasskeyUnlockMethod,
  upsertPassphraseUnlockMethod
} from '@/session/unlockMethods'
import { mintSpaceId } from '@/stores/wasRemoteStore'
import type { Session } from '@/types/auth'

/**
 * This client's freshly minted key set for a brand-new account: the client
 * seed (random, local, never derived from any secret and never leaving the
 * browser), the account's user key (its roster identity -- recipient zero of every
 * encrypted collection, cached locally under the unlock layer), this client's
 * did:webvh update-key seeds (the identity log can only ever be extended with
 * client-held keys), and the account pointer the keyring record carries in
 * place of the retired data seed: where the account lives. The Space id is an
 * independent random identifier minted here (nothing about the account derives
 * from any key); the did:webvh half is backfilled after provisioning publishes
 * it. Built before session creation so the storage clients bind to the minted
 * id.
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
 * The tail both signup sequences share: provisioning has published the
 * did:webvh id, so it is backfilled into the account pointer (the keyring
 * record and the local pin) by re-binding under the unlock secret still in
 * hand, and THEN the Space controller is promoted onto it. The order is
 * load-bearing: the pointer must durably name the did before the promotion
 * PUT, since the pointer is what tells the next login to sign under the
 * promoted keyId (a tear between the two is healed at the next login).
 * Best-effort -- the pointer's spaceId + host already locate the account.
 *
 * Only the re-bind differs between the two (a passphrase bind, or a passkey
 * PRF bind that also re-delegates its management zcap), so the caller passes
 * it in.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.pointer] {AccountPointer}   the pre-backfill pointer
 * @param options.rebind {function}   re-binds the unlock record to the
 *   did-carrying pointer
 * @returns {Promise<void>}
 */
async function backfillPointerAndPromote({
  session,
  pointer,
  rebind
}: {
  session: Session
  pointer?: AccountPointer
  rebind: (fullPointer: AccountPointer & { did: string }) => Promise<void>
}): Promise<void> {
  session.profile.accountPointer = pointer
  if (!pointer || !session.profile.didWebvh) {
    return
  }
  const fullPointer = { ...pointer, did: session.profile.didWebvh.did }
  try {
    await rebind(fullPointer)
    session.profile.accountPointer = fullPointer
    await session.storage.ensurePromotedController({
      profile: session.profile
    })
  } catch (err) {
    console.warn(
      'Could not backfill the did:webvh and promote the controller:',
      err
    )
  }
}

/**
 * The CREDENTIAL-ANCHORED signup: the default on a non-remembered browser with
 * a WAS server configured. No durable client is minted anywhere -- the whole
 * establishment (`establishCredentialAnchoredAccount`) is anchored on the
 * passphrase's ladder, and the visit then enters the account through the
 * ordinary transient composition, leaving zero local residue.
 *
 * Ordering matches the durable flavor's spirit: the account is probed first
 * (a create-nothing transient record fetch -- the durable probe would
 * self-enroll this browser), and the record carrying the ladder seed is
 * durably written before anything else exists (inside the establishment).
 * The registry entry rides the establishment's pre-promotion window.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param [options.email] {string}
 * @returns {Promise<{ session?: Session, userExists: boolean }>}
 */
async function signUpCredentialAnchoredWithPassphrase({
  passphrase,
  email
}: {
  passphrase: string
  email?: string
}): Promise<{ session?: Session; userExists: boolean }> {
  const persistence = transientSessionPersistence()
  // One 600k-iteration derivation for the whole signup.
  const credential = await deriveUnlockCredential({
    secret: passphrase,
    kdf: KEYRING_KDF
  })
  const probe = await fetchTransientKeyring({
    credential,
    accountLogPinStore: persistence.logPins
  })
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
    persistence,
    beforePromotion: async ({ zcapClient, userKey, establishment }) => {
      // The registry entry, in the last root-invocation window. Best-effort
      // by the hook's contract: a miss is re-recordable later, never fatal.
      // Read first (the compare-and-swap wrapper's own fresh read): the
      // transient login's heal branch re-runs the whole establishment, and
      // a re-fired hook starting from a fresh registry would clobber the
      // first run's record (its user handle re-minted, every other entry
      // dropped). Only a true absent starts fresh. A THROWN read or write
      // -- the bootstrap-signed read refused against an account a
      // concurrent run already promoted, say -- skips with a report: a
      // write on an empty base there would be the same clobber, and the
      // miss stays re-recordable by the later recorders.
      try {
        await updateUnlockMethodsWithClient({
          zcapClient,
          spaceId,
          userKey,
          mutate: existing =>
            upsertPassphraseUnlockMethod({
              record: existing ?? emptyUnlockMethodsRegistry(),
              unlockSpaceId: establishment.unlockSpaceId,
              manageCapability: establishment.manageCapability,
              standing: establishment.standingFields
            })
        })
      } catch (err) {
        console.warn(
          'Could not update the unlock-methods registry at signup; ' +
            'skipping the passphrase entry (re-recordable at the next ' +
            'durable login):',
          err
        )
      }
    }
  })

  // Enter the account exactly as any later public-terminal login would: the
  // ordinary transient composition over the record just established.
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
    persistence
  })
  return { session, userExists: false }
}

/**
 * Creates a new wallet under a passphrase, or reports that this passphrase
 * already has one.
 *
 * Durability routing mirrors the login's: on a non-remembered browser with a
 * WAS server configured the signup is CREDENTIAL-ANCHORED (ladder-anchored
 * genesis, transient session, zero local residue); an explicit
 * `rememberBrowser: true` -- the programmatic remember-this-browser entry
 * (the e2e seam today, the signup form's checkbox when it lands) -- and every
 * no-WAS deployment run the durable flow below.
 *
 * Durable ordering: the account is probed first -- resolving the passphrase
 * through the keyring and reading `userExists` is what prevents a re-signup
 * with an existing passphrase from overwriting that account's keyring and
 * orphaning the wallet (the probe session is discarded, so it must not
 * provision). The passphrase is then bound to this client's key set BEFORE
 * the data Space is created: an account whose keyring failed to publish must
 * not be created, and binding first means a failed signup leaves no orphaned
 * data Space behind. The pointer backfill and the controller promotion come
 * last, in that order.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param [options.email] {string}
 * @param [options.rememberBrowser] {boolean}   `true` forces the durable
 *   flow; absent or `false`, a WAS-configured signup runs credential-anchored
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
  if (WAS_SERVER_URL && rememberBrowser !== true) {
    return signUpCredentialAnchoredWithPassphrase({ passphrase, email })
  }
  // Probe for an existing account first. loginWithPassphrase resolves the
  // passphrase through the keyring and reports whether this identity already
  // has a wallet; probing (rather than binding a raw seed straight away) is
  // what prevents a re-signup with an existing passphrase from overwriting
  // that account's keyring and orphaning the wallet. The probe session is
  // discarded after reading `userExists`, so it must not provision.
  // One 600k-iteration derivation for the whole signup: the probe login, the
  // bind, and the pointer-backfill re-bind all run on this identity.
  const credential = await deriveUnlockCredential({
    secret: passphrase,
    kdf: KEYRING_KDF
  })
  // Signup stays durable: the probe forces the durable route so a cold
  // browser re-signing-up with an existing standing passphrase behaves as
  // before (locates the account, never starts a transient ceremony).
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

  await backfillPointerAndPromote({
    session,
    pointer,
    rebind: async fullPointer => {
      await bindPassphrase({
        clientSeed: seed,
        controller: session.user.id,
        passphrase,
        email,
        userKey,
        webvhUpdateKeys,
        pointer: fullPointer,
        credential
      })
    }
  })

  // Make the passphrase a STANDING credential (roster wrap, document entry,
  // bridge delegation, standing-layout record) and record its standing configuration in the
  // registry. Best-effort like the backfill above: a failure leaves the
  // record in the plain layout, which logs in normally and falls back to the
  // connect-another-wallet ceremony on a fresh browser.
  await establishPassphraseStanding({ session, passphrase, email, credential })

  return { session, userExists: false }
}

/**
 * Creates a new wallet under a passkey.
 *
 * Ordering: the passkey is registered and its PRF output bound to this
 * client's key set BEFORE the data Space is created (a failed signup leaves no
 * orphaned Space); provisioning follows; the pointer backfill precedes the
 * controller promotion; and the unlock-methods registry is written only after
 * provisioning, since it lives in the data Space that provisioning creates.
 * There is no `userExists` probe -- a fresh credential cannot collide with an
 * existing account, so there is nothing to probe.
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
  // No `userExists` probe: a fresh credential cannot collide with an
  // existing account, so there is nothing to probe (unlike the
  // passphrase path).
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
  // BEFORE creating the data Space: an account whose keyring failed to
  // publish must not be created, and binding first means a failed signup
  // leaves no orphaned data Space behind. A brand-new wallet has no
  // authenticator credentials yet, so there is nothing to exclude.
  // Delegating this passkey's unlock Space management zcap to the
  // account identity keeps a lost passkey revocable tap-free from
  // Settings.
  const userHandle = crypto.getRandomValues(new Uint8Array(16))
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

  // The re-bind runs with the PRF output still in hand -- no second
  // ceremony -- and also re-delegates the management zcap to the
  // just-published did:webvh, so the passkey entry recorded below is
  // revocable from ANY enrolled client (the pre-promotion delegation named
  // this first client's did:key alone).
  await backfillPointerAndPromote({
    session,
    pointer,
    rebind: async fullPointer => {
      const { manageCapability } = await bindUnlockSecret({
        clientSeed: seed,
        controller: session.user.id,
        secret: registration.prfOutput,
        kdf: PASSKEY_KDF,
        email,
        userKey,
        webvhUpdateKeys,
        pointer: fullPointer,
        delegateManagementTo: unlockManagementGrantee({
          pointer: fullPointer,
          controller: session.user.id
        })
      })
      if (manageCapability) {
        entry.manageCapability = manageCapability
      }
    }
  })

  // Make the passkey a STANDING credential (roster wrap, verbatim document
  // entry -- the PRF output is high-entropy -- bridge delegation,
  // standing-layout record), with the PRF output still in hand. Best-effort:
  // a failure leaves the plain-layout record from the rebind above, which
  // logs in normally and falls back to the connect ceremony on a fresh
  // browser.
  try {
    const established = await establishStandingUnlock({
      session,
      secret: registration.prfOutput,
      kdf: PASSKEY_KDF,
      lowEntropy: false,
      email
    })
    session.profile.persistClientKeys = established.persistClientKeys
    if (established.manageCapability) {
      entry.manageCapability = established.manageCapability
    }
    Object.assign(entry, established.standingFields)
  } catch (err) {
    console.warn(
      'Could not establish the passkey as a standing credential; a fresh ' +
        'browser will need the connect-another-wallet ceremony:',
      err
    )
  }

  // Write the initial unlock-methods registry only now: it lives in the
  // data Space, which `provisionNewWallet` just created, so this must run
  // after provisioning (the registry write needs the Space to exist).
  // Non-fatal -- the passkey already logs in. Read first: a registry that
  // already exists keeps its user handle (the handle is minted once per
  // account -- a re-minted one would register a second resident credential
  // on the next passkey add) and its other entries; the passkey entry is
  // upserted into it. Only a true absent mints the record from the handle
  // registered above. A THROWN read skips the write rather than starting
  // from an empty base, which would be the same clobber.
  try {
    await updateUnlockMethods({
      session,
      mutate: existing =>
        upsertPasskeyUnlockMethod({
          record: existing ?? {
            version: 1,
            userHandle: base64urlnopad.encode(userHandle),
            methods: []
          },
          entry
        })
    })
  } catch (err) {
    console.warn('Could not record the new passkey in the registry:', err)
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
    console.warn('Could not save the passkey-safety notice:', err)
  }

  return { session }
}
