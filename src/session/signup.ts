/**
 * The two new-account provisioning sequences behind the signup page: one for a
 * passkey account, one for a passphrase account. Both mint this client's key
 * set locally, bind it under the chosen unlock secret BEFORE any data Space
 * exists, provision the wallet, and only then backfill the published did:webvh
 * into the account pointer and promote the Space controller onto it. The page
 * keeps the wizard state and the error copy; the orderings live here.
 */
import { base64urlnopad } from '@scure/base'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import { mintClientWebvhUpdateKeys } from '@interop/wallet-core/webvh'
import { mintPuk } from '@interop/wallet-core/keys'
import { PASSKEY_KDF, WAS_SERVER_URL } from '@/app.config'
import { savePasskeySafetyNotice } from '@/lib/sessionKey'
import { mintSpaceId } from '@/stores/wasRemoteStore'
import { initSessionFromSeed, loginWithPassphrase } from '@/session/initSession'
import {
  bindPassphrase,
  bindUnlockSecret,
  unlockManagementGrantee
} from '@/session/keyring'
import { provisionNewWallet } from '@/session/provisionNewWallet'
import {
  enrollPasskey,
  putUnlockMethods,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import type { Session } from '@/types/auth'

/**
 * This client's freshly minted key set for a brand-new account: the client
 * seed (random, local, never derived from any secret and never leaving the
 * browser), the account's PUK (its roster identity -- recipient zero of every
 * encrypted collection, cached locally under the unlock layer), this client's
 * did:webvh update-key seeds (the identity log can only ever be extended with
 * client-held keys), and the account pointer the keyring record carries in
 * place of the retired data seed: where the account lives. The Space id is an
 * independent random identifier minted here (nothing about the account derives
 * from any key); the did:webvh half is backfilled after provisioning publishes
 * it. Built before session creation so the storage clients bind to the minted
 * id.
 *
 * @returns {Promise<{ seed: Uint8Array, puk: object, webvhUpdateKeys: object,
 *   pointer?: AccountPointer }>}
 */
async function mintAccountKeySet() {
  const seed = crypto.getRandomValues(new Uint8Array(32))
  const puk = await mintPuk()
  const webvhUpdateKeys = await mintClientWebvhUpdateKeys()
  const pointer: AccountPointer | undefined = WAS_SERVER_URL
    ? { spaceId: mintSpaceId(), host: WAS_SERVER_URL }
    : undefined
  return { seed, puk, webvhUpdateKeys, pointer }
}

/**
 * Creates a new wallet under a passphrase, or reports that this passphrase
 * already has one.
 *
 * Ordering: the account is probed first -- resolving the passphrase through
 * the keyring and reading `userExists` is what prevents a re-signup with an
 * existing passphrase from overwriting that account's keyring and orphaning
 * the wallet (the probe session is discarded, so it must not provision). The
 * passphrase is then bound to this client's key set BEFORE the data Space is
 * created: an account whose keyring failed to publish must not be created, and
 * binding first means a failed signup leaves no orphaned data Space behind.
 * The pointer backfill and the controller promotion come last, in that order.
 *
 * @param options {object}
 * @param options.passphrase {string}
 * @param [options.email] {string}
 * @returns {Promise<{ session?: Session, userExists: boolean }>}
 */
export async function signUpWithPassphrase({
  passphrase,
  email
}: {
  passphrase: string
  email?: string
}): Promise<{ session?: Session; userExists: boolean }> {
  // Probe for an existing account first. loginWithPassphrase resolves the
  // passphrase through the keyring and reports whether this identity already
  // has a wallet; probing (rather than binding a raw seed straight away) is
  // what prevents a re-signup with an existing passphrase from overwriting
  // that account's keyring and orphaning the wallet. The probe session is
  // discarded after reading `userExists`, so it must not provision.
  const probe = await loginWithPassphrase({
    passphrase,
    email,
    provisionStorage: false
  })
  if (probe.userExists) {
    return { userExists: true }
  }

  // This is a new user. Session creation does not provision
  // (`provisionStorage: false`); `provisionNewWallet` runs the ordered
  // provisioning sequence only after the bind succeeds.
  const { seed, puk, webvhUpdateKeys, pointer } = await mintAccountKeySet()
  const { session } = await initSessionFromSeed({
    seed,
    puk,
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
    puk,
    webvhUpdateKeys,
    pointer
  })
  session.profile.persistClientKeys = persistClientKeys

  // Provision collections, record the initial history, and seed the
  // welcome credential.
  await provisionNewWallet({ session })

  // Provisioning published the did:webvh id; backfill it into the account
  // pointer (the record and the local pin) with a re-bind, and THEN
  // promote the Space controller to the did:webvh: the pointer must
  // durably name the did before the promotion PUT, since the pointer is
  // what tells the next login to sign under the promoted keyId (a tear
  // between the two is healed at the next login). Best-effort: the
  // pointer's spaceId + host already locate the account.
  session.profile.accountPointer = pointer
  if (pointer && session.profile.didWebvh) {
    const fullPointer = { ...pointer, did: session.profile.didWebvh.did }
    try {
      await bindPassphrase({
        clientSeed: seed,
        controller: session.user.id,
        passphrase,
        email,
        puk,
        webvhUpdateKeys,
        pointer: fullPointer
      })
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
  const { seed, puk, webvhUpdateKeys, pointer } = await mintAccountKeySet()
  const { session } = await initSessionFromSeed({
    seed,
    puk,
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
    puk,
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

  // Provisioning published the did:webvh id; backfill it into the
  // account pointer (the record and the local pin) by re-binding with
  // the PRF output still in hand -- no second ceremony, and THEN
  // promote the Space controller to the did:webvh: the pointer must
  // durably name the did before the promotion PUT, since the pointer
  // is what tells the next login to sign under the promoted keyId (a
  // tear between the two is healed at the next login). Best-effort:
  // the pointer's spaceId + host already locate the account.
  session.profile.accountPointer = pointer
  if (pointer && session.profile.didWebvh) {
    const fullPointer = { ...pointer, did: session.profile.didWebvh.did }
    try {
      // The re-bind also re-delegates the management zcap to the
      // just-published did:webvh, so the passkey entry recorded below
      // is revocable from ANY enrolled client (the pre-promotion
      // delegation named this first client's did:key alone).
      const { manageCapability } = await bindUnlockSecret({
        clientSeed: seed,
        controller: session.user.id,
        secret: registration.prfOutput,
        kdf: PASSKEY_KDF,
        email,
        puk,
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

  // Write the initial unlock-methods registry only now: it lives in the
  // data Space, which `provisionNewWallet` just created, so this must run
  // after provisioning (`putUnlockMethods` needs the Space to exist).
  // Non-fatal -- the passkey already logs in.
  const record: UnlockMethodsRecord = {
    version: 1,
    userHandle: base64urlnopad.encode(userHandle),
    methods: [entry]
  }
  try {
    await putUnlockMethods({ session, record })
  } catch (err) {
    console.warn('Could not record the new passkey in the registry:', err)
  }

  // Mark this as a passkey-only account so the dashboard can prompt the
  // user to add a second unlock method. Non-fatal.
  try {
    await savePasskeySafetyNotice({
      controller: session.user.id,
      backupEligibility: registration.backupEligibility,
      backupState: registration.backupState
    })
  } catch (err) {
    console.warn('Could not save the passkey-safety notice:', err)
  }

  return { session }
}
