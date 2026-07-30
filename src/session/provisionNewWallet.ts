/**
 * New-wallet provisioning sequence, shared by the signup and guest flows.
 *
 * Both create a brand-new wallet identity and then run the exact same ordered
 * sequence: provision the collections (locally always, and on the remote WAS
 * Space when one is configured), record the initial account + space-created
 * history, and seed the wallet with default contacts and a welcome credential.
 * This is business logic (no React), so it lives here rather than being pasted
 * into each page.
 *
 * Ordering matters and is deliberate: `ensureUserCollections` must run first so
 * there is somewhere to write to before the history entries and the seeded
 * contacts/credential, and so the self-contact can carry the did:web/did:webvh
 * DIDs it mints. Signup additionally binds the passphrase to the data seed
 * *before* calling this (so a data Space is never created for an account whose
 * keyring failed to publish); that bind stays in the page, since it needs the
 * passphrase this helper never sees.
 *
 * The steps run sequentially and are not transactional: a failure part-way
 * through (e.g. after the Space exists but before the welcome credential is
 * written) leaves the wallet partially provisioned. That residual edge is
 * accepted -- the next full login re-runs the idempotent `ensureUserCollections`
 * and the wallet remains usable.
 */
import type { Session } from '@/types/auth'
import { welcomeCredential } from '@/fixtures/welcomeCredential'
import {
  interopAllianceTeamContact,
  selfContact
} from '@/fixtures/defaultContacts'

/**
 * Provisions a freshly created wallet: collections, initial history, default
 * contacts, and the welcome credential. `addHistorySpaceCreated` is called
 * unconditionally -- with no remote store (a guest) it records the
 * local-collections variant, so it is not gated on remote storage.
 *
 * @param options {object}
 * @param options.session {Session}   the freshly created full session
 * @returns {Promise<void>}
 */
export async function provisionNewWallet({
  session
}: {
  session: Session
}): Promise<void> {
  const { storage, user, profile } = session

  // Create the Space (remote) and open/init the collections (local always).
  await storage.ensureUserCollections({ user, profile })

  // Now that there is somewhere to write to, start the history.
  await storage.addHistoryNewAccount({ user })
  await storage.addHistorySpaceCreated({ user })

  // Seed the default contacts: the Interop Alliance Team, and a self-contact
  // carrying the did:web/did:webvh DIDs `ensureUserCollections` minted above
  // (absent for guests, without a KMS/WAS server, or if provisioning failed)
  // plus the signup email, when one was entered. `session.isGuest` gates the
  // email: a guest's `user.email` is an internal placeholder (see
  // `initGuestSession`), never something the user typed, so it must not leak
  // into the contact.
  await storage.addContact({ contact: interopAllianceTeamContact })
  await storage.addContact({
    contact: selfContact({
      didWeb: profile.didWeb?.did,
      didWebvh: profile.didWebvh?.did,
      email: session.isGuest ? undefined : user.email
    })
  })

  // Seed the wallet with a welcome credential. `addCredential` records its own
  // credential-created history entry, so this must not log one separately.
  await storage.addCredential({ credential: welcomeCredential, user })
}
