/**
 * New-wallet provisioning sequence, shared by the signup and guest flows.
 *
 * Both create a brand-new wallet identity and then run the exact same ordered
 * sequence: provision the collections (locally always, and on the remote WAS
 * Space when one is configured), record the initial account + space-created
 * history, and seed the wallet with a welcome credential. This is business
 * logic (no React), so it lives here rather than being pasted into each page.
 *
 * Ordering matters and is deliberate: `ensureUserCollections` must run first so
 * there is somewhere to write to before the history entries and the welcome
 * credential. Signup additionally binds the passphrase to the data seed
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

/**
 * Provisions a freshly created wallet: collections, initial history, and the
 * welcome credential. `addHistorySpaceCreated` is called unconditionally --
 * with no remote store (a guest) it records the local-collections variant, so
 * it is not gated on remote storage.
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

  // Seed the wallet with a welcome credential. `addCredential` records its own
  // credential-created history entry, so this must not log one separately.
  await storage.addCredential({ credential: welcomeCredential, user })
}
