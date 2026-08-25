/**
 * New-wallet provisioning sequence, shared by the guest flow and the no-WAS
 * signup (a WAS signup runs the credential-anchored establishment instead
 * and seeds its welcome content through `seedWelcomeContent` below).
 *
 * Both callers create a brand-new wallet identity and then run the exact same
 * ordered sequence: provision the collections (local, plus the remote Space
 * where one applies), record the initial account + space-created history, and
 * seed the wallet with default contacts and a welcome credential. This is
 * business logic (no React), so it lives here rather than being pasted into
 * each page.
 *
 * Ordering matters and is deliberate: `ensureUserCollections` must run first so
 * there is somewhere to write to before the history entries and the seeded
 * contacts/credential, and so the self-contact can carry the did:web/did:webvh
 * DIDs it mints. The no-WAS signup additionally binds the passphrase *before*
 * calling this (an account whose keyring failed to publish must not be
 * created); that bind stays with the caller, since it needs the passphrase
 * this helper never sees.
 *
 * The steps run sequentially and are not transactional: a failure part-way
 * through (e.g. after the collections exist but before the welcome credential
 * is written) leaves the wallet partially provisioned. That residual edge is
 * accepted -- the next full login re-runs the idempotent `ensureUserCollections`
 * and the wallet remains usable.
 */
import { setClientLabel } from '@interop/wallet-core/keys'
import { clientSigningKeyMultibase } from '@interop/wallet-core/webvh'
import { selfContact } from '@interop/social-core'
import { DEFAULT_CLIENT_LABEL } from '@/app.config'
import type { Session } from '@/types/auth'
import { welcomeCredential } from '@/fixtures/welcomeCredential'
import { interopAllianceTeamContact } from '@/fixtures/defaultContacts'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:provision')

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

  // Label the first enrolled client. Every later client gets its label at
  // enrollment approval; this one has no approving screen, so the wallet
  // names itself in `key-map/client-labels.json` (the Connected wallets
  // panel would otherwise show "Unnamed wallet"). Only a did:webvh account
  // has that panel, and only a remote store has somewhere to write the
  // label; best-effort either way.
  if (
    storage.remoteStore &&
    !session.isGuest &&
    profile.didWebvh &&
    profile.keyAgent
  ) {
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

  // Now that there is somewhere to write to, start the history. The two
  // records are independent, so they are written together.
  await Promise.all([
    storage.addHistoryNewAccount({ user }),
    storage.addHistorySpaceCreated({ user })
  ])

  // Seed the default contacts: the Interop Alliance Team, and a self-contact
  // carrying the did:web/did:webvh DIDs `ensureUserCollections` minted above
  // (absent for guests, without a KMS/WAS server, or if provisioning failed)
  // plus the signup email, when one was entered. `session.isGuest` gates the
  // email: a guest's `user.email` is an internal placeholder (see
  // `initGuestSession`), never something the user typed, so it must not leak
  // into the contact.
  // Seeded contacts are decorative, so a failure here is logged and stepped
  // over rather than failing provisioning and leaving the wallet without its
  // welcome credential (and, on the signup path, without the unlock-methods
  // entry the page writes after this returns).
  try {
    await Promise.all([
      storage.addContact({ contact: interopAllianceTeamContact }),
      storage.addContact({
        contact: selfContact({
          dids: [profile.didWeb?.did, profile.didWebvh?.did].filter(
            (did): did is string => Boolean(did)
          ),
          ...(session.isGuest ? {} : { email: user.email })
        })
      })
    ])
  } catch (err) {
    log.warn('Could not seed the default contacts', { err })
  }

  // Seed the wallet with a welcome credential. `addCredential` records its own
  // credential-created history entry, so this must not log one separately.
  await storage.addCredential({ credential: welcomeCredential, user })
}

/**
 * How long the signup tail waits for the welcome seed before proceeding
 * without it: the seed sits on the signup's critical path, and a hung
 * request (a captive portal, a stalled server) never rejects, so it must
 * not be able to hang the spinner on an already-established account.
 */
const SEED_WELCOME_TIMEOUT_MS = 15_000

/**
 * Best-effort welcome-content seeding for the WAS signup tails: the welcome
 * credential and the two new-account history records, written through the
 * session's own storage (the replica-less remote-direct variant a transient
 * session carries, or the durable replica of a remembered/passkey signup's
 * self-enrolled session). The two contact seeds wait for FW-210's
 * remote-direct contact operations; the first-client label, where one
 * applies, is the durable tail's own write. The whole function is
 * best-effort: the account is fully established before it runs, so a torn
 * seed costs only cosmetic content -- a failure is logged and never
 * rethrown, and a seed still pending after `SEED_WELCOME_TIMEOUT_MS` is
 * stepped past the same way. This helper is not an ensure (the history
 * writes mint fresh ids per call, with no completion detection), so it must
 * stay on the fresh-signup tails (each entered once per new account) and
 * must not migrate into `establishCredentialAnchoredAccount` or any
 * heal/re-run path.
 *
 * @param options {object}
 * @param options.session {Session}   the composed transient session
 * @returns {Promise<void>}
 */
export async function seedWelcomeContent({
  session
}: {
  session: Session
}): Promise<void> {
  const { storage, user } = session
  // Attribute the seeds to the account's own identity: on a transient
  // session `user.id` is the per-visit ephemeral key (GC'd with its annex
  // generation, never an account identity), and `accountController` is the
  // record's bound controller -- on a credential-anchored account the ladder
  // VM's bootstrap did:key, retired at the first self-enrollment. The
  // account pointer's did:webvh is the identity that outlives both.
  const seedUser = {
    ...user,
    id:
      session.profile.accountPointer?.did ??
      session.profile.accountController ??
      user.id
  }
  // The catch stays attached to the seeding promise itself, so a rejection
  // arriving after the timeout has won cannot become unhandled.
  const seeding = (async () => {
    // The two records are independent, so they are written together.
    await Promise.all([
      storage.addHistoryNewAccount({ user: seedUser }),
      storage.addHistorySpaceCreated({ user: seedUser })
    ])
    // `addCredential` records its own credential-created history entry, so
    // this must not log one separately.
    await storage.addCredential({
      credential: welcomeCredential,
      user: seedUser
    })
  })().catch(err => {
    log.warn('Could not seed the welcome content', { err })
  })
  let timer: ReturnType<typeof setTimeout> | undefined
  const timedOut = await Promise.race([
    seeding.then(() => false),
    new Promise<boolean>(resolve => {
      timer = setTimeout(() => resolve(true), SEED_WELCOME_TIMEOUT_MS)
    })
  ])
  clearTimeout(timer)
  if (timedOut) {
    log.warn('Could not seed the welcome content: timed out', {
      timeoutMs: SEED_WELCOME_TIMEOUT_MS
    })
  }
}
