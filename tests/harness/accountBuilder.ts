/**
 * The account builder: the named account shapes the harness tests start
 * from, each produced through the real ceremonies against the in-process
 * server. Every shape starts as a credential-anchored passphrase signup
 * (`signUpWithPassphrase`, entered as a transient session) and adds one
 * thing through the entry point the app itself runs:
 *
 * - `buildPassphraseAccount`: nothing more.
 * - `buildPasskeyAccount`: a second standing credential, a test passkey
 *   added by the Settings ceremony `addAccountPasskey` from the signup's
 *   transient session, with `testAuthenticator` in place of WebAuthn.
 * - `buildRecoveryCodeAccount`: one recovery code, issued by
 *   `issueRecoveryCode` from the signup's transient session. The code is
 *   not spent.
 * - `buildEnrolledClientAccount`: one enrolled client, a remembered
 *   browser. A WAS deployment offers two entries that produce one: the
 *   self-enrollment of a `rememberBrowser: true` login on a profile holding
 *   no client-key record (`initSession.ts`, through
 *   `selfEnrollStandingClient`), and the two-party enrollment
 *   (`src/lib/enrollment.ts`). The builder uses the self-enrollment, a
 *   passphrase login on a fresh profile it returns.
 *
 * The builder leaves no actor live: every actor it opens is logged out
 * before it returns. A test continues with the secrets, the Space id, and
 * (for the enrolled client) the profile, through `harness.logIn`.
 *
 * `@interop/wallet-core/testing` builds the same four shapes through the
 * package's own ceremonies, and none of the shapes above builds through it.
 * That builder holds its unlock records in memory, derives a passphrase
 * under its fast KDF, and writes no registry record and no browser profile.
 * A login must find all of those, and each shape here exists to be logged
 * into:
 *
 * - The passphrase shape needs the unlock Space and unlock record the
 *   shipped KDF's unlock identity locates.
 * - The passkey shape needs a passkey's unlock record and its registry
 *   entry. The shared builder's second credential is a passphrase.
 * - The recovery code shape needs the recovery record the `/recover` locate
 *   step reads, and the registry entry naming the code.
 * - The enrolled client shape needs a browser profile holding the client-key
 *   record, and the client's `connections` entry.
 *
 * A test that only needs an account to exist on the server in a shape takes
 * `buildServerStateAccount`, which runs the shared builder against the
 * harness's server and returns its result. No `harness.logIn` enters such an
 * account. A test acts on it with what the result carries: the ladder seed,
 * the standing client, and the bridge and sibling delegations.
 *
 * Import this module statically: it loads the wallet modules only inside
 * the builders, after the harness has booted.
 */
import {
  createTestPasskey,
  testAuthenticator,
  type BrowserProfile,
  type TestPasskey,
  type WalletActor,
  type WalletHarness
} from './walletHarness'

/**
 * What every shape returns: the account Space id and the passphrase the
 * account was signed up with.
 */
export interface BuiltAccount {
  readonly spaceId: string
  readonly passphrase: string
}

/**
 * The passphrase shape plus a test passkey, a standing credential of the
 * account.
 */
export interface PasskeyAccount extends BuiltAccount {
  readonly passkey: TestPasskey
}

/**
 * The passphrase shape plus an issued, unspent recovery code, and its roster
 * kid as the registry entry records it.
 */
export interface RecoveryCodeAccount extends BuiltAccount {
  readonly recoveryCode: string
  readonly recoveryKid: string
}

/**
 * The passphrase shape plus one enrolled client: the browser profile that
 * holds its client-key record and replica, and its did:key (the remembered
 * session's `user.id`).
 */
export interface EnrolledClientAccount extends BuiltAccount {
  readonly enrolledProfile: BrowserProfile
  readonly enrolledClientDid: string
}

/**
 * A passphrase that no other account in the process uses: an unlock
 * credential locates its account by the passphrase alone.
 *
 * @returns {string}
 */
function uniquePassphrase(): string {
  return `harness-account-${crypto.randomUUID()}-Zz9!`
}

/**
 * Settles a visit the builder runs, refusing when any of its background work
 * failed: a shape built on a broken visit is not the shape its name claims.
 *
 * @param options {object}
 * @param options.actor {WalletActor}
 * @returns {Promise<void>}
 */
async function settleClean({ actor }: { actor: WalletActor }): Promise<void> {
  const { failures } = await actor.settled()
  if (failures.length > 0) {
    throw new Error(
      `The builder's visit "${actor.name}" settled with failed background ` +
        `work: ${failures.map(failure => failure.source).join(', ')}.`,
      { cause: failures }
    )
  }
}

/**
 * The signup every shape starts from, settled, with its actor still live.
 *
 * @param options {object}
 * @param options.harness {WalletHarness}
 * @param options.passphrase {string}
 * @returns {Promise<WalletActor>}
 */
async function settledSignup({
  harness,
  passphrase
}: {
  harness: WalletHarness
  passphrase: string
}): Promise<WalletActor> {
  const signup = await harness.signUp({ passphrase, name: 'builder signup' })
  await settleClean({ actor: signup })
  return signup
}

/**
 * A credential-anchored account with one passphrase.
 *
 * @param options {object}
 * @param options.harness {WalletHarness}
 * @param [options.passphrase] {string}   a unique one by default
 * @returns {Promise<BuiltAccount>}
 */
export async function buildPassphraseAccount({
  harness,
  passphrase = uniquePassphrase()
}: {
  harness: WalletHarness
  passphrase?: string
}): Promise<BuiltAccount> {
  const signup = await settledSignup({ harness, passphrase })
  await signup.logout()
  return { spaceId: signup.spaceId, passphrase }
}

/**
 * A credential-anchored account with a passphrase and a test passkey, the
 * passkey added by `addAccountPasskey` from the signup's transient session.
 *
 * @param options {object}
 * @param options.harness {WalletHarness}
 * @param [options.passphrase] {string}   a unique one by default
 * @returns {Promise<PasskeyAccount>}
 */
export async function buildPasskeyAccount({
  harness,
  passphrase = uniquePassphrase()
}: {
  harness: WalletHarness
  passphrase?: string
}): Promise<PasskeyAccount> {
  const signup = await settledSignup({ harness, passphrase })
  const { addAccountPasskey } = await import('@/session/accountSettings')
  const passkey = createTestPasskey()
  const { recorded } = await signup.run(session =>
    addAccountPasskey({
      session,
      locale: 'en',
      userName: 'harness',
      promptForPrfRetry: async () => true,
      register: testAuthenticator({ passkey })
    })
  )
  if (!recorded) {
    throw new Error('The passkey add left its registry entry incomplete.')
  }
  await signup.logout()
  return { spaceId: signup.spaceId, passphrase, passkey }
}

/**
 * A credential-anchored account with one recovery code issued by
 * `issueRecoveryCode` from the signup's transient session.
 *
 * @param options {object}
 * @param options.harness {WalletHarness}
 * @param [options.passphrase] {string}   a unique one by default
 * @returns {Promise<RecoveryCodeAccount>}
 */
export async function buildRecoveryCodeAccount({
  harness,
  passphrase = uniquePassphrase()
}: {
  harness: WalletHarness
  passphrase?: string
}): Promise<RecoveryCodeAccount> {
  const signup = await settledSignup({ harness, passphrase })
  const { generateRecoveryCode, issueRecoveryCode } =
    await import('@/session/recovery')
  const recoveryCode = generateRecoveryCode()
  const { entry } = await signup.run(session =>
    issueRecoveryCode({ session, code: recoveryCode, label: 'Harness code' })
  )
  await signup.logout()
  return {
    spaceId: signup.spaceId,
    passphrase,
    recoveryCode,
    recoveryKid: entry.recoveryKid
  }
}

/**
 * A credential-anchored account with one enrolled client: a
 * `rememberBrowser: true` passphrase login on a fresh profile, which
 * self-enrolls that profile.
 *
 * @param options {object}
 * @param options.harness {WalletHarness}
 * @param [options.passphrase] {string}   a unique one by default
 * @returns {Promise<EnrolledClientAccount>}
 */
export async function buildEnrolledClientAccount({
  harness,
  passphrase = uniquePassphrase()
}: {
  harness: WalletHarness
  passphrase?: string
}): Promise<EnrolledClientAccount> {
  const signup = await settledSignup({ harness, passphrase })
  await signup.logout()
  const enrolledProfile = harness.coldProfile({ name: 'enrolled client' })
  const enrollee = await harness.logIn({
    passphrase,
    profile: enrolledProfile,
    rememberBrowser: true,
    name: 'self-enrollment'
  })
  if (enrollee.kind !== 'remembered') {
    throw new Error('The self-enrolling login did not proceed remembered.')
  }
  await settleClean({ actor: enrollee })
  await enrollee.logout()
  return {
    spaceId: signup.spaceId,
    passphrase,
    enrolledProfile,
    enrolledClientDid: enrollee.session.user.id
  }
}

type SharedBuilder = typeof import('@interop/wallet-core/testing')

/**
 * The shared builder's shapes by name, each account existing as server-side
 * state alone.
 */
export interface ServerStateBuilders {
  passphrase: SharedBuilder['buildPassphraseAccount']
  'second-credential': SharedBuilder['buildSecondCredentialAccount']
  'recovery-code': SharedBuilder['buildRecoveryCodeAccount']
  'enrolled-client': SharedBuilder['buildEnrolledClientAccount']
}

/**
 * An account in a named shape, built by `@interop/wallet-core/testing`
 * against the harness's server. Only its server-side state exists: no unlock
 * Space, no registry record, and no browser profile, so no login finds it.
 *
 * @param options {object}
 * @param options.harness {WalletHarness}
 * @param options.shape {keyof ServerStateBuilders}
 * @param [options.passphrase] {string}   a unique one by default
 * @returns {Promise<object>}   the shared builder's result for the shape
 */
export async function buildServerStateAccount<
  Shape extends keyof ServerStateBuilders
>({
  harness,
  shape,
  passphrase
}: {
  harness: WalletHarness
  shape: Shape
  passphrase?: string
}): Promise<Awaited<ReturnType<ServerStateBuilders[Shape]>>> {
  const shared = await import('@interop/wallet-core/testing')
  const builders: ServerStateBuilders = {
    passphrase: shared.buildPassphraseAccount,
    'second-credential': shared.buildSecondCredentialAccount,
    'recovery-code': shared.buildRecoveryCodeAccount,
    'enrolled-client': shared.buildEnrolledClientAccount
  }
  const account = await builders[shape]({
    baseServerUrl: harness.serverUrl,
    ...(passphrase === undefined ? {} : { passphrase })
  })
  return account as Awaited<ReturnType<ServerStateBuilders[Shape]>>
}

/**
 * The torn state of an account left pointing at a deleted annex generation:
 * the collection the document's `#DelegatedClients` pointer names is deleted
 * by a live remembered actor, which root-invokes the auxiliary Space, the
 * way a stale GC pass collects it. The actor stays live.
 *
 * @param options {object}
 * @param options.actor {WalletActor}   a remembered actor on the account
 * @returns {Promise<void>}
 */
export async function deletePointedGeneration({
  actor
}: {
  actor: WalletActor
}): Promise<void> {
  const { pointedClientAnnexReach } = await import('@/session/annexReach')
  await actor.run(async session => {
    const pointer = session.profile.accountPointer
    if (!pointer?.did) {
      throw new Error('The session carries no promoted account pointer.')
    }
    const reach = await pointedClientAnnexReach({
      session,
      pointer: { ...pointer, did: pointer.did }
    })
    await reach!.was
      .space(reach!.spaceId)
      .collection(reach!.generationId)
      .delete()
  })
}
