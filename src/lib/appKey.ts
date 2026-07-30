/**
 * The App Connect app-key credential: a self-issued VC that carries a 32-byte
 * seed an app keeps in the user's wallet so it can open its encrypted data on
 * this and other devices. Unlike the Login Credential, the issuer and subject
 * are NOT the wallet user's did:key -- they are a did:key derived from the seed
 * itself (self-issued by the app key), so the credential validates standalone
 * and the same seed reconstitutes the same identity on every device. The
 * credential is bound to the CHAPI requesting origin (`credentialSubject.origin`)
 * and matched wallet-side against that origin, so a phishing origin can neither
 * recover an existing app key nor be handed one minted for another origin.
 *
 * The minted credential is byte-for-byte the shape `@interop/was-react`'s
 * `parseSeedCredential` accepts: an inline seed `@context` (the shared
 * `urn:was:` terms plus the app's own type term under its `vocabBase`, no
 * hosted context or document-loader changes), a `name`/`description` pair, and
 * a seed encoded as base64url without padding. It is a VC 1.0 credential
 * signed with the wallet default suite (`Ed25519Signature2020`); `vc.issue`
 * auto-fills `issuanceDate`.
 *
 * Every app key also carries the shared `AppKeyCredential` marker type, which
 * is what makes a store-time refusal of a foreign app key possible
 * ({@link assertStorableAppKey}).
 */
import * as vc from '@interop/vc'
import { base64urlnopad } from '@scure/base'
import { CapabilityAgent } from '@interop/webkms-client'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { StoredCredential } from '@/types/credential'
import type { IAppConnectApp } from '@/lib/walletRequest'
import { documentLoader } from '@/lib/walletRequest/composeVP'
import { issuerId, subjectId, typeArray } from '@/lib/vcShape'

/**
 * The app identity an App Connect request presents (display `name`, plus the
 * `credentialType` / `vocabBase` that parameterize the app-key credential).
 * Re-exported so callers importing the appKey module get the type alongside it.
 */
export type AppConnectApp = IAppConnectApp

/**
 * The semantic `handle` mixed into seed derivation. It identifies the agent but
 * does not affect the derived key (the seed already encodes it), so it is
 * cosmetic; kept in sync with was-react's `deriveIdentity` for legibility.
 */
export const APP_KEY_HANDLE = 'freewallet-app-key'

/**
 * The key name mixed into seed derivation. Unlike the handle this is
 * load-bearing: it is the HMAC message in `CapabilityAgent` derivation, so the
 * exact string must match was-react's `deriveIdentity` for the derived did:key
 * to agree.
 */
export const APP_KEY_KEY_NAME = 'app-key'

const VC_1_CONTEXT_URL = 'https://www.w3.org/2018/credentials/v1'

/**
 * The marker type every minted app key carries alongside the app's own
 * `credentialType`, mapped to one stable IRI for every app (NOT interpolated
 * from an app's `vocabBase`). It makes "presents as an app key" a term check
 * rather than a shape heuristic, which is what the store-time refusal
 * ({@link assertStorableAppKey}) and the match path key off.
 *
 * It is a self-declaration, not evidence: the `type` array of a planted
 * credential is attacker-controlled like the rest of it. The marker makes the
 * rule precise; the seed-to-subject binding ({@link appKeySeedBindsSubject})
 * remains the only thing that authenticates.
 */
export const APP_KEY_CREDENTIAL_TYPE = 'AppKeyCredential'

const APP_KEY_CREDENTIAL_TYPE_IRI = 'urn:was:AppKeyCredential'

/**
 * The number of random bytes in an app-key seed.
 */
const SEED_BYTE_LENGTH = 32

/**
 * Builds the inline JSON-LD context object appended after the VC 1.0 context.
 * The marker type and the `seed` / `origin` claims carry shared `urn:was:`
 * IRIs -- they mean the same thing for every app, so they do not belong under
 * a per-app `vocabBase`, which keeps only the app's own type term. Still
 * interpolated (not constant) because that one term varies per app.
 *
 * @param options {object}
 * @param options.vocabBase {string}
 * @param options.credentialType {string}
 * @returns {Record<string, unknown>}
 */
function appKeyContext({
  vocabBase,
  credentialType
}: {
  vocabBase: string
  credentialType: string
}): Record<string, unknown> {
  return {
    '@protected': true,
    [APP_KEY_CREDENTIAL_TYPE]: APP_KEY_CREDENTIAL_TYPE_IRI,
    [credentialType]: `${vocabBase}${credentialType}`,
    seed: 'urn:was:seed',
    origin: 'urn:was:origin',
    name: 'https://schema.org/name',
    description: 'https://schema.org/description'
  }
}

/**
 * Whether a credential presents as an app key -- that is, carries the
 * {@link APP_KEY_CREDENTIAL_TYPE} marker in its `type` array. Says nothing
 * about whether it IS one; that is the seed-to-subject binding's job.
 *
 * @param credential {IVerifiableCredential}
 * @returns {boolean}
 */
export function presentsAsAppKey(credential: IVerifiableCredential): boolean {
  return typeArray(credential.type).includes(APP_KEY_CREDENTIAL_TYPE)
}

/**
 * The refusal a store path raises for a credential that presents as an app key
 * without binding to its own seed. A distinct class so the UI can show its own
 * translated wording rather than this message.
 */
export class AppKeyRefusedError extends Error {
  constructor() {
    super(
      'This credential claims to be an app key, but its key does not match ' +
        'its identifier. It was not stored.'
    )
    this.name = 'AppKeyRefusedError'
  }
}

/**
 * Refuses a credential that presents as an app key but whose subject DID does
 * not derive from the seed it itself carries. Called on every path that puts a
 * credential in the store from outside the wallet (the CHAPI store popup, the
 * URL / QR / manual-paste import), so a planted app key never reaches the
 * store, the dashboard, or the user's Space -- rather than being stored and
 * then quietly ignored at match time.
 *
 * A credential with no marker is left alone, so an ordinary credential that
 * merely happens to carry a `seed` or `origin` claim is never caught; a
 * genuine app key handed over legitimately still stores, because it binds.
 *
 * @param credential {IVerifiableCredential}
 * @returns {Promise<void>}   rejects with the refusal reason
 */
export async function assertStorableAppKey(
  credential: IVerifiableCredential
): Promise<void> {
  if (!presentsAsAppKey(credential)) {
    return
  }
  if (!(await appKeySeedBindsSubject(credential))) {
    throw new AppKeyRefusedError()
  }
}

/**
 * Whether an app-key credential's subject DID is the one its own seed derives
 * -- the binding that makes the credential an app key rather than merely a
 * self-issued claim to be one. Self-issuance is a weak signal (anyone can
 * self-issue); this is the strong one, and it is fully local: the credential
 * carries the seed, so re-derive with the same call `mintAppKeyCredential`
 * uses and compare. Fails closed on an absent, non-base64url, or otherwise
 * unusable seed rather than throwing out of the match path.
 *
 * @param credential {IVerifiableCredential}
 * @returns {Promise<boolean>}
 */
export async function appKeySeedBindsSubject(
  credential: IVerifiableCredential
): Promise<boolean> {
  const subjectDid = subjectId(credential)
  const seed = appKeySeedBytes(credential)
  if (!subjectDid || !seed || seed.length !== SEED_BYTE_LENGTH) {
    return false
  }
  try {
    const agent = await CapabilityAgent.fromSeed({
      seed,
      handle: APP_KEY_HANDLE,
      keyName: APP_KEY_KEY_NAME
    })
    return agent.id === subjectDid
  } catch {
    return false
  }
}

/**
 * The self-issued app-key credentials among a set of stored credentials for a
 * given app + origin: those whose `type` includes both the
 * {@link APP_KEY_CREDENTIAL_TYPE} marker and `credentialType`, whose issuer
 * equals the subject (self-issued), whose `credentialSubject.origin` equals
 * `origin`, and whose subject DID derives from the seed they carry. Sorted
 * latest-first by `issuanceDate`.
 *
 * The marker is required here, not merely tolerated: a credential can then
 * only reach the delegation path by carrying it, which is exactly what the
 * store-time refusal screens.
 *
 * The seed-to-subject check is what keeps a planted credential (imported
 * before the store-time refusal existed, or restored from a Space) from
 * winning the match on an attacker-chosen `issuanceDate` and making its DID
 * the App Connect `controller` the wallet delegates to.
 *
 * @param options {object}
 * @param options.credentials {StoredCredential[]}
 * @param options.credentialType {string}
 * @param options.origin {string}
 * @returns {Promise<StoredCredential[]>}
 */
export async function appKeyCredentialsIn({
  credentials,
  credentialType,
  origin
}: {
  credentials: StoredCredential[]
  credentialType: string
  origin: string
}): Promise<StoredCredential[]> {
  // Cheap, synchronous predicates first, so only plausible candidates pay for
  // a key derivation.
  const candidates = credentials.filter(({ vc: credential }) => {
    const issuer = issuerId(credential.issuer)
    return (
      presentsAsAppKey(credential) &&
      typeArray(credential.type).includes(credentialType) &&
      !!issuer &&
      issuer === subjectId(credential) &&
      appKeyOrigin(credential) === origin
    )
  })
  const bound = await Promise.all(
    candidates.map(({ vc: credential }) => appKeySeedBindsSubject(credential))
  )
  return candidates
    .filter((_candidate, index) => bound[index])
    .sort((first, second) => {
      const firstDate = (first.vc.issuanceDate as string) ?? ''
      const secondDate = (second.vc.issuanceDate as string) ?? ''
      return secondDate.localeCompare(firstDate)
    })
}

/**
 * The current (latest) app-key credential for an app + origin, or undefined
 * when the user has none -- which signals first run for that app/origin.
 *
 * @param options {object}
 * @param options.credentials {StoredCredential[]}
 * @param options.credentialType {string}
 * @param options.origin {string}
 * @returns {Promise<StoredCredential | undefined>}
 */
export async function findAppKeyCredential({
  credentials,
  credentialType,
  origin
}: {
  credentials: StoredCredential[]
  credentialType: string
  origin: string
}): Promise<StoredCredential | undefined> {
  return (await appKeyCredentialsIn({ credentials, credentialType, origin }))[0]
}

/**
 * Mints a fresh app-key credential for an app + origin: generates a 32-byte
 * seed, derives the seed's did:key, and self-issues the credential (issuer ==
 * subject == the seed-derived DID) in the exact shape was-react's
 * `parseSeedCredential` accepts. Does NOT store the result -- the caller decides
 * whether to save it.
 *
 * @param options {object}
 * @param options.app {AppConnectApp}
 * @param options.origin {string}
 * @returns {Promise<{ credential: IVerifiableCredential; subjectDid: string }>}
 */
export async function mintAppKeyCredential({
  app,
  origin
}: {
  app: AppConnectApp
  origin: string
}): Promise<{ credential: IVerifiableCredential; subjectDid: string }> {
  const { name: appName, credentialType, vocabBase } = app
  const seedBytes = crypto.getRandomValues(new Uint8Array(SEED_BYTE_LENGTH))
  const agent = await CapabilityAgent.fromSeed({
    seed: seedBytes,
    handle: APP_KEY_HANDLE,
    keyName: APP_KEY_KEY_NAME
  })
  const controllerDid = agent.id
  const credential = {
    '@context': [
      VC_1_CONTEXT_URL,
      appKeyContext({ vocabBase, credentialType })
    ],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential', APP_KEY_CREDENTIAL_TYPE, credentialType],
    name: `${appName} app key`,
    description:
      `The ${appName} app keeps this key in your wallet so it can open ` +
      'your encrypted data on this and other devices.',
    issuer: controllerDid,
    credentialSubject: {
      id: controllerDid,
      seed: base64urlnopad.encode(seedBytes),
      origin
    }
  }
  const suite = new Ed25519Signature2020({ signer: agent.getSigner() })
  const signed = (await vc.issue({
    credential,
    suite,
    documentLoader
  })) as IVerifiableCredential
  return { credential: signed, subjectDid: controllerDid }
}

/**
 * The subject DID (`credentialSubject.id`) of an app-key credential, or
 * undefined. For a valid app-key credential this equals the issuer.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string | undefined}
 */
export function appKeySubjectDid(
  credential: IVerifiableCredential
): string | undefined {
  return subjectId(credential)
}

/**
 * The 32-byte seed an app-key credential carries
 * (`credentialSubject.seed`, base64url-no-pad), or undefined when it is absent
 * or malformed. This is the client secret from which the app's per-collection
 * key-agreement keys derive; the wallet holds it at consent time (freshly
 * minted or matched) to provision the app's encrypted collections.
 *
 * @param credential {IVerifiableCredential}
 * @returns {Uint8Array | undefined}
 */
export function appKeySeedBytes(
  credential: IVerifiableCredential
): Uint8Array | undefined {
  const subject = credential.credentialSubject as { seed?: unknown } | undefined
  if (!subject || typeof subject.seed !== 'string') {
    return undefined
  }
  try {
    return base64urlnopad.decode(subject.seed)
  } catch {
    return undefined
  }
}

/**
 * The origin (`credentialSubject.origin`) an app-key credential is bound to,
 * when present.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string | undefined}
 */
export function appKeyOrigin(
  credential: IVerifiableCredential
): string | undefined {
  const subject = credential.credentialSubject as
    { origin?: unknown } | undefined
  return subject && typeof subject.origin === 'string'
    ? subject.origin
    : undefined
}
