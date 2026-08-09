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
 * `https://w3id.org/byoe#` terms plus the app's own type term under its
 * `vocabBase`, no hosted context or document-loader changes), a
 * `name`/`description` pair, and
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
import { CONTEXT_V1 } from 'byoe-context'
import { CapabilityAgent } from '@interop/webkms-client'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { StoredCredential } from '@/types/credential'
import type { IAppConnectApp } from '@/lib/walletRequest'
import { documentLoader } from '@/lib/walletRequest/composeVP'
import {
  byIssuanceDateDesc,
  isSelfIssued,
  subjectId,
  typeArray
} from '@/lib/vcShape'

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
const APP_KEY_HANDLE = 'freewallet-app-key'

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
 * rule precise -- and the seed-to-subject binding
 * ({@link appKeySeedBindsSubject}) authenticates only a credential's internal
 * consistency, never its provenance (a fully attacker-generated credential
 * binds perfectly). That is exactly why external ingest refuses on the marker
 * alone, binding or not ({@link assertStorableAppKey}): app keys are
 * wallet-minted, never imported.
 */
export const APP_KEY_CREDENTIAL_TYPE = 'AppKeyCredential'

/**
 * The shared BYOE term IRIs, taken from the published context rather than
 * restated here.
 */
const BYOE_TERMS = CONTEXT_V1['@context']

const APP_KEY_CREDENTIAL_TYPE_IRI = BYOE_TERMS.AppKeyCredential

/**
 * The number of random bytes in an app-key seed.
 */
const SEED_BYTE_LENGTH = 32

/**
 * Builds the inline JSON-LD context object appended after the VC 1.0 context.
 * The marker type and the `seed` / `origin` claims carry shared
 * `https://w3id.org/byoe#` IRIs (imported from `byoe-context`) -- they mean
 * the same thing for every app, so they do not belong under a per-app
 * `vocabBase`, which keeps only the app's own type term. Still interpolated
 * (not constant) because that one term varies per app.
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
    seed: BYOE_TERMS.seed,
    origin: BYOE_TERMS.origin,
    name: BYOE_TERMS.name,
    description: BYOE_TERMS.description
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
 * but arrived from outside the wallet's own mint path. A distinct class so the
 * UI can show its own translated wording rather than this message.
 */
export class AppKeyRefusedError extends Error {
  constructor() {
    super(
      'This credential claims to be an app key. App keys are created by the ' +
        'wallet itself and cannot be added from outside, so it was not stored.'
    )
    this.name = 'AppKeyRefusedError'
  }
}

/**
 * Refuses any credential that presents as an app key, unconditionally --
 * whether or not it binds to its own seed. Called on every path that puts a
 * credential in the store from outside the wallet (the CHAPI store popup, the
 * URL / QR / manual-paste import), so an externally arriving app key never
 * reaches the store, the dashboard, or the user's Space.
 *
 * The seed-to-subject binding ({@link appKeySeedBindsSubject}) authenticates
 * only the credential's internal consistency, not its provenance: a fully
 * attacker-generated credential binds perfectly (a fresh seed, the victim
 * app's `origin` and `credentialType`, self-issued), and storing it would make
 * its DID the controller the wallet delegates the user's storage to. So there
 * is no "binds, so it stores" carve-out here: app-key credentials are
 * wallet-minted, never imported, and only the wallet's own mint path
 * (`StorageManager.addMintedAppKey`) may store one.
 *
 * A credential with no marker is left alone, so an ordinary credential that
 * merely happens to carry a `seed` or `origin` claim is never caught.
 *
 * @param credential {IVerifiableCredential}
 * @returns {void}   throws the refusal reason
 */
export function assertStorableAppKey(credential: IVerifiableCredential): void {
  if (presentsAsAppKey(credential)) {
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
 * Raised by {@link assertMintedAppKey} when a credential offered to the mint
 * path's store door (`StorageManager.addMintedAppKey`) does not carry the
 * mint invariants. Reaching it means a caller tried to route a foreign
 * credential through the wallet's own mint door -- a programming error, not a
 * user-facing refusal, so it is not translated like
 * {@link AppKeyRefusedError}.
 */
export class AppKeyMintInvariantError extends Error {
  constructor() {
    super(
      'Only a wallet-minted app-key credential (marker type present, subject ' +
        'DID derived from its own seed) can be stored through the mint path.'
    )
    this.name = 'AppKeyMintInvariantError'
  }
}

/**
 * Asserts the mint invariants on a credential the wallet claims to have just
 * minted: it presents as an app key (the marker type) and its subject DID
 * re-derives from the seed it carries. The mirror image of
 * {@link assertStorableAppKey} -- external ingest refuses every marker
 * credential, the mint door stores only credentials that carry the full mint
 * shape -- kept beside it so the two halves of the app-key store policy live
 * in one module.
 *
 * @param credential {IVerifiableCredential}
 * @returns {Promise<void>}   throws {@link AppKeyMintInvariantError}
 */
export async function assertMintedAppKey(
  credential: IVerifiableCredential
): Promise<void> {
  if (
    !presentsAsAppKey(credential) ||
    !(await appKeySeedBindsSubject(credential))
  ) {
    throw new AppKeyMintInvariantError()
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
  const candidates = appKeyCandidates({ credentials, credentialType, origin })
  const bound = await Promise.all(
    candidates.map(({ vc: credential }) => appKeySeedBindsSubject(credential))
  )
  return candidates.filter((_candidate, index) => bound[index])
}

/**
 * How far past "now" a candidate's `issuanceDate` may sit before it is
 * excluded from matching. Generous on purpose: the wallet stamps mint time,
 * so the only legitimate way a stored app key is future-dated is clock skew
 * between two of the user's own clients, and excluding a genuine key would
 * mint a duplicate whose seed cannot open the app's existing data. A whole
 * day covers any clock a working TLS stack tolerates, while still cutting
 * off the far-future `issuanceDate` a planted credential uses to win the
 * latest-first ranking durably.
 */
const ISSUANCE_SKEW_GRACE_MS = 24 * 60 * 60 * 1000

/**
 * Whether a credential states an `issuanceDate` the latest-first ranking can
 * trust: a string that parses to a real timestamp no further in the future
 * than the clock-skew grace. Candidates are ranked on a date the credential
 * itself states, so without this cutoff a planted credential dated 2099 would
 * outrank every key the wallet ever mints. Store-time refusal
 * ({@link assertStorableAppKey}) is the primary door; this is the match-time
 * backstop for a credential that reached the store some other way (stored
 * before the refusal existed, or injected into the Space directly).
 *
 * Fails CLOSED on an absent, non-string, or unparseable date: the ranking
 * compares raw strings, so a value `Date.parse` cannot make sense of
 * ('9999-99-99...', 'z2099') would still sort ahead of every real ISO date --
 * exactly the durable-win slot a planted credential wants -- and a non-string
 * would throw inside the sort. The wallet's own mint path always stamps a
 * parseable ISO date (`vc.issue` auto-fills it), so nothing legitimate is
 * dropped.
 *
 * @param credential {IVerifiableCredential}
 * @returns {boolean}
 */
function issuedWithinSkewGrace(credential: IVerifiableCredential): boolean {
  const raw = (credential as { issuanceDate?: unknown }).issuanceDate
  if (typeof raw !== 'string') {
    return false
  }
  const issued = Date.parse(raw)
  return (
    Number.isFinite(issued) && issued <= Date.now() + ISSUANCE_SKEW_GRACE_MS
  )
}

/**
 * The app-key candidates for an app + origin, latest-first: everything the
 * cheap, synchronous predicates accept, so only plausible candidates pay for a
 * key derivation. A candidate whose `issuanceDate` is missing, unparseable,
 * or beyond the clock-skew grace is dropped here
 * ({@link issuedWithinSkewGrace}), so a far-future or garbage date can never
 * win the ranking. Sorting here (rather than after the binding check) lets
 * {@link findAppKeyCredential} stop at the newest credential that binds.
 *
 * @param options {object}
 * @param options.credentials {StoredCredential[]}
 * @param options.credentialType {string}
 * @param options.origin {string}
 * @returns {StoredCredential[]}
 */
function appKeyCandidates({
  credentials,
  credentialType,
  origin
}: {
  credentials: StoredCredential[]
  credentialType: string
  origin: string
}): StoredCredential[] {
  return credentials
    .filter(
      ({ vc: credential }) =>
        presentsAsAppKey(credential) &&
        typeArray(credential.type).includes(credentialType) &&
        isSelfIssued(credential) &&
        appKeyOrigin(credential) === origin &&
        issuedWithinSkewGrace(credential)
    )
    .sort(byIssuanceDateDesc)
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
  // Newest-first, returning at the first credential that binds: a planted one
  // ranked above it by its own `issuanceDate` is discarded on the way, and the
  // credentials below it never pay for a key derivation.
  for (const candidate of appKeyCandidates({
    credentials,
    credentialType,
    origin
  })) {
    if (await appKeySeedBindsSubject(candidate.vc)) {
      return candidate
    }
  }
  return undefined
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
 * or malformed. This is the app's client secret, the root of its identity and
 * of the keys it encrypts its own data with. The wallet reads it only to
 * re-derive the credential's subject DID and check that the two bind
 * ({@link appKeySeedBindsSubject}); nothing downstream of the match takes the
 * seed, so it never reaches the grant path.
 *
 * @param credential {IVerifiableCredential}
 * @returns {Uint8Array | undefined}
 */
function appKeySeedBytes(
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
