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
 * `parseSeedCredential` accepts: an inline seed `@context` (interpolated from
 * the app's `vocabBase` and `credentialType`, no hosted context or
 * document-loader changes), a `name`/`description` pair, and a seed encoded as
 * base64url without padding. It is a VC 1.0 credential signed with the wallet
 * default suite (`Ed25519Signature2020`); `vc.issue` auto-fills `issuanceDate`.
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
 * The number of random bytes in an app-key seed.
 */
const SEED_BYTE_LENGTH = 32

/**
 * Builds the inline JSON-LD context object appended after the VC 1.0 context.
 * The type term and the `seed` / `origin` claims are namespaced under the app's
 * `vocabBase`; `name` / `description` map to their schema.org IRIs. Interpolated
 * (not constant) because it varies per app.
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
    [credentialType]: `${vocabBase}${credentialType}`,
    seed: `${vocabBase}seed`,
    origin: `${vocabBase}origin`,
    name: 'https://schema.org/name',
    description: 'https://schema.org/description'
  }
}

/**
 * The self-issued app-key credentials among a set of stored credentials for a
 * given app + origin: those whose `type` includes `credentialType`, whose
 * issuer equals the subject (self-issued), and whose `credentialSubject.origin`
 * equals `origin`. Sorted latest-first by `issuanceDate`.
 *
 * @param options {object}
 * @param options.credentials {StoredCredential[]}
 * @param options.credentialType {string}
 * @param options.origin {string}
 * @returns {StoredCredential[]}
 */
export function appKeyCredentialsIn({
  credentials,
  credentialType,
  origin
}: {
  credentials: StoredCredential[]
  credentialType: string
  origin: string
}): StoredCredential[] {
  return credentials
    .filter(({ vc: credential }) => {
      const issuer = issuerId(credential.issuer)
      return (
        typeArray(credential.type).includes(credentialType) &&
        !!issuer &&
        issuer === subjectId(credential) &&
        appKeyOrigin(credential) === origin
      )
    })
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
 * @returns {StoredCredential | undefined}
 */
export function findAppKeyCredential({
  credentials,
  credentialType,
  origin
}: {
  credentials: StoredCredential[]
  credentialType: string
  origin: string
}): StoredCredential | undefined {
  return appKeyCredentialsIn({ credentials, credentialType, origin })[0]
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
    type: ['VerifiableCredential', credentialType],
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
