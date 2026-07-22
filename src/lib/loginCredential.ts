/**
 * The self-issued Login Credential: a VC whose issuer and subject are both the
 * user's own did:key, carrying a preferred username (handle). A relying party
 * asks for it over CHAPI via `QueryByExample { example: { type:
 * 'LoginCredential' } }`; the wallet answers with the stored copy when the user
 * has set a handle in Settings.
 *
 * The credential uses an inline `@context` object (legal JSON-LD that canonizes
 * deterministically, no hosted context or document-loader changes): the type
 * term maps to `urn:freewallet:vocab#LoginCredential` and `preferredUsername`
 * to the ActivityStreams IRI. It is a VC 1.0 credential signed with the wallet
 * default suite (`Ed25519Signature2020`); `vc.issue` auto-fills `issuanceDate`.
 * A VC 1.0 credential inside a VC 2.0 presentation is fine -- it carries its
 * own context.
 */
import * as vc from '@interop/vc'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { Session } from '@/types/auth'
import type { StoredCredential } from '@/types/credential'
import { documentLoader } from '@/lib/walletRequest/composeVP'
import { issuerId, subjectId, typeArray } from '@/lib/vcShape'

/**
 * The `type` term identifying a Login Credential (both the wallet-defined type
 * and the credentialSubject claim it carries).
 */
export const LOGIN_CREDENTIAL_TYPE = 'LoginCredential'

/**
 * The inline JSON-LD context object appended after the VC 1.0 context: it
 * defines the `LoginCredential` type term and the `preferredUsername` claim.
 */
const LOGIN_CREDENTIAL_CONTEXT = {
  '@protected': true,
  LoginCredential: 'urn:freewallet:vocab#LoginCredential',
  preferredUsername: 'https://www.w3.org/ns/activitystreams#preferredUsername'
} as const

const VC_1_CONTEXT_URL = 'https://www.w3.org/2018/credentials/v1'

/**
 * Issues (signs) a self-issued Login Credential for the given username. The
 * issuer and subject are both `session.user.id`, signed with the session's
 * root key.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.username {string}
 * @returns {Promise<IVerifiableCredential>}
 */
export async function issueLoginCredential({
  session,
  username
}: {
  session: Session
  username: string
}): Promise<IVerifiableCredential> {
  const did = session.user.id
  const credential = {
    '@context': [VC_1_CONTEXT_URL, LOGIN_CREDENTIAL_CONTEXT],
    type: ['VerifiableCredential', LOGIN_CREDENTIAL_TYPE],
    issuer: did,
    credentialSubject: {
      id: did,
      preferredUsername: username
    }
  }
  const suite = new Ed25519Signature2020({
    signer: session.profile.keyAgent!.getSigner()
  })
  return (await vc.issue({
    credential,
    suite,
    documentLoader
  })) as IVerifiableCredential
}

/**
 * The self-issued Login Credentials among a set of stored credentials: those
 * whose `type` includes `LoginCredential` and whose issuer equals the subject
 * (self-issued). Sorted latest-first by `issuanceDate`.
 *
 * @param options {object}
 * @param options.credentials {StoredCredential[]}
 * @returns {StoredCredential[]}
 */
export function loginCredentialsIn({
  credentials
}: {
  credentials: StoredCredential[]
}): StoredCredential[] {
  return credentials
    .filter(({ vc: credential }) => {
      const issuer = issuerId(credential.issuer)
      return (
        typeArray(credential.type).includes(LOGIN_CREDENTIAL_TYPE) &&
        !!issuer &&
        issuer === subjectId(credential)
      )
    })
    .sort((first, second) => {
      const firstDate = (first.vc.issuanceDate as string) ?? ''
      const secondDate = (second.vc.issuanceDate as string) ?? ''
      return secondDate.localeCompare(firstDate)
    })
}

/**
 * The current (latest) self-issued Login Credential, or undefined when the user
 * has no handle set.
 *
 * @param options {object}
 * @param options.credentials {StoredCredential[]}
 * @returns {StoredCredential | undefined}
 */
export function findLoginCredential({
  credentials
}: {
  credentials: StoredCredential[]
}): StoredCredential | undefined {
  return loginCredentialsIn({ credentials })[0]
}

/**
 * The preferred username carried by a Login Credential, when present.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string | undefined}
 */
export function loginHandleOf(
  credential: IVerifiableCredential
): string | undefined {
  const subject = credential.credentialSubject as
    { preferredUsername?: unknown } | undefined
  return subject && typeof subject.preferredUsername === 'string'
    ? subject.preferredUsername
    : undefined
}

/**
 * Sets (or clears) the user's login handle: deletes any prior self-issued
 * Login Credential(s), then -- for a non-empty username -- issues and stores a
 * fresh one. An empty username leaves the handle unset (delete only).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.username {string}
 * @returns {Promise<void>}
 */
export async function setLoginHandle({
  session,
  username
}: {
  session: Session
  username: string
}): Promise<void> {
  const existing = await session.storage.listCredentials()
  const prior = loginCredentialsIn({ credentials: existing })
  for (const { cid } of prior) {
    await session.storage.deleteCredential({ cid })
  }
  const trimmed = username.trim()
  if (!trimmed) {
    return
  }
  const credential = await issueLoginCredential({ session, username: trimmed })
  await session.storage.addCredential({ credential, user: session.user })
}
