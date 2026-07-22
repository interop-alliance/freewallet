/**
 * Composes a Verifiable Presentation to send back to a requester. The VP is
 * signed when DID Authentication was requested (proving control of the holder's
 * DID over the request's `challenge` / `domain`), and unsigned otherwise.
 * Ported from DCW's `composeVp.ts`, adapted to Freewallet's `Session`: the
 * signer is the KMS-held did:web `authentication` key when one is provisioned
 * (holder = the published did:web DID), falling back to the passphrase-derived
 * root key (holder = the user's did:key) for guests, no-KMS deployments, and
 * not-yet-provisioned sessions.
 */
import * as vc from '@interop/vc'
import { securityLoader } from '@interop/security-document-loader'
import type { Session } from '@/types/auth'
import { kmsAuthenticationSigner } from '@/lib/didWeb'
import { presentationSuiteFor } from './presentationSuite'
import type {
  IVerifiableCredential,
  IVerifiablePresentation,
  IZcap
} from './types'

/**
 * Shared JSON-LD document loader for presentation and credential signing.
 * Exported so single-VC issuance (`src/lib/loginCredential.ts`) reuses the
 * same context resolution the VP compose path uses.
 */
export const documentLoader = securityLoader({
  fetchRemoteContexts: true
}).build()

/**
 * A presentation carrying an embedded `zcap` array. Embedded before signing so
 * a DIDAuth proof covers the grants (D1). Each entry is a self-contained,
 * self-authenticating delegated capability carrying its own `@context`.
 */
type PresentationWithZcaps = IVerifiablePresentation & {
  '@context': string | Array<string | object>
  zcap?: IZcap[]
  appConnect?: { firstRun: boolean }
}

/**
 * The bare `zcap` term definition appended to the VP `@context` when grants are
 * embedded. Only the top-level term is defined (mapped to an app-specific IRI);
 * the zcap sub-contexts are *not* hoisted -- each embedded zcap self-describes
 * via its own `@context`. Defining the term is what lets JSON-LD safe-mode
 * canonicalization include (rather than reject) the grants, so the
 * authentication proof genuinely covers them.
 */
const ZCAP_TERM_CONTEXT = {
  '@protected': true,
  zcap: { '@id': 'urn:freewallet:vocab#zcap', '@container': '@set' }
} as const

/**
 * The `appConnect` term definition appended to the VP `@context` when an App
 * Connect response marker is embedded. The member is a JSON literal
 * (`@type: '@json'`) so its `firstRun` boolean canonicalizes as one opaque
 * value; embedding happens before signing, so the DIDAuth proof covers the
 * marker the same way it covers the grants.
 */
const APP_CONNECT_TERM_CONTEXT = {
  '@protected': true,
  appConnect: { '@id': 'urn:freewallet:vocab#appConnect', '@type': '@json' }
} as const

/**
 * Embeds the delegated capabilities on the presentation and adds the bare
 * `zcap` term to its `@context`.
 */
function embedZcaps(presentation: PresentationWithZcaps, zcaps: IZcap[]): void {
  if (zcaps.length === 0) {
    return
  }
  const base = presentation['@context']
  const contextArray = Array.isArray(base) ? base : [base]
  presentation['@context'] = [...contextArray, ZCAP_TERM_CONTEXT]
  presentation.zcap = zcaps
}

/**
 * Embeds the App Connect response marker (the wallet-provided `firstRun`
 * signal) on the presentation and adds the `appConnect` term to its
 * `@context`.
 */
function embedAppConnect(
  presentation: PresentationWithZcaps,
  appConnect: { firstRun: boolean } | undefined
): void {
  if (!appConnect) {
    return
  }
  const base = presentation['@context']
  const contextArray = Array.isArray(base) ? base : [base]
  presentation['@context'] = [...contextArray, APP_CONNECT_TERM_CONTEXT]
  presentation.appConnect = appConnect
}

/**
 * Creates a Verifiable Presentation for the requester.
 *
 * @param options {object}
 * @param options.session {Session} - The logged-in session; its
 *   `profile.keyAgent` supplies the signer and `user.id` the holder DID.
 * @param [options.selectedVCs] {IVerifiableCredential[]} - VCs the user chose
 * to share (empty for a DID-Auth-only response).
 * @param [options.challenge] {string} - Required when DID Auth is requested.
 * @param [options.domain] {string} - Required when DID Auth is requested.
 * @param options.didAuthRequested {boolean} - Whether to sign the VP.
 * @param [options.cryptosuite] {string} - Negotiated cryptosuite; falls back to
 *   the wallet default (Ed25519Signature2020) when absent.
 * @param [options.zcaps] {IZcap[]} - Delegated capabilities to embed as the
 *   VP's `zcap` array (before signing, so a DIDAuth proof covers them).
 * @param [options.appConnect] {{ firstRun: boolean }} - App Connect response
 *   marker to embed (before signing, like the grants).
 * @returns {Promise<IVerifiablePresentation>}
 */
export async function composeVP({
  session,
  selectedVCs = [],
  challenge,
  domain,
  didAuthRequested,
  cryptosuite,
  zcaps = [],
  appConnect
}: {
  session: Session
  selectedVCs?: IVerifiableCredential[]
  challenge?: string
  domain?: string
  didAuthRequested: boolean
  cryptosuite?: string
  zcaps?: IZcap[]
  appConnect?: { firstRun: boolean }
}): Promise<IVerifiablePresentation> {
  if (!didAuthRequested && selectedVCs.length === 0 && zcaps.length === 0) {
    throw new Error(
      'A VP requires credentials, capabilities, or a DID Auth request.'
    )
  }
  if (didAuthRequested && !(challenge && domain)) {
    throw new Error('Both "challenge" and "domain" are required for DID Auth.')
  }

  if (!didAuthRequested) {
    // Return an unsigned VP. verify: false skips per-VC validation (including
    // expiration checks). A zcap-only response rides here: the grants are
    // individually signed and controller-bound, so they need no VP proof.
    const presentation = vc.createPresentation({
      verifiableCredential: selectedVCs.length > 0 ? selectedVCs : undefined,
      verify: false,
      version: 1.0
    }) as PresentationWithZcaps
    embedZcaps(presentation, zcaps)
    embedAppConnect(presentation, appConnect)
    return presentation
  }

  // Prefer the KMS-held did:web `authentication` key when provisioned: the
  // holder becomes the published did:web DID. Falls back to the
  // passphrase-derived root key (holder = did:key) for guests, no-KMS
  // deployments, and sessions where did:web provisioning has not (yet)
  // succeeded. The root key is always present in an active session.
  const kmsSigner = await kmsAuthenticationSigner({ session })
  let signer
  let holder
  if (kmsSigner) {
    signer = kmsSigner
    holder = session.profile.didWeb!.did
  } else {
    signer = session.profile.keyAgent!.getSigner()
    holder = session.user.id
  }
  // Sign with the cryptosuite the verifier requested (via VCALM
  // `acceptedCryptosuites`), falling back to the wallet default. The suite
  // dictates the VC data model version: eddsa-rdfc-2022 proofs require VC 2.0,
  // the default Ed25519Signature2020 proof uses VC 1.0.
  const { suite, version } = presentationSuiteFor({ signer, cryptosuite })

  const presentation = vc.createPresentation({
    holder,
    verifiableCredential: selectedVCs.length > 0 ? selectedVCs : undefined,
    verify: false,
    version
  }) as PresentationWithZcaps

  // Embed the grants before signing so the authentication proof covers them
  // (D1). The entries additionally self-authenticate via their own delegation
  // proofs and carry their own `@context`. The App Connect marker is embedded
  // the same way, for the same reason.
  embedZcaps(presentation, zcaps)
  embedAppConnect(presentation, appConnect)

  return (await vc.signPresentation({
    presentation,
    challenge,
    domain,
    documentLoader,
    suite
  })) as IVerifiablePresentation
}
