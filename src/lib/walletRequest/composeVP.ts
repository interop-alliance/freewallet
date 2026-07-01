/**
 * Composes a Verifiable Presentation to send back to a requester. The VP is
 * signed when DID Authentication was requested (proving control of the holder's
 * DID over the request's `challenge` / `domain`), and unsigned otherwise.
 * Ported from DCW's `composeVp.ts`, adapted to Freewallet's `Session`: the
 * signer is the Ed25519 key the CapabilityAgent already derived from the
 * passphrase, and the holder is the user's did:key.
 */
import * as vc from '@interop/vc'
import { securityLoader } from '@interop/security-document-loader'
import type { Session } from '@/types/auth'
import { presentationSuiteFor } from './presentationSuite'
import type { IVerifiableCredential, IVerifiablePresentation } from './types'

const documentLoader = securityLoader({ fetchRemoteContexts: true }).build()

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
 * @returns {Promise<IVerifiablePresentation>}
 */
export async function composeVP({
  session,
  selectedVCs = [],
  challenge,
  domain,
  didAuthRequested,
  cryptosuite
}: {
  session: Session
  selectedVCs?: IVerifiableCredential[]
  challenge?: string
  domain?: string
  didAuthRequested: boolean
  cryptosuite?: string
}): Promise<IVerifiablePresentation> {
  if (!didAuthRequested && selectedVCs.length === 0) {
    throw new Error('A VP requires either credentials or a DID Auth request.')
  }
  if (didAuthRequested && !(challenge && domain)) {
    throw new Error('Both "challenge" and "domain" are required for DID Auth.')
  }

  if (!didAuthRequested) {
    // Return an unsigned VP. verify: false skips per-VC validation (including
    // expiration checks).
    return vc.createPresentation({
      verifiableCredential: selectedVCs,
      verify: false,
      version: 1.0
    }) as IVerifiablePresentation
  }

  // Sign with the cryptosuite the verifier requested (via VCALM
  // `acceptedCryptosuites`), falling back to the wallet default. The suite
  // dictates the VC data model version: eddsa-rdfc-2022 proofs require VC 2.0,
  // the default Ed25519Signature2020 proof uses VC 1.0.
  const signer = session.profile.keyAgent.getSigner()
  const { suite, version } = presentationSuiteFor({ signer, cryptosuite })

  const presentation = vc.createPresentation({
    holder: session.user.id,
    verifiableCredential: selectedVCs.length > 0 ? selectedVCs : undefined,
    verify: false,
    version
  })

  return (await vc.signPresentation({
    presentation,
    challenge,
    domain,
    documentLoader,
    suite
  })) as IVerifiablePresentation
}
