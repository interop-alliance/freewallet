/**
 * Composes a Verifiable Presentation to send back to a requester. The signing
 * itself lives in the shared `@interop/wallet-core/request` `composeVp`; this
 * wrapper resolves Freewallet's signer + holder from the `Session` (the
 * KMS-held did:web `authentication` key when one is provisioned, holder = the
 * published did:web DID; otherwise the passphrase-derived root key, holder =
 * the user's did:key) and enforces Freewallet's stricter DID Auth rule (a
 * `domain` is required, where the shared guard requires only a `challenge`).
 *
 * The shared `composeVp` defaults its `vocabBaseIri` to `urn:freewallet:vocab#`,
 * so the embedded-grant `@context` term IRIs -- and therefore the signed proof
 * bytes -- are identical to the pre-extraction output.
 */
import {
  composeVp,
  documentLoader as sharedDocumentLoader
} from '@interop/wallet-core/request'
import type { PresentationSigner } from '@interop/wallet-core/request'
import type { Session } from '@/types/auth'
import { kmsAuthenticationSigner } from '@/lib/didWeb'
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
export const documentLoader = sharedDocumentLoader

/**
 * Resolves the authentication signer and holder DID for the session: the
 * KMS-held did:web `authentication` key when provisioned (holder = the
 * published did:web DID), falling back to the passphrase-derived root key
 * (holder = the user's did:key) for guests, no-KMS deployments, and sessions
 * where did:web provisioning has not (yet) succeeded.
 *
 * @param session {Session}
 * @returns {Promise<PresentationSigner>}
 */
export async function presentationSignerFor(
  session: Session
): Promise<PresentationSigner> {
  const kmsSigner = await kmsAuthenticationSigner({ session })
  if (kmsSigner) {
    return { signer: kmsSigner, holder: session.profile.didWeb!.did }
  }
  return {
    signer: session.profile.keyAgent!.getSigner(),
    holder: session.user.id
  }
}

/**
 * Creates a Verifiable Presentation for the requester.
 *
 * @param options {object}
 * @param options.session {Session} - The logged-in session; supplies the signer
 *   and holder DID.
 * @param [options.selectedVCs] {IVerifiableCredential[]} - VCs the user chose
 *   to share (empty for a DID-Auth-only response).
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
  // Freewallet's stricter DID Auth rule: both `challenge` and `domain` are
  // required (the shared guard requires only `challenge`). Enforced here so the
  // replay-check invariant is preserved.
  if (didAuthRequested && !(challenge && domain)) {
    throw new Error('Both "challenge" and "domain" are required for DID Auth.')
  }

  const presentationSigner = await presentationSignerFor(session)

  return composeVp({
    presentationSigner,
    selectedVcs: selectedVCs,
    challenge,
    domain,
    didAuthRequested,
    cryptosuite,
    zcaps,
    appConnect
  })
}
