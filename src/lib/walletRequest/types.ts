/**
 * VC API message types for external messages to the wallet -- either offers of
 * credentials (`IVpOffer`) or requests for credentials / DID Authentication
 * (`IVpRequest`). Ported and trimmed from DCW's `walletRequestApi.ts`.
 *
 * These messages arrive today via CHAPI popups, but the shapes are transport
 * agnostic so the same classification/compose logic can later back other entry
 * points (QR scan, paste-into-Add-Credential) without dragging React or CHAPI
 * along.
 *
 * @see https://w3c-ccg.github.io/vp-request-spec/
 */
import type {
  IVerifiableCredential,
  IVerifiablePresentation
} from '@interop/data-integrity-core'

/**
 * The union of VC API message types the wallet can classify. Zcap and exchange
 * invitation / issue request messages are deferred to later work.
 */
export type WalletAPIMessage = IVPRequest | IVPOffer

/**
 * "I'm offering the following credentials" -- a Verifiable Presentation offered
 * to the wallet for storage.
 *
 * @see https://vcplayground.org/docs/n/chapi/wallets/native/#vc-api
 */
export type IVPOffer = {
  credentialRequestOrigin?: string
  verifiablePresentation: IVerifiablePresentation
  redirectUrl?: string
}

/**
 * "The following things are requested" -- a Verifiable Presentation Request
 * asking the wallet to share credentials and/or prove DID Authentication.
 *
 * @see https://w3c-ccg.github.io/vp-request-spec/
 */
export type IVPRequest = {
  credentialRequestOrigin?: string
  verifiablePresentationRequest: IVPRDetails
  redirectUrl?: string
}

/**
 * The body of a Verifiable Presentation Request: one or more queries, plus the
 * `challenge` / `domain` used when a DID Authentication proof is requested.
 */
export type IVPRDetails = {
  query: IVPRQuery | IVPRQuery[]
  challenge?: string
  domain?: string
}

export type IVPRQuery = IQueryByExample | IDIDAuthenticationQuery

/**
 * A request for one or more VCs matching an example credential shape.
 *
 * @see https://w3c-ccg.github.io/vp-request-spec/#query-by-example
 */
export type IQueryByExample = {
  type: 'QueryByExample'
  acceptedCryptosuites?: Array<{ cryptosuite: string }>
  credentialQuery: {
    reason?: string
    example: {
      '@context'?: string | object | Array<string | object>
      type?: string | string[]
      issuer?: string | object | Array<string | object>
      [x: string]: unknown
    }
  }
}

/**
 * A request for a proof of DID Authentication (a signed VerifiablePresentation
 * over the request's `challenge` / `domain`).
 *
 * @see https://w3c-ccg.github.io/vp-request-spec/#the-did-authentication-query-format
 */
export type IDIDAuthenticationQuery = {
  type: 'DIDAuthentication'
  acceptedMethods?: Array<{ method: string }>
  acceptedCryptosuites?: Array<{ cryptosuite: string }>
}

/**
 * The wallet's response to a request, delivered by whichever transport received
 * it (CHAPI `respondWith`, a future exchange-URL POST, etc). Zcaps land
 * later.
 */
export type WalletResponse = {
  verifiablePresentation?: IVerifiablePresentation
}

/**
 * Which workflow a classified request maps to:
 * - `'vc'` -- share one or more credentials (`QueryByExample` only);
 * - `'didauth'` -- prove DID Authentication only, no credentials;
 * - `'vc+didauth'` -- share credentials *and* prove DID Authentication.
 */
export type WalletRequestKind = 'vc' | 'didauth' | 'vc+didauth'

export type { IVerifiableCredential, IVerifiablePresentation }
