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
  IVerifiablePresentation,
  IZcap
} from '@interop/data-integrity-core'

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
 * `query` is optional: a CHAPI request that carries a `protocols` entry sends an
 * empty VPR body, deferring the real request to the named protocol exchange.
 */
export type IVPRDetails = {
  query?: IVPRQuery | IVPRQuery[]
  challenge?: string
  domain?: string
  interact?: IVPRInteract
}

export type IVPRQuery =
  IQueryByExample | IDIDAuthenticationQuery | IZcapQuery | IAppConnectQuery

/**
 * The interaction endpoints a VPR offers for delivering the response, when the
 * transport that carried the request is not itself the response channel.
 *
 * @see https://w3c-ccg.github.io/vp-request-spec/#interaction-types
 */
export type IVPRInteract = {
  service?: Array<{ type: string; serviceEndpoint?: string }>
}

/**
 * The cryptosuites a verifier will accept for the response proof. VCALM types
 * each entry as an object, but verifiers in the wild (vcplayground.org among
 * them) send bare cryptosuite name strings; both forms are accepted.
 */
export type IAcceptedCryptosuites = Array<string | { cryptosuite: string }>

/**
 * A single credential query within a `QueryByExample`: an example credential
 * shape to match stored credentials against, plus an optional human-readable
 * `reason` to show the user. `acceptedCryptosuites` may be stated here rather
 * than on the enclosing query -- which is where vcplayground.org puts it.
 */
export type ICredentialQuery = {
  reason?: string
  acceptedCryptosuites?: IAcceptedCryptosuites
  example: {
    '@context'?: string | object | Array<string | object>
    type?: string | string[]
    issuer?: string | object | Array<string | object>
    [x: string]: unknown
  }
}

/**
 * A request for one or more VCs matching an example credential shape.
 * `credentialQuery` may be a single detail object or an array of them.
 *
 * @see https://w3c-ccg.github.io/vp-request-spec/#query-by-example
 */
export type IQueryByExample = {
  type: 'QueryByExample'
  acceptedCryptosuites?: IAcceptedCryptosuites
  credentialQuery: ICredentialQuery | ICredentialQuery[]
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
  acceptedCryptosuites?: IAcceptedCryptosuites
}

/**
 * A request for one or more delegated capabilities (zcaps) on the user's WAS
 * storage. `AuthorizationCapabilityQuery` is the canonical type string (VCALM
 * §3.4.4); `ZcapQuery` is a legacy alias sent by DCW / the
 * `wallet-to-webapp-demo`. `capabilityQuery` may be a single detail object or
 * an array of them.
 *
 * @see https://w3c.github.io/vcalm/ -- AuthorizationCapabilityQuery
 */
export type IZcapQuery = {
  type: 'AuthorizationCapabilityQuery' | 'ZcapQuery'
  capabilityQuery: ICapabilityQueryDetail | ICapabilityQueryDetail[]
  challenge?: string
}

/**
 * A single requested capability: which actions (`allowedAction`) the RP
 * (`controller`) wants on which storage target (`invocationTarget`), with an
 * optional human-readable `reason` and RP-chosen `referenceId`. The
 * `invocationTarget` is either a plain URL (satisfied only under the user's own
 * Space) or a wallet-defined descriptor object (`urn:was:collection` /
 * `urn:was:public-collection` / `urn:was:space`), resolved by
 * `resolveInvocationTarget`.
 */
export type ICapabilityQueryDetail = {
  referenceId?: string
  reason?: string
  allowedAction?: string | string[]
  controller: string
  invocationTarget: string | { type: string; name?: string }
}

/**
 * A requested capability within an App Connect request: the same shape as
 * `ICapabilityQueryDetail` minus `controller` (the wallet fills it with the
 * app-key credential's subject DID -- the request cannot name a DID it does
 * not know yet) and minus `reason` (the App Connect consent screen supersedes
 * per-grant reason lines).
 */
export type IAppConnectCapabilityQuery = Omit<
  ICapabilityQueryDetail,
  'controller' | 'reason'
>

/**
 * The app identity an App Connect request presents: a display `name` for the
 * consent screen, plus the `credentialType` / `vocabBase` pair that
 * parameterizes the app-key credential the wallet matches (returning user) or
 * mints (first run).
 */
export type IAppConnectApp = {
  name: string
  credentialType: string
  vocabBase: string
}

/**
 * "Connect this app to the user's wallet and Space" -- a single-round request
 * that combines app-key recovery-or-minting with capability delegation. The
 * wallet finds (or self-issues) the app-key credential for the requesting
 * origin, delegates the requested capabilities to its subject DID, and
 * returns credential + grants in one signed presentation.
 */
export type IAppConnectQuery = {
  type: 'AppConnectQuery'
  app: IAppConnectApp
  capabilityQuery?: IAppConnectCapabilityQuery | IAppConnectCapabilityQuery[]
}

/**
 * An App Connect request as classified onto the `WalletRequestProfile`: the
 * app identity plus its capability queries normalized to an array.
 */
export type IAppConnectRequest = {
  app: IAppConnectApp
  capabilityQueries: IAppConnectCapabilityQuery[]
}

/**
 * The wallet's response to a request, delivered by whichever transport received
 * it (CHAPI `respondWith`, a future exchange-URL POST, etc). Delegated zcaps
 * ride *inside* the response VP (as a `zcap` array, embedded before signing);
 * they are also threaded back out here as `zcaps` -- the same objects that were
 * delegated -- so a caller can record exactly what was granted without
 * re-parsing the VP's (compose-shape-coupled) `zcap` array. Empty or absent
 * when the request granted no capabilities. For an App Connect request,
 * `appConnect` reports what the wallet did (first run vs returning, and the
 * app-key subject DID the grants were delegated to) so the caller can log it
 * without re-parsing the VP.
 */
export type WalletResponse = {
  verifiablePresentation?: IVerifiablePresentation
  zcaps?: IZcap[]
  appConnect?: { firstRun: boolean; subjectDid: string }
}

/**
 * A VP Request classified on two independent axes: whether DID Authentication
 * is requested, and separately what content is asked for (credentials and/or
 * capability delegations). Any combination is valid, including zcap-only. The
 * consent screen renders one section per non-empty axis; the two axes replace
 * the former `'vc' | 'didauth' | 'vc+didauth'` cross-product enum. An App
 * Connect request (`appConnect` set) is exclusive with the credential and
 * standalone capability axes -- one mental model per popup -- and renders its
 * own dedicated consent panel.
 */
export type WalletRequestProfile = {
  didAuth: boolean
  vcQueries: IQueryByExample[]
  zcapRequests: ICapabilityQueryDetail[]
  appConnect: IAppConnectRequest | null
}

export type { IVerifiableCredential, IVerifiablePresentation, IZcap }
