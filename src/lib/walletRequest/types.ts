/**
 * Wallet-request message types for Freewallet. The core VPR vocabulary, the
 * CHAPI event shapes, and the wallet-response shape now live in
 * `@interop/wallet-core/request` (this module was the extraction seed); they are
 * re-exported here so existing `@/lib/walletRequest` importers are unaffected.
 *
 * This file keeps only what stays app-side: Freewallet's App Connect protocol
 * extension, and the widened query union / request profile that carry it (the
 * shared vocabulary covers just the three VPR-spec query types).
 *
 * @see https://w3c-ccg.github.io/vp-request-spec/
 */
import type {
  ICapabilityQueryDetail,
  IQueryByExample,
  IVPRInteract,
  IVPRQuery as ISpecVPRQuery
} from '@interop/wallet-core/request'

// Re-export the shared VPR vocabulary + CHAPI event / response shapes so
// existing importers keep their `@/lib/walletRequest` import site. `IVPRDetails`
// is NOT re-exported: Freewallet keeps a widened version below whose `query`
// accepts the app-side `AppConnectQuery`.
export type {
  IVPOffer,
  IVPRequest,
  IVPRInteract,
  IAcceptedCryptosuites,
  ICredentialQuery,
  IQueryByExample,
  IDIDAuthenticationQuery,
  IZcapQuery,
  ICapabilityQueryDetail,
  WalletResponse,
  CHAPIProtocols,
  CHAPIGetEvent,
  CHAPIStoreEvent,
  IVerifiableCredential,
  IVerifiablePresentation,
  IZcap
} from '@interop/wallet-core/request'

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
 * The query union Freewallet dispatches on: the three VPR-spec query types
 * (from the shared vocabulary) widened with the app-side `AppConnectQuery`. An
 * extra union member with a distinct `type` string flows through the shared
 * classify helpers (which accept the spec union structurally) without issue.
 */
export type IVPRQuery = ISpecVPRQuery | IAppConnectQuery

/**
 * The body of a Verifiable Presentation Request: one or more queries, plus the
 * `challenge` / `domain` used when a DID Authentication proof is requested.
 * Widened from the shared vocabulary so `query` accepts Freewallet's App
 * Connect query (a request carrying an `AppConnectQuery` is a legal Freewallet
 * VPR body). A structural superset of the shared `IVPRDetails`, so a shared VPR
 * (from the exchange client / CHAPI) flows into Freewallet's classify / process
 * wrappers unchanged.
 */
export type IVPRDetails = {
  query?: IVPRQuery | IVPRQuery[]
  challenge?: string
  domain?: string
  interact?: IVPRInteract
}

/**
 * A VP Request classified on independent axes: whether DID Authentication is
 * requested, what credentials are asked for (`vcQueries`), and what capability
 * delegations are asked for (`zcapRequests`). Freewallet extends the shared
 * profile with its App Connect axis: an App Connect request (`appConnect` set)
 * is exclusive with the credential and standalone capability axes -- one mental
 * model per popup -- and renders its own dedicated consent panel.
 */
export type WalletRequestProfile = {
  didAuth: boolean
  vcQueries: IQueryByExample[]
  zcapRequests: ICapabilityQueryDetail[]
  appConnect: IAppConnectRequest | null
}
