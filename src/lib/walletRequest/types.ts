/**
 * Wallet-request message types for Freewallet. The core VPR vocabulary, the
 * CHAPI event shapes, and the wallet-response shape now live in
 * `@interop/wallet-core/request` (this module was the extraction seed); they are
 * re-exported here so existing `@/lib/walletRequest` importers are unaffected.
 *
 * The App Connect protocol extension -- its `app` block, query, and classified
 * request -- now lives in `@interop/wallet-core/request` too and is re-exported
 * here. This file keeps only the widened query union / request profile that
 * carry it (the shared vocabulary's own union covers just the three VPR-spec
 * query types).
 *
 * @see https://w3c-ccg.github.io/vp-request-spec/
 */
import type {
  IAppConnectQuery,
  IAppConnectRequest,
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
  IZcap,
  IAppConnectApp,
  IAppConnectCapabilityQuery,
  IAppConnectQuery,
  IAppConnectRequest
} from '@interop/wallet-core/request'

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
