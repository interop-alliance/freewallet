/**
 * VC API exchange client moved to `@interop/wallet-core/request` (with the
 * network transport injectable, defaulting to `globalThis.fetch` -- the same
 * transport this module used directly). The exports are re-pointed here so
 * `@/lib/walletRequest` importers are unaffected.
 */
export {
  vcApiExchangeUrl,
  beginExchange,
  startExchange,
  submitPresentation,
  deliverPresentation,
  collectIssuedPresentation,
  presentationEndpointFor
} from '@interop/wallet-core/request'
export type { VCAPIExchangeResponse } from '@interop/wallet-core/request'
