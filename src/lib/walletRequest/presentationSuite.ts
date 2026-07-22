/**
 * Cryptosuite negotiation and proof-suite construction moved to
 * `@interop/wallet-core/request` (this module was byte-identical to it); the
 * exports are re-pointed here so `@/lib/walletRequest` importers are unaffected.
 */
export {
  EDDSA_RDFC_2022,
  negotiateCryptosuite,
  presentationSuiteFor
} from '@interop/wallet-core/request'
