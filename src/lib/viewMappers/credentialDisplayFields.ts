/**
 * The aggregate credential display projection (`getDisplayFields`) moved to
 * `@interop/wallet-core/display`; re-exported here so existing importers are
 * unaffected. The library returns raw ISO dates (the raw-values seam); the
 * `expirationDate` field is a raw ISO string, formatted at the UI layer.
 */
export { getDisplayFields } from '@interop/wallet-core/display'
