/**
 * Normalizes raw user or QR input into an array of IVerifiableCredential
 * objects. Accepts a URL (fetched via the CORS proxy) or raw JSON/JSON-LD. A
 * VP1- prefix string (VPQR) is detected but no longer supported. Used by
 * AddCredentialPage and AcceptCredentialsPage.
 *
 * The normalization itself moved to `@interop/wallet-core/display`; this wrapper
 * injects Freewallet's CORS-proxy `fetchFromURL` and keeps the positional
 * `(raw)` signature its callers use. The coded `ResolveCredentialsInputError`
 * (same `empty` / `invalid_input` / `none_found` / `vpqr_unsupported` taxonomy)
 * is re-exported from the library so the i18n message mapper's `instanceof`
 * check stays valid.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { resolveCredentialsInput as sharedResolveCredentialsInput } from '@interop/wallet-core/display'
import { fetchFromURL } from '@/lib/fetchFromURL'

export { ResolveCredentialsInputError } from '@interop/wallet-core/display'

export async function resolveCredentialsInput(
  raw: string
): Promise<IVerifiableCredential[]> {
  return sharedResolveCredentialsInput({ raw, fetchUrl: fetchFromURL })
}
