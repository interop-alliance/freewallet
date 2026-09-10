/**
 * Normalizes raw user or QR input into an array of IVerifiableCredential
 * objects. Accepts a URL (fetched via the CORS proxy) or raw JSON/JSON-LD. A
 * VP1- prefix string (VPQR) is detected but no longer supported. Used by
 * AddCredentialPage and AcceptCredentialsPage.
 *
 * The normalization itself moved to `@interop/vc-display`; this wrapper
 * injects Freewallet's CORS-proxy `fetchFromURL` and keeps the positional
 * `(raw)` signature its callers use. The coded `ResolveCredentialsInputError`
 * (same `empty` / `invalid_input` / `none_found` / `vpqr_unsupported` taxonomy)
 * is re-exported from the library for construction and typing; a catch site
 * matches it on `name`, since a duplicated copy of the package would make an
 * `instanceof` check miss it.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { resolveCredentialsInput as sharedResolveCredentialsInput } from '@interop/vc-display'
import { fetchFromURL } from '@/lib/corsProxy'

export { ResolveCredentialsInputError } from '@interop/vc-display'

export async function resolveCredentialsInput(
  raw: string
): Promise<IVerifiableCredential[]> {
  return sharedResolveCredentialsInput({ raw, fetchUrl: fetchFromURL })
}
