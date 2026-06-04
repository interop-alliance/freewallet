/**
 * Normalizes raw user or QR input into an array of IVerifiableCredential
 * objects. Accepts a URL (fetched via CORS proxy) or raw JSON/JSON-LD. A
 * VP1- prefix string (VPQR) is detected but no longer supported. Used by
 * AddCredentialPage and AcceptCredentialsPage.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { fetchFromURL } from '@/lib/fetchFromURL'
import { credentialsFromJSON } from '@/lib/credentialsFromJSON'

export class ResolveCredentialsInputError extends Error {
  readonly code: 'empty' | 'invalid_input' | 'none_found' | 'vpqr_unsupported'
  constructor(
    code: 'empty' | 'invalid_input' | 'none_found' | 'vpqr_unsupported'
  ) {
    super(code)
    this.name = 'ResolveCredentialsInputError'
    this.code = code
  }
}

export async function resolveCredentialsInput(
  raw: string
): Promise<IVerifiableCredential[]> {
  const trimmed = raw.trimStart()
  if (!trimmed) {
    throw new ResolveCredentialsInputError('empty')
  }

  let credentials: IVerifiableCredential[]

  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    const jsonText = await fetchFromURL(trimmed)
    credentials = credentialsFromJSON(jsonText)
  } else if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    credentials = credentialsFromJSON(trimmed)
  } else if (trimmed.startsWith('VP1-')) {
    throw new ResolveCredentialsInputError('vpqr_unsupported')
  } else {
    throw new ResolveCredentialsInputError('invalid_input')
  }

  if (credentials.length === 0) {
    throw new ResolveCredentialsInputError('none_found')
  }

  return credentials
}
