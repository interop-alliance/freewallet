/**
 * Normalizes raw user or QR input into an array of IVerifiableCredential
 * objects. Accepts a URL (fetched via CORS proxy), raw JSON/JSON-LD, or a
 * VP1- prefix string (VPQR, decoded via @digitalcredentials/vpqr). Used by
 * AddCredentialPage and AcceptCredentialsPage.
 */
import { fromQrCode } from '@digitalcredentials/vpqr'
import { securityLoader } from '@digitalcredentials/security-document-loader'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { fetchFromURL } from '@/lib/fetchFromURL'
import { credentialsFromJSON } from '@/lib/credentialsFromJSON'

const documentLoader = securityLoader().build()

export class ResolveCredentialsInputError extends Error {
  readonly code: 'empty' | 'invalid_input' | 'none_found'
  constructor(code: 'empty' | 'invalid_input' | 'none_found') {
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
    const { vp } = await fromQrCode({ text: trimmed, documentLoader })
    credentials = credentialsFromJSON(JSON.stringify(vp))
  } else {
    throw new ResolveCredentialsInputError('invalid_input')
  }

  if (credentials.length === 0) {
    throw new ResolveCredentialsInputError('none_found')
  }

  return credentials
}
