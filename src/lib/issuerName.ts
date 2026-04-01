import type { IVerifiableCredential } from '@digitalcredentials/ssi'

export interface IssuerDetails {
  id: string
  name: string
  url: string
  image: string
}

/**
 * Human-readable issuer string (VerifierPlus-style: name, else id, else DID string).
 */
export function issuerName(credential: IVerifiableCredential): string {
  const { issuer } = credential
  if (typeof issuer === 'string') {
    return issuer
  }
  return issuer.name ?? issuer.id ?? 'Unknown Issuer'
}

/**
 * Maps VC `issuer` to display fields. Matches VerifierPlus `IssuerObject`:
 * `id`, `name?`, `url?`, `image?` (see verifier-plus `app/types/credential.d.ts`).
 * `issuer` may also be a bare IRI string (`IssuerURI`).
 *
 * OBv3 sometimes uses `image: { id: "..." }`; we resolve that to a string URL.
 */
export function getIssuerDetails(
  issuer: IVerifiableCredential['issuer']
): IssuerDetails {
  if (typeof issuer === 'string') {
    return { id: issuer, name: '', url: '', image: '' }
  }

  const imageRaw = issuer.image
  let image = ''
  if (typeof imageRaw === 'string') {
    image = imageRaw
  } else if (imageRaw && typeof imageRaw === 'object' && 'id' in imageRaw) {
    image = String((imageRaw as { id?: string }).id ?? '')
  }

  return {
    id: issuer.id ?? '',
    name: issuer.name ?? '',
    url: issuer.url ?? '',
    image
  }
}
