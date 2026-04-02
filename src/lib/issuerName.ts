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
 * `id`, `name?`, `url?`, `image?`
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
