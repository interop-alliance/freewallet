import type { IVerifiableCredential } from '@interop/data-integrity-core'

function hasType(data: any, typeName: string): boolean {
  return Array.isArray(data?.type) && data.type.includes(typeName)
}

function hasWrappedCredentials(
  data: any
): data is { verifiableCredential: IVerifiableCredential | IVerifiableCredential[] } {
  return hasType(data, 'VerifiablePresentation') && 'verifiableCredential' in data
}

export function credentialsFromJSON(text: string): IVerifiableCredential[] {
  const data = JSON.parse(text)

  if (Array.isArray(data)) {
    const vcs = data.filter((item: any) => hasType(item, 'VerifiableCredential'))
    if (vcs.length > 0) {
      return vcs
    }
    throw new Error('Array did not contain any Verifiable Credentials.')
  }

  if (hasWrappedCredentials(data)) {
    const wrapped = data.verifiableCredential
    return Array.isArray(wrapped) ? wrapped : [wrapped]
  }

  if (hasType(data, 'VerifiableCredential')) {
    return [data]
  }

  throw new Error('Could not decode Verifiable Credential(s) from the JSON.')
}
