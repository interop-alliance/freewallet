import type { IVerifiableCredential } from '@interop/data-integrity-core'

import { typeArray } from '@/lib/vcShape'

function hasType(data: unknown, typeName: string): boolean {
  const type = (data as { type?: unknown } | null | undefined)?.type
  return typeArray(type).includes(typeName)
}

function hasWrappedCredentials(data: unknown): data is {
  verifiableCredential: IVerifiableCredential | IVerifiableCredential[]
} {
  return (
    hasType(data, 'VerifiablePresentation') &&
    typeof data === 'object' &&
    data !== null &&
    'verifiableCredential' in data
  )
}

export function credentialsFromJSON(text: string): IVerifiableCredential[] {
  const data = JSON.parse(text)

  if (Array.isArray(data)) {
    const vcs = data.filter(item => hasType(item, 'VerifiableCredential'))
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
