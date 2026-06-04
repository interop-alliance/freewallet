import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { getDisplayFields } from '@/lib/viewMappers/credentialDisplayFields'

export function credentialTitle(credential: IVerifiableCredential): string {
  return getDisplayFields(credential).credentialName
}
