import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { getDisplayFields } from '@/lib/viewMappers/credentialDisplayFields'

export function credentialTitle(credential: IVerifiableCredential): string {
  return getDisplayFields(credential).credentialName
}
