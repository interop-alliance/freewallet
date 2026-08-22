import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { credentialName } from '@interop/vc-display'

export function credentialTitle(credential: IVerifiableCredential): string {
  return credentialName(credential)
}
