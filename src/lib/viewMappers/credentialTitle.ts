import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { credentialName } from '@interop/wallet-core/display'

export function credentialTitle(credential: IVerifiableCredential): string {
  return credentialName(credential)
}
