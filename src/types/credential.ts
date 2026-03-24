import type { IVerifiableCredential } from '@digitalcredentials/ssi'

export interface StoredCredential {
  cid: string
  vc: IVerifiableCredential
}
