import type { IVerifiableCredential, IAlignment } from '@digitalcredentials/ssi'

export interface CredentialDisplayFields {
  credentialName: string
  issuedTo: string
  issuanceDate: string
  expirationDate: string
  credentialDescription: string
  criteria: string
  achievementImage: string
  achievementType: string
  alignments: IAlignment[]
}

export interface StoredCredential {
  cid: string
  vc: IVerifiableCredential
}

// JSON Schema, used for RxDb collections
export const StoredCredentialSchema = {
  version: 0,
  primaryKey: 'cid',
  type: 'object',
  properties: {
    cid: { type: 'string', maxLength: 128 },
    vc: { type: 'object', additionalProperties: true }
  },
  required: ['cid']
}
