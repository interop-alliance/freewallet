import type { IVerifiableCredential } from '@digitalcredentials/ssi'

export interface AlignmentItem {
  targetName: string
  targetUrl: string
  targetDescription: string
}

export interface CredentialDisplayFields {
  credentialName: string
  issuedTo: string
  issuanceDate: string
  expirationDate: string
  credentialDescription: string
  criteria: string
  achievementImage: string
  achievementType: string
  alignments: AlignmentItem[]
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
