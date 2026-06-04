/**
 * VC-related types for the wallet UI: display projection, verification
 * results, and the StoredCredential wrapper used by both BrowserStore and
 * WASRemoteStore.
 */
import type { IVerifiableCredential, IAlignment } from '@interop/data-integrity-core'

/**
 * Projected display fields extracted from a raw VC for the credential card and detail view.
 */
export interface CredentialDisplayFields {
  credentialName: string
  issuedTo: string
  expirationDate: string
  credentialDescription: string
  criteria: string
  achievementImage: string
  achievementType: string
  alignments: IAlignment[]
}

/**
 * Raw response shape from @digitalcredentials/verifier-core, augmented with wallet-specific fields.
 */
export interface VerifyCredentialPayload {
  log?: Array<{
    id: string
    valid?: boolean
    matchingIssuers?: Array<Record<string, unknown>>
    error?: { name?: string; message?: string }
  }>
  errors?: Array<{ message?: string; name?: string }>
  credential?: object
  verified?: boolean
  results?: Array<{
    verified?: boolean
    log?: Array<{ id: string; valid?: boolean }>
    credential?: object
  }>
  hasStatusError?: boolean
}

/**
 * Wallet verification checklist (Signature / Expiry / Revocation rows).
 */
export interface VerificationChecklist {
  signature: VerificationStep
  expiry: VerificationStep
  status: VerificationStep
}

/**
 * Alias for mapped checklist used by UI hooks and panels.
 */
export type VerificationResult = VerificationChecklist

export interface VerificationStep {
  valid: boolean
  message: string
  error?: string
}

/**
 * A VC as persisted in BrowserStore or WASRemoteStore, keyed by its CID.
 */
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
