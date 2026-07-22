/**
 * VC-related types for the wallet UI: display projection, verification
 * results, and the StoredCredential wrapper returned by the storage layer.
 */
import type {
  IVerifiableCredential,
  IAlignment
} from '@interop/data-integrity-core'

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
 * Legacy verify payload synthesized by `@/lib/verify` for the UI layer.
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
 * DCW five-step checklist; `expiry` / `status` alias ResumeCredentialCard
 * fields.
 */
export interface VerificationChecklist {
  supportedFormat: VerificationStep
  signature: VerificationStep
  issuer: VerificationStep
  revocation: VerificationStep
  expiration: VerificationStep
  /**
   * @deprecated Use `expiration`.
   */
  expiry: VerificationStep
  /**
   * @deprecated Use `revocation`.
   */
  status: VerificationStep
}

export type VerificationResult = VerificationChecklist

export type VerificationStepStatus = 'positive' | 'warning' | 'negative'

export interface VerificationStep {
  valid: boolean
  message: string
  status: VerificationStepStatus
  error?: string
}

export type VerificationAggregateStatus =
  'verified' | 'warning' | 'not_verified'

/**
 * A VC as returned by the storage layer. The `cid` is the credential's
 * content cid (a hash of the canonicalized VC, see `src/lib/cidFrom.ts`),
 * which keys the content-addressed local `private-credentials` collection.
 */
export interface StoredCredential {
  cid: string
  vc: IVerifiableCredential
}
