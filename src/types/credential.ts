/**
 * VC-related types for the wallet UI: display projection, verification
 * results, and the StoredCredential wrapper returned by the storage layer.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'

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
    /**
     * Present only on a fatal verification failure (nothing about the
     * credential could be checked); the UI renders its `message`.
     */
    error?: {
      details: { cause: { message: string; name: string } }
      message: string
      name: string
      isFatal: boolean
    }
  }>
  hasStatusError?: boolean
}

/**
 * DCW five-step checklist; `expiry` / `status` alias ResumeCredentialCard
 * fields.
 */
export interface VerificationResult {
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

export type VerificationStepStatus = 'positive' | 'warning' | 'negative'

export interface VerificationStep {
  valid: boolean
  message: string
  status: VerificationStepStatus
  error?: string
}

/**
 * A VC as returned by the storage layer. The `cid` is the credential's
 * content cid (a hash of the canonicalized VC, see `cidFrom` in
 * `@interop/was-client/sync`),
 * which keys the content-addressed local `private-credentials` collection.
 */
export interface StoredCredential {
  cid: string
  vc: IVerifiableCredential
}
