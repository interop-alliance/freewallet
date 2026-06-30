/**
 * VC-related types for the wallet UI: display projection, verification
 * results, and the StoredCredential wrapper used by both BrowserStore and
 * WASRemoteStore.
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

/** DCW five-step checklist; `expiry` / `status` alias ResumeCredentialCard fields. */
export interface VerificationChecklist {
  supportedFormat: VerificationStep
  signature: VerificationStep
  issuer: VerificationStep
  revocation: VerificationStep
  expiration: VerificationStep
  /** @deprecated Use `expiration`. */
  expiry: VerificationStep
  /** @deprecated Use `revocation`. */
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
 * A VC as persisted in BrowserStore or WASRemoteStore. The `cid` field is an
 * opaque storage/route id: in local BrowserStore mode it is the content cid
 * (a hash of the VC); in remote mode the encrypted `private-credentials`
 * collection mints an EDV id and that is carried here instead. Treat it as an
 * opaque key -- do not re-hash or validate it as a content cid.
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
