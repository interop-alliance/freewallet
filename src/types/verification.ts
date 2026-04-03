export interface VerificationStep {
  valid: boolean
  message: string
  error?: string
}

export interface VerificationResult {
  signature: VerificationStep
  expiry: VerificationStep
  status: VerificationStep
}
