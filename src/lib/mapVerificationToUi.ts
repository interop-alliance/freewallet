import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import type { VerificationResult, VerificationStep } from '@/types/credential'
import { getExpirationInstant } from '@/lib/formatDate'

const STEP_ID = {
  validSignature: 'valid_signature',
  expiration: 'expiration',
  revocation: 'revocation_status',
  registeredIssuer: 'registered_issuer'
} as const

type LogLine = {
  id: string
  valid?: boolean
  error?: { message?: string; name?: string }
  foundInRegistries?: string[]
}

function getVerifyLogLines(raw: Record<string, unknown>): LogLine[] {
  const results = raw.results as Array<{ log?: LogLine[] }> | undefined
  const logFromFirstResult = results?.[0]?.log
  if (logFromFirstResult && Array.isArray(logFromFirstResult)) {
    return logFromFirstResult
  }
  const topLevelLog = raw.log
  if (Array.isArray(topLevelLog)) {
    return topLevelLog as LogLine[]
  }
  return []
}

function stepFromLogEntry(
  entry: LogLine | undefined,
  okMessage: string,
  failMessage: string
): VerificationStep {
  if (!entry) {
    return {
      valid: false,
      message: failMessage,
      error: 'Missing verification step'
    }
  }
  const errMsg = entry.error?.message
  const ok = entry.valid === true && !entry.error
  if (ok) {
    return { valid: true, message: okMessage }
  }
  return {
    valid: false,
    message: failMessage,
    ...(errMsg ? { error: errMsg } : {})
  }
}

function combineSignatureAndIssuer(
  sig: VerificationStep,
  issuer: LogLine | undefined
): VerificationStep {
  if (!issuer) {
    return sig
  }
  const issuerOk = issuer.valid === true && !issuer.error
  const issuerErr = issuer.error?.message
  if (issuerOk && sig.valid) {
    return sig
  }
  if (!issuerOk && issuerErr) {
    return {
      valid: false,
      message: 'Cryptographic or issuer registry check did not pass',
      error: sig.error ? `${sig.error} — Issuer: ${issuerErr}` : issuerErr
    }
  }
  if (!sig.valid) {
    return sig
  }
  return {
    valid: false,
    message: 'Issuer not listed in configured trusted registries',
    error: issuerErr
  }
}

/** Maps the return value of `verifyCredential` in `@/lib/verify` to Signature / Expiry / Revocation checklist rows. */
export function verifyResultToChecklist(
  raw: Record<string, unknown>,
  credential: IVerifiableCredential
): VerificationResult {
  const log = getVerifyLogLines(raw)
  const byId = (id: string) =>
    log.find(line => line.id === id)

  const resultsWithError = raw.results as
    | Array<{ error?: { message?: string } }>
    | undefined
  const firstResult = resultsWithError?.[0]
  const globalErr =
    typeof firstResult?.error?.message === 'string'
      ? firstResult.error.message
      : undefined

  const withGlobalErr = (step: VerificationStep) =>
    !step.valid && !step.error && globalErr
      ? { ...step, error: globalErr }
      : step

  const signature = combineSignatureAndIssuer(
    stepFromLogEntry(
      byId(STEP_ID.validSignature),
      'Cryptographic proof verified',
      'Cryptographic proof could not be verified'
    ),
    byId(STEP_ID.registeredIssuer)
  )

  let expiry = stepFromLogEntry(
    byId(STEP_ID.expiration),
    'Credential is within its validity period',
    'Validity period check did not pass'
  )

  if (!byId(STEP_ID.expiration)) {
    const exp = getExpirationInstant(credential)
    if (!exp) {
      expiry = {
        valid: true,
        message: 'No expiration date on credential'
      }
    } else {
      const expired = exp.getTime() < Date.now()
      expiry = expired
        ? {
            valid: false,
            message: `Credential expired on ${exp.toISOString()}`
          }
        : {
            valid: true,
            message: `Valid until ${exp.toISOString()}`
          }
    }
  }

  let status: VerificationStep
  if (!credential.credentialStatus) {
    status = {
      valid: true,
      message: 'No revocation status on credential'
    }
  } else {
    status = stepFromLogEntry(
      byId(STEP_ID.revocation),
      'Revocation status checked; credential is not revoked',
      'Revocation status check did not pass'
    )
  }

  if (globalErr) {
    return {
      signature: withGlobalErr(signature),
      expiry: withGlobalErr(expiry),
      status: withGlobalErr(status)
    }
  }

  return { signature, expiry, status }
}
