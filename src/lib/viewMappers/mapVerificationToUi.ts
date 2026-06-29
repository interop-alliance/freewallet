import type { TFunction } from 'i18next'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type {
  VerificationResult,
  VerificationStep,
  VerificationStepStatus
} from '@/types/credential'
import { getExpirationInstant } from '@/lib/viewMappers/formatDate'
import { getVerifyLogFromPayload } from '@/lib/viewMappers/verifyLog'

const STEP_ID = {
  validSignature: 'valid_signature',
  expiration: 'expiration',
  revocation: 'revocation_status',
  registeredIssuer: 'registered_issuer'
} as const

const SUPPORTED_CREDENTIAL_TYPES = [
  'VerifiableCredential',
  'OpenBadgeCredential'
]

const CHECKLIST_MSG = {
  supportedFormatOk: 'is in a supported credential format',
  supportedFormatFail: 'is not a recognized credential type',
  signatureOk: 'has a valid signature',
  signatureFail: 'has an invalid signature',
  issuerOk: 'has been issued by a known issuer',
  issuerFail: "isn't in a known issuer registry",
  revocationOk: 'has not been revoked',
  revocationFail: 'has been revoked',
  expirationOk: 'has not expired',
  expirationFail: 'has expired',
  noExpiration: 'has no expiration date set'
} as const

type ChecklistMsgKey = keyof typeof CHECKLIST_MSG

type LogLine = {
  id: string
  valid?: boolean
  error?: { message?: string; name?: string }
}

function checklistText(t: TFunction | undefined, key: ChecklistMsgKey): string {
  if (!t) {
    return CHECKLIST_MSG[key]
  }
  return t(`verification.checklist.${key}`)
}

function getVerifyLogLines(raw: Record<string, unknown>): LogLine[] {
  return getVerifyLogFromPayload(raw) as LogLine[]
}

function step(
  valid: boolean,
  message: string,
  severity: VerificationStepStatus,
  error?: string
): VerificationStep {
  return {
    valid,
    message,
    status: severity,
    ...(error ? { error } : {})
  }
}

function logValid(entry: LogLine | undefined): boolean | undefined {
  if (!entry) {
    return undefined
  }
  return entry.valid === true && !entry.error
}

function supportedFormatStep(
  credential: IVerifiableCredential,
  t?: TFunction
): VerificationStep {
  const hasKnownType =
    Array.isArray(credential.type) &&
    credential.type.some(type => SUPPORTED_CREDENTIAL_TYPES.includes(type))

  return step(
    hasKnownType,
    hasKnownType
      ? checklistText(t, 'supportedFormatOk')
      : checklistText(t, 'supportedFormatFail'),
    hasKnownType ? 'positive' : 'negative'
  )
}

function signatureStep(
  entry: LogLine | undefined,
  t?: TFunction
): VerificationStep {
  const valid = logValid(entry) ?? false
  return step(
    valid,
    valid ? checklistText(t, 'signatureOk') : checklistText(t, 'signatureFail'),
    valid ? 'positive' : 'negative',
    entry?.error?.message
  )
}

function issuerStep(
  entry: LogLine | undefined,
  t?: TFunction
): VerificationStep {
  const valid = logValid(entry) ?? false
  return step(
    valid,
    valid ? checklistText(t, 'issuerOk') : checklistText(t, 'issuerFail'),
    valid ? 'positive' : 'warning',
    entry?.error?.message
  )
}

function revocationStep(
  entry: LogLine | undefined,
  credential: IVerifiableCredential,
  t?: TFunction
): VerificationStep {
  if (!credential.credentialStatus && !entry) {
    return step(true, checklistText(t, 'revocationOk'), 'positive')
  }

  const valid = logValid(entry) ?? true
  return step(
    valid,
    valid
      ? checklistText(t, 'revocationOk')
      : checklistText(t, 'revocationFail'),
    valid ? 'positive' : 'negative',
    entry?.error?.message
  )
}

function expirationStep(
  entry: LogLine | undefined,
  credential: IVerifiableCredential,
  t?: TFunction
): VerificationStep {
  const exp = getExpirationInstant(credential)
  const hasExpirationDate = exp != null

  if (!hasExpirationDate && !entry) {
    return step(true, checklistText(t, 'noExpiration'), 'positive')
  }

  if (entry) {
    const valid = logValid(entry) ?? false
    return step(
      valid,
      valid
        ? checklistText(t, 'expirationOk')
        : checklistText(t, 'expirationFail'),
      valid ? 'positive' : 'warning',
      entry.error?.message
    )
  }

  const expired = exp!.getTime() < Date.now()
  return step(
    !expired,
    expired
      ? checklistText(t, 'expirationFail')
      : checklistText(t, 'expirationOk'),
    expired ? 'warning' : 'positive'
  )
}

function withGlobalErr(
  stepValue: VerificationStep,
  globalErr?: string
): VerificationStep {
  if (stepValue.valid || !globalErr) {
    return stepValue
  }
  return { ...stepValue, error: stepValue.error ?? globalErr }
}

function attachLegacyAliases(
  checklist: Omit<VerificationResult, 'expiry' | 'status'>
): VerificationResult {
  return {
    ...checklist,
    expiry: checklist.expiration,
    status: checklist.revocation
  }
}

/**
 * Maps `verifyCredential` output to the five-step DCW checklist.
 */
export function verifyResultToChecklist(
  raw: Record<string, unknown>,
  credential: IVerifiableCredential,
  t?: TFunction
): VerificationResult {
  const log = getVerifyLogLines(raw)
  const byId = (id: string) => log.find(line => line.id === id)

  const resultsWithError = raw.results as
    | Array<{ error?: { message?: string } }>
    | undefined
  const globalErr =
    typeof resultsWithError?.[0]?.error?.message === 'string'
      ? resultsWithError[0].error.message
      : undefined

  const checklist = {
    supportedFormat: supportedFormatStep(credential, t),
    signature: signatureStep(byId(STEP_ID.validSignature), t),
    issuer: issuerStep(byId(STEP_ID.registeredIssuer), t),
    revocation: revocationStep(byId(STEP_ID.revocation), credential, t),
    expiration: expirationStep(byId(STEP_ID.expiration), credential, t)
  }

  if (!globalErr) {
    return attachLegacyAliases(checklist)
  }

  return attachLegacyAliases({
    supportedFormat: withGlobalErr(checklist.supportedFormat, globalErr),
    signature: withGlobalErr(checklist.signature, globalErr),
    issuer: withGlobalErr(checklist.issuer, globalErr),
    revocation: withGlobalErr(checklist.revocation, globalErr),
    expiration: withGlobalErr(checklist.expiration, globalErr)
  })
}
