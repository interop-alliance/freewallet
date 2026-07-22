import type { TFunction } from 'i18next'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { buildVerificationChecklist } from '@interop/wallet-core/display'
import type { ChecklistMsgKey } from '@interop/wallet-core/display'
import type { VerificationResult } from '@/types/credential'

const CHECKLIST_MSG: Record<ChecklistMsgKey, string> = {
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
}

/**
 * Builds the localized `labels` map the shared checklist builder consumes: each
 * message key resolved through i18next when a `TFunction` is supplied, else the
 * English default.
 */
function checklistLabels(t?: TFunction): Record<ChecklistMsgKey, string> {
  const keys = Object.keys(CHECKLIST_MSG) as ChecklistMsgKey[]
  return Object.fromEntries(
    keys.map(key => [
      key,
      t ? t(`verification.checklist.${key}`) : CHECKLIST_MSG[key]
    ])
  ) as Record<ChecklistMsgKey, string>
}

/**
 * Maps `verifyCredential` output to the five-step DCW checklist, applying
 * Freewallet's localized messages. Thin `TFunction` wrapper over the shared
 * `buildVerificationChecklist` (which takes an injected `labels` map).
 */
export function verifyResultToChecklist(
  raw: Record<string, unknown>,
  credential: IVerifiableCredential,
  t?: TFunction
): VerificationResult {
  return buildVerificationChecklist(raw, credential, checklistLabels(t))
}
