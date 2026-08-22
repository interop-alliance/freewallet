import type { TFunction } from 'i18next'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { buildVerificationChecklist } from '@interop/vc-display'
import type { ChecklistMsgKey } from '@interop/vc-display'
import type { VerificationResult } from '@/types/credential'

/**
 * The checklist message keys, in the order the shared builder expects them.
 * The strings themselves live only in the locale files, under
 * `verification.checklist.*`.
 */
const CHECKLIST_MSG_KEYS: ChecklistMsgKey[] = [
  'supportedFormatOk',
  'supportedFormatFail',
  'signatureOk',
  'signatureFail',
  'issuerOk',
  'issuerFail',
  'revocationOk',
  'revocationFail',
  'expirationOk',
  'expirationFail',
  'noExpiration'
]

/**
 * Builds the localized `labels` map the shared checklist builder consumes:
 * each message key resolved through i18next.
 *
 * @param t {TFunction}
 * @returns {Record<ChecklistMsgKey, string>}
 */
function checklistLabels(t: TFunction): Record<ChecklistMsgKey, string> {
  return Object.fromEntries(
    CHECKLIST_MSG_KEYS.map(key => [key, t(`verification.checklist.${key}`)])
  ) as Record<ChecklistMsgKey, string>
}

/**
 * Maps `verifyCredential` output to the five-step DCW checklist, applying
 * Freewallet's localized messages. Thin `TFunction` wrapper over the shared
 * `buildVerificationChecklist` (which takes an injected `labels` map).
 *
 * @param options {object}
 * @param options.raw {Record<string, unknown>}
 * @param options.credential {IVerifiableCredential}
 * @param options.t {TFunction}
 * @returns {VerificationResult}
 */
export function verifyResultToChecklist({
  raw,
  credential,
  t
}: {
  raw: Record<string, unknown>
  credential: IVerifiableCredential
  t: TFunction
}): VerificationResult {
  return buildVerificationChecklist(raw, credential, checklistLabels(t))
}
