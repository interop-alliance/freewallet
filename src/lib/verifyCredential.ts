import * as vc from '@digitalbazaar/vc'
import { DataIntegrityProof } from '@digitalbazaar/data-integrity'
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020'
import { cryptosuite as eddsaRdfc2022Cryptosuite } from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite'
import {
  checkStatus as checkBitstringStatus,
  statusTypeMatches
} from '@digitalbazaar/vc-bitstring-status-list'
import { securityLoader } from '@digitalcredentials/security-document-loader'
import type { IVerifiableCredential } from '@digitalcredentials/ssi'

import type { VerificationResult, VerificationStep } from '@/types/verification'
import { getExpirationInstant } from '@/lib/formatDate'
import { MAX_CLOCK_SKEW_SEC, EXPIRED_MESSAGE } from '@/app.config'

let loaderInstance: ReturnType<typeof securityLoader> | null = null

function getDocumentLoader() {
  if (!loaderInstance) {
    loaderInstance = securityLoader({ fetchRemoteContexts: true })
  }
  return loaderInstance.build()
}

function getSuites() {
  return [
    new Ed25519Signature2020(),
    new DataIntegrityProof({ cryptosuite: eddsaRdfc2022Cryptosuite })
  ]
}

const skipStatusDuringVcVerify = () => Promise.resolve({ verified: true })

function isExpiredRelativeToNow(
  credential: IVerifiableCredential,
  now: Date,
  maxClockSkewSec = MAX_CLOCK_SKEW_SEC
): boolean {
  const exp = getExpirationInstant(credential)
  if (!exp || Number.isNaN(exp.getTime())) {
    return false
  }
  const t1 = now.getTime()
  const t2 = exp.getTime()
  if (Math.abs(t1 - t2) < maxClockSkewSec * 1000) {
    return false
  }
  return t1 > t2
}

function expiryStepFor(
  credential: IVerifiableCredential,
  now: Date
): VerificationStep {
  const exp = getExpirationInstant(credential)
  if (!exp) {
    return {
      valid: true,
      message: 'No expiration date on credential'
    }
  }
  const expired = isExpiredRelativeToNow(credential, now)
  const formatted = exp.toISOString()
  if (expired) {
    return {
      valid: false,
      message: `Credential expired on ${formatted}`
    }
  }
  return {
    valid: true,
    message: `Valid until ${formatted}`
  }
}

async function verifySignatureWithVc(
  credential: IVerifiableCredential,
  now: Date
): Promise<Awaited<ReturnType<typeof vc.verifyCredential>>> {
  const documentLoader = getDocumentLoader()
  const suite = getSuites()
  const hasStatus = credential.credentialStatus != null
  const base = {
    credential,
    suite,
    documentLoader,
    now,
    maxClockSkew: MAX_CLOCK_SKEW_SEC,
    ...(hasStatus ? { checkStatus: skipStatusDuringVcVerify } : {})
  }

  let result = await vc.verifyCredential(base)
  if (
    !result.verified &&
    result.error instanceof Error &&
    result.error.message === EXPIRED_MESSAGE
  ) {
    const exp = getExpirationInstant(credential)
    if (exp && !Number.isNaN(exp.getTime())) {
      const retryNow = new Date(exp.getTime() - 1000)
      result = await vc.verifyCredential({ ...base, now: retryNow })
    }
  }
  return result
}

function signatureStepFromVcResult(
  result: Awaited<ReturnType<typeof vc.verifyCredential>>
): VerificationStep {
  if (result.verified) {
    return { valid: true, message: 'Cryptographic proof verified' }
  }
  const err = result.error
  const msg =
    err instanceof Error
      ? err.message
      : typeof err === 'string'
        ? err
        : 'Signature verification failed'
  return {
    valid: false,
    message: 'Cryptographic proof could not be verified',
    error: msg
  }
}

async function revocationStep(
  credential: IVerifiableCredential
): Promise<VerificationStep> {
  if (!credential.credentialStatus) {
    return {
      valid: true,
      message: 'No revocation status on credential'
    }
  }

  if (!statusTypeMatches({ credential })) {
    return {
      valid: false,
      message: 'Revocation status present but not a Bitstring Status List',
      error: 'Unsupported or unrecognized credentialStatus for in-browser check'
    }
  }

  const documentLoader = getDocumentLoader()
  const suite = getSuites()

  const statusResult = await checkBitstringStatus({
    credential,
    documentLoader,
    suite,
    verifyBitstringStatusListCredential: true,
    verifyMatchingIssuers: true
  })

  if (statusResult.verified) {
    const revoked = statusResult.results?.some(
      (r: { status?: boolean }) => r.status === true
    )
    if (revoked) {
      return {
        valid: false,
        message: 'Credential is revoked or suspended per status list',
        error: 'Revoked or suspended'
      }
    }
    return {
      valid: true,
      message: 'Revocation status checked; credential is not revoked'
    }
  }

  const err = statusResult.error
  const msg =
    err instanceof Error ? err.message : 'Could not verify revocation status'
  return {
    valid: false,
    message: 'Could not verify revocation status',
    error: msg
  }
}

export async function verifyCredential(
  credential: IVerifiableCredential
): Promise<VerificationResult> {
  const now = new Date()

  try {
    const expiry = expiryStepFor(credential, now)
    const vcResult = await verifySignatureWithVc(credential, now)
    const signature = signatureStepFromVcResult(vcResult)

    let status: VerificationStep
    if (!credential.credentialStatus) {
      status = {
        valid: true,
        message: 'No revocation status on credential'
      }
    } else if (!vcResult.verified) {
      status = {
        valid: false,
        message:
          'Skipped revocation check because signature verification failed',
        error: signature.error
      }
    } else {
      status = await revocationStep(credential)
    }

    return { signature, expiry, status }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    const failed: VerificationStep = {
      valid: false,
      message: 'Verification error',
      error: message
    }
    return {
      signature: failed,
      expiry: failed,
      status: failed
    }
  }
}
