/**
 * Credential verification against the DCC Known Registries. Wraps
 * @digitalcredentials/verifier-core and normalizes its output into a
 * VerifyCredentialPayload. Notable special case: if the verifier returns a
 * `status_list_not_found` error for the revocation check, that row is dropped
 * and the credential is not treated as revoked (the status list simply isn't
 * published).
 */
import * as verifierCore from '@digitalcredentials/verifier-core'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { KNOWN_REGISTRIES_URL, KnownDidRegistries } from '@/app.config'
import type { VerifyCredentialPayload } from '@/types/credential'

const CredentialErrorTypes = {
  CouldNotBeVerified:
    'Credential could not be checked for verification and may be malformed.',
  DidNotInRegistry: 'Could not find issuer in registry with given DID.'
} as const

async function loadKnownDIDRegistries() {
  try {
    const regRes = await fetch(KNOWN_REGISTRIES_URL)
    if (!regRes.ok) {
      throw new Error(`Registry fetch failed: ${regRes.status}`)
    }
    return await regRes.json()
  } catch (err) {
    console.warn('Using fallback KnownDidRegistries:', err)
    return KnownDidRegistries
  }
}

export async function verifyCredential(
  credential: IVerifiableCredential
): Promise<VerifyCredentialPayload> {
  try {
    const knownDIDRegistries = await loadKnownDIDRegistries()

    const result = (await verifierCore.verifyCredential({
      credential: credential as never,
      knownDIDRegistries
    })) as VerifyCredentialPayload

    result.verified = Array.isArray(result.log)
      ? result.log.every(check => check.valid)
      : false

    if (result?.errors) {
      const errorMessage =
        Array.isArray(result.errors) && result.errors.length > 0
          ? (result.errors[0].message ??
            CredentialErrorTypes.CouldNotBeVerified)
          : CredentialErrorTypes.CouldNotBeVerified
      return createFatalErrorResult(credential, errorMessage)
    }

    if (!result.results) {
      result.results = [
        {
          verified: (result.log ?? []).every(check => check.valid),
          log: result.log,
          credential: result.credential
        }
      ]
    }

    if (result?.verified === false) {
      const revocationIndex = (result.log ?? []).findIndex(
        c => c.id === 'revocation_status'
      )

      if (revocationIndex !== -1) {
        const revocationObject = result.log![revocationIndex]

        if (revocationObject?.error?.name === 'status_list_not_found') {
          result.log!.splice(revocationIndex, 1)

          result.verified = (result.log ?? []).every(log => log.valid)
        } else {
          const revocationResult = {
            id: 'revocation_status',
            valid: revocationObject.valid ?? false
          }

          ;(result.results[0].log ??= []).push(revocationResult)
          result.hasStatusError = !!revocationObject.error
        }
      }
    }

    if (!result.log) {
      result.verified = false
      ;(result.results[0].log ??= []).push({
        id: 'registered_issuer',
        valid: false
      })
      addErrorToResult(
        result as { results: unknown[] },
        CredentialErrorTypes.DidNotInRegistry,
        false
      )
    }

    return result
  } catch (err) {
    console.warn(err)
    return createFatalErrorResult(
      credential,
      CredentialErrorTypes.CouldNotBeVerified
    )
  }
}

function addErrorToResult(
  result: { results: unknown[] },
  message: string,
  isFatal = true
) {
  ;(result.results[0] as Record<string, unknown>).error = {
    details: {
      cause: {
        message,
        name: 'Error'
      }
    },
    message,
    name: 'Error',
    isFatal
  }
}

function createFatalErrorResult(
  credential: IVerifiableCredential,
  message: string
) {
  const result = {
    verified: false,
    results: [
      {
        verified: false,
        credential,
        log: [
          { id: 'expiration', valid: false },
          { id: 'valid_signature', valid: false },
          { id: 'issuer_did_resolves', valid: false },
          { id: 'revocation_status', valid: false }
        ]
      }
    ]
  }
  addErrorToResult(result, message, true)
  return result
}
