/**
 * Pure WebAuthn / PRF ceremony logic for passkey-based unlock. Runs the
 * `create()` (registration) and `get()` (assertion) ceremonies with fully
 * self-generated challenges -- there is no relying-party verifier here, so the
 * challenge is throwaway; the single security property consumed downstream is
 * the WebAuthn PRF output, which a replayed assertion never exposes. This
 * module knows nothing about sessions or React: it traffics in raw byte
 * arrays (credential ids, user handles, the 32-byte PRF output) and leaves
 * key derivation to its callers.
 */
import { PASSKEY_PRF_INPUT, PASSKEY_RP_ID } from '@/app.config'

/**
 * Result of a passkey registration ceremony. `prfOutput` is exactly 32 bytes;
 * `backupEligibility` / `backupState` are the BE / BS authenticator-data flags
 * parsed at creation, surfaced so callers can warn about device-bound (not
 * synced) passkeys.
 */
export interface PasskeyRegistration {
  credentialId: Uint8Array
  transports: string[]
  prfOutput: Uint8Array
  backupEligibility: boolean
  backupState: boolean
}

/**
 * Result of a passkey assertion ceremony. `userHandle` is the discoverable
 * credential's stored user handle when the authenticator returns one, else
 * null. `prfOutput` is exactly 32 bytes.
 */
export interface PasskeyAssertion {
  credentialId: Uint8Array
  userHandle: Uint8Array | null
  prfOutput: Uint8Array
}

/**
 * Raised when the user dismisses or aborts a passkey ceremony
 * (`NotAllowedError` / `AbortError`, or a declined PRF retry).
 */
export class PasskeyCancelledError extends Error {
  constructor(message = 'The passkey operation was cancelled.') {
    super(message)
    this.name = 'PasskeyCancelledError'
  }
}

/**
 * Raised when the authenticator or browser cannot evaluate the WebAuthn PRF
 * extension, so no unlock secret can be derived from this passkey.
 */
export class PasskeyPrfUnsupportedError extends Error {
  constructor(
    message = 'This passkey or browser cannot evaluate the PRF extension.'
  ) {
    super(message)
    this.name = 'PasskeyPrfUnsupportedError'
  }
}

/**
 * Raised when registration hits an `excludeCredentials` entry
 * (`InvalidStateError`): a passkey for this wallet already exists on the
 * chosen authenticator.
 */
export class PasskeyDuplicateError extends Error {
  constructor(
    message = 'A passkey for this wallet already exists on this authenticator.'
  ) {
    super(message)
    this.name = 'PasskeyDuplicateError'
  }
}

/**
 * Copies any BufferSource into a fresh, standalone Uint8Array so callers never
 * hold a view onto a WebAuthn-owned buffer.
 *
 * @param source {BufferSource}
 * @returns {Uint8Array}
 */
function copyBytes(source: BufferSource): Uint8Array {
  if (source instanceof ArrayBuffer) {
    return new Uint8Array(source.slice(0))
  }
  return new Uint8Array(
    source.buffer.slice(
      source.byteOffset,
      source.byteOffset + source.byteLength
    )
  )
}

/**
 * Generates a fresh 32-byte challenge. It is never verified (there is no RP
 * verifier), but WebAuthn requires one and it must be unpredictable.
 *
 * @returns {Uint8Array<ArrayBuffer>}
 */
function randomChallenge(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(32))
}

// The PRF extension input, shared by every ceremony. The cast satisfies the
// strict `BufferSource` (ArrayBuffer-backed) shape lib.dom expects while
// preserving the exact `PASSKEY_PRF_INPUT` reference.
const PRF_EXTENSION: AuthenticationExtensionsClientInputs = {
  prf: { eval: { first: PASSKEY_PRF_INPUT as BufferSource } }
}

/**
 * Translates a DOMException thrown by a WebAuthn ceremony into a typed passkey
 * error, rethrowing anything unrecognised unchanged. `duplicateEligible` is
 * true only for `create()`, where `InvalidStateError` means an
 * `excludeCredentials` match rather than a generic failure.
 *
 * @param options {object}
 * @param options.err {unknown}   the caught error
 * @param options.duplicateEligible {boolean}   whether InvalidStateError maps
 *   to PasskeyDuplicateError (create() only)
 * @returns {never}
 */
function mapCeremonyError({
  err,
  duplicateEligible
}: {
  err: unknown
  duplicateEligible: boolean
}): never {
  if (err instanceof DOMException) {
    if (err.name === 'NotAllowedError' || err.name === 'AbortError') {
      throw new PasskeyCancelledError(err.message)
    }
    if (duplicateEligible && err.name === 'InvalidStateError') {
      throw new PasskeyDuplicateError(err.message)
    }
  }
  throw err
}

/**
 * Builds the `create()` publicKey options for a passkey registration. The RP
 * id comes from PASSKEY_RP_ID (undefined by default, so the page origin's
 * registrable domain applies), the challenge is throwaway, and the credential
 * is discoverable (resident) with user verification required. PRF is requested
 * with the fixed app-wide eval input.
 *
 * @param options {object}
 * @param options.userHandle {Uint8Array}   the WebAuthn user handle (user.id)
 * @param options.userName {string}   cosmetic account name shown in pickers
 * @param [options.excludeCredentialIds] {Uint8Array[]}   ids to reject as
 *   same-authenticator duplicates
 * @returns {PublicKeyCredentialCreationOptions}
 */
export function buildRegistrationOptions({
  userHandle,
  userName,
  excludeCredentialIds = []
}: {
  userHandle: Uint8Array
  userName: string
  excludeCredentialIds?: Uint8Array[]
}): PublicKeyCredentialCreationOptions {
  return {
    rp: { id: PASSKEY_RP_ID, name: 'Freewallet' },
    user: {
      id: userHandle as BufferSource,
      name: userName,
      displayName: userName
    },
    challenge: randomChallenge(),
    pubKeyCredParams: [
      { type: 'public-key', alg: -8 }, // EdDSA
      { type: 'public-key', alg: -7 }, // ES256
      { type: 'public-key', alg: -257 } // RS256
    ],
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required'
    },
    excludeCredentials: excludeCredentialIds.map(id => ({
      type: 'public-key',
      id: id as BufferSource
    })),
    attestation: 'none',
    extensions: PRF_EXTENSION
  }
}

/**
 * Builds the `get()` publicKey options for a passkey assertion. An empty
 * `credentialIds` yields the discoverable one-tap flow (the browser account
 * picker scopes to the RP id); a non-empty list restricts the ceremony to
 * specific credentials (retry / tap-to-revoke flows).
 *
 * @param options {object}
 * @param [options.credentialIds] {Uint8Array[]}   restrict to these credentials
 * @returns {PublicKeyCredentialRequestOptions}
 */
export function buildAssertionOptions({
  credentialIds = []
}: {
  credentialIds?: Uint8Array[]
}): PublicKeyCredentialRequestOptions {
  return {
    rpId: PASSKEY_RP_ID,
    challenge: randomChallenge(),
    allowCredentials: credentialIds.map(id => ({
      type: 'public-key',
      id: id as BufferSource
    })),
    userVerification: 'required',
    extensions: PRF_EXTENSION
  }
}

/**
 * Parses the backup-eligibility (BE, 0x08) and backup-state (BS, 0x10) flags
 * from authenticator data. The flags byte sits at index 32 (after the 32-byte
 * RP id hash); a buffer too short to contain it yields both flags false.
 *
 * @param authenticatorData {ArrayBuffer | Uint8Array}
 * @returns {{ backupEligibility: boolean, backupState: boolean }}
 */
export function parseBackupFlags(authenticatorData: ArrayBuffer | Uint8Array): {
  backupEligibility: boolean
  backupState: boolean
} {
  const bytes =
    authenticatorData instanceof Uint8Array
      ? authenticatorData
      : new Uint8Array(authenticatorData)
  const flags = bytes.length > 32 ? bytes[32] : 0
  return {
    backupEligibility: (flags & 0x08) !== 0,
    backupState: (flags & 0x10) !== 0
  }
}

/**
 * Reads the PRF `results.first` value from a ceremony's client-extension
 * results, or null when absent.
 *
 * @param credential {PublicKeyCredential}
 * @returns {Uint8Array | null}
 */
function prfResult(credential: PublicKeyCredential): Uint8Array | null {
  const first = credential.getClientExtensionResults().prf?.results?.first
  return first ? copyBytes(first) : null
}

/**
 * Reads the authenticator transports advertised by a just-created credential,
 * guarding against older browsers that lack `getTransports()`.
 *
 * @param response {AuthenticatorAttestationResponse}
 * @returns {string[]}
 */
function readTransports(response: AuthenticatorAttestationResponse): string[] {
  return typeof response.getTransports === 'function'
    ? response.getTransports()
    : []
}

/**
 * Reads the BE / BS flags from a just-created credential, guarding against
 * older browsers that lack `getAuthenticatorData()` (both default to false).
 *
 * @param response {AuthenticatorAttestationResponse}
 * @returns {{ backupEligibility: boolean, backupState: boolean }}
 */
function readBackupFlags(response: AuthenticatorAttestationResponse): {
  backupEligibility: boolean
  backupState: boolean
} {
  if (typeof response.getAuthenticatorData !== 'function') {
    return { backupEligibility: false, backupState: false }
  }
  return parseBackupFlags(response.getAuthenticatorData())
}

/**
 * Creates a discoverable passkey and returns its PRF output alongside the
 * credential id, transports, and backup flags. Many authenticators evaluate
 * PRF only during assertion, not creation, so when `create()` yields no PRF
 * result this runs a follow-up `get()` restricted to the just-created
 * credential -- but only after `promptForPrfRetry()` consents, since that
 * second ceremony needs a fresh user gesture.
 *
 * @param options {object}
 * @param options.userHandle {Uint8Array}   the WebAuthn user handle (user.id)
 * @param options.userName {string}   cosmetic account name shown in pickers
 * @param [options.excludeCredentialIds] {Uint8Array[]}   reject these as
 *   same-authenticator duplicates
 * @param options.promptForPrfRetry {() => boolean | Promise<boolean>}
 *   resolves true to run the follow-up assertion, false to cancel
 * @param [options.signal] {AbortSignal}   aborts the ceremony
 * @returns {Promise<PasskeyRegistration>}
 */
export async function registerPasskey({
  userHandle,
  userName,
  excludeCredentialIds = [],
  promptForPrfRetry,
  signal
}: {
  userHandle: Uint8Array
  userName: string
  excludeCredentialIds?: Uint8Array[]
  promptForPrfRetry: () => boolean | Promise<boolean>
  signal?: AbortSignal
}): Promise<PasskeyRegistration> {
  const publicKey = buildRegistrationOptions({
    userHandle,
    userName,
    excludeCredentialIds
  })

  let credential: PublicKeyCredential
  try {
    credential = (await navigator.credentials.create({
      publicKey,
      signal
    })) as PublicKeyCredential
  } catch (err) {
    mapCeremonyError({ err, duplicateEligible: true })
  }

  const response = credential.response as AuthenticatorAttestationResponse
  const transports = readTransports(response)
  const { backupEligibility, backupState } = readBackupFlags(response)
  const credentialId = copyBytes(credential.rawId)

  let prfOutput = prfResult(credential)
  if (!prfOutput) {
    prfOutput = await resolvePrfViaAssertion({
      credential,
      transports,
      promptForPrfRetry,
      signal
    })
  }

  return {
    credentialId,
    transports,
    prfOutput,
    backupEligibility,
    backupState
  }
}

/**
 * Runs the follow-up assertion that evaluates PRF for a freshly created
 * credential when `create()` did not. A `prf.enabled === false` output means
 * the authenticator refuses PRF outright (hard-unsupported, no prompt); any
 * other missing-result case is retryable and gated on user consent. If the
 * retry assertion still returns no PRF result, PRF is unsupported (no second
 * retry).
 *
 * @param options {object}
 * @param options.credential {PublicKeyCredential}   the just-created credential
 * @param options.transports {string[]}   its advertised transports
 * @param options.promptForPrfRetry {() => boolean | Promise<boolean>}
 * @param [options.signal] {AbortSignal}
 * @returns {Promise<Uint8Array>}
 */
async function resolvePrfViaAssertion({
  credential,
  transports,
  promptForPrfRetry,
  signal
}: {
  credential: PublicKeyCredential
  transports: string[]
  promptForPrfRetry: () => boolean | Promise<boolean>
  signal?: AbortSignal
}): Promise<Uint8Array> {
  const prf = credential.getClientExtensionResults().prf
  // An explicit `enabled === false` means the authenticator will never yield a
  // PRF output; retrying cannot help.
  if (prf?.enabled === false) {
    throw new PasskeyPrfUnsupportedError()
  }

  const consented = await promptForPrfRetry()
  if (!consented) {
    throw new PasskeyCancelledError()
  }

  let assertion: PublicKeyCredential
  try {
    assertion = (await navigator.credentials.get({
      publicKey: {
        rpId: PASSKEY_RP_ID,
        challenge: randomChallenge(),
        allowCredentials: [
          {
            type: 'public-key',
            id: credential.rawId,
            transports: transports as AuthenticatorTransport[]
          }
        ],
        userVerification: 'required',
        extensions: PRF_EXTENSION
      },
      signal
    })) as PublicKeyCredential
  } catch (err) {
    mapCeremonyError({ err, duplicateEligible: false })
  }

  const retried = prfResult(assertion)
  if (!retried) {
    throw new PasskeyPrfUnsupportedError()
  }
  return retried
}

/**
 * Evaluates the WebAuthn PRF extension via an assertion ceremony -- the
 * one-tap login / unlock path. With an empty `credentialIds` the browser's
 * account picker scopes to the RP id (discoverable flow); a non-empty list
 * restricts the ceremony to specific credentials. A missing PRF result means
 * the passkey or browser cannot unlock the wallet.
 *
 * @param options {object}
 * @param [options.credentialIds] {Uint8Array[]}   restrict to these credentials
 * @param [options.signal] {AbortSignal}   aborts the ceremony
 * @returns {Promise<PasskeyAssertion>}
 */
export async function assertPasskeyPrf({
  credentialIds = [],
  signal
}: {
  credentialIds?: Uint8Array[]
  signal?: AbortSignal
}): Promise<PasskeyAssertion> {
  const publicKey = buildAssertionOptions({ credentialIds })

  let assertion: PublicKeyCredential
  try {
    assertion = (await navigator.credentials.get({
      publicKey,
      signal
    })) as PublicKeyCredential
  } catch (err) {
    mapCeremonyError({ err, duplicateEligible: false })
  }

  const prfOutput = prfResult(assertion)
  if (!prfOutput) {
    throw new PasskeyPrfUnsupportedError()
  }

  const response = assertion.response as AuthenticatorAssertionResponse
  return {
    credentialId: copyBytes(assertion.rawId),
    userHandle: response.userHandle ? copyBytes(response.userHandle) : null,
    prfOutput
  }
}

/**
 * Reports whether this browser exposes the WebAuthn API at all. Actual PRF
 * capability is only discoverable by running a ceremony, so callers hide the
 * passkey affordances when this is false and error-map everything else.
 *
 * @returns {boolean}
 */
export function passkeySupported(): boolean {
  return typeof PublicKeyCredential !== 'undefined'
}
