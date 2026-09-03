/**
 * The signup wizard's URL contract: which step `/signup` shows, and which
 * login method it runs. Both ride the search params so a mid-wizard reload
 * keeps them. SignupPage writes them through `setSearchParams` and reads them
 * back; the lobby builds the same shape when it hands a failed run back to
 * the step the user must act on. One module, so the two cannot drift.
 */
import type { SetupMethod } from '@/stores/setupStore'

export const SIGNUP_STEP_PARAM = 'step'
export const SIGNUP_METHOD_PARAM = 'method'

/**
 * The wizard's steps in order. `start` is the login-method choice, where the
 * passphrase field lives; it is the default, so it carries no `step` param
 * and a bare `/signup` opens it.
 */
export const SIGNUP_STEPS = ['start', 'email', 'storage'] as const

export type SignupStep = (typeof SIGNUP_STEPS)[number]

/**
 * The search params naming one step of the wizard. Both defaults are omitted
 * rather than written out: the passphrase method and the `start` step are
 * what a bare `/signup` means.
 *
 * @param options {object}
 * @param options.method {SetupMethod}
 * @param options.step {SignupStep}
 * @returns {Record<string, string>}
 */
export function signupStepParams({
  method,
  step
}: {
  method: SetupMethod
  step: SignupStep
}): Record<string, string> {
  return {
    ...(method === 'passkey' ? { [SIGNUP_METHOD_PARAM]: method } : {}),
    ...(step === 'start' ? {} : { [SIGNUP_STEP_PARAM]: step })
  }
}

/**
 * The same step as a router path, for callers that navigate rather than
 * rewrite the current page's params (the lobby's hand-back).
 *
 * @param options {object}
 * @param options.method {SetupMethod}
 * @param options.step {SignupStep}
 * @returns {string}
 */
export function signupStepPath({
  method,
  step
}: {
  method: SetupMethod
  step: SignupStep
}): string {
  const query = new URLSearchParams(signupStepParams({ method, step }))
  const search = query.toString()
  return search ? `/signup?${search}` : '/signup'
}

/**
 * The step the params name, `start` for an absent or unknown value.
 *
 * @param params {URLSearchParams}
 * @returns {SignupStep}
 */
export function signupStepOf(params: URLSearchParams): SignupStep {
  const value = params.get(SIGNUP_STEP_PARAM)
  return SIGNUP_STEPS.find(step => step === value) ?? 'start'
}

/**
 * The login method the params name. Passphrase is the default: an absent or
 * unknown value means the passphrase path.
 *
 * @param params {URLSearchParams}
 * @returns {SetupMethod}
 */
export function signupMethodOf(params: URLSearchParams): SetupMethod {
  return params.get(SIGNUP_METHOD_PARAM) === 'passkey'
    ? 'passkey'
    : 'passphrase'
}
