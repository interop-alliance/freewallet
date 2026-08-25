import { loadOnce } from 'credential-handler-polyfill'
import { installHandler } from 'web-credential-handler'
import { DEPLOY_URL, MEDIATOR_BASE } from '@/app.config'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:chapi:register')

/**
 * The native WebAuthn `create()`, bound to its container before the CHAPI
 * polyfill runs (this module always loads before the polyfill does). The
 * polyfill wraps `navigator.credentials` in a Proxy and installs its own
 * bound `get`/`store` -- but `create` falls through the Proxy's default trap
 * as an unbound native method, so calling it post-polyfill throws
 * `TypeError: Illegal invocation`, breaking every passkey registration.
 * `registerWallet` re-attaches this bound original after the polyfill loads.
 */
const nativeCredentialsCreate = navigator.credentials?.create?.bind(
  navigator.credentials
)

/**
 * Reads the current 'credentialhandler' permission state from the mediator
 * without prompting the user. The polyfill attaches its permission manager to
 * `navigator.credentialsPolyfill` once `loadOnce` has run.
 *
 * @returns {Promise<string>} The permission state (e.g. 'granted', 'denied',
 *   'prompt'); 'prompt' if the polyfill is unavailable or the query fails.
 */
async function queryHandlerPermission(): Promise<string> {
  const polyfill = (
    navigator as unknown as {
      credentialsPolyfill?: {
        permissions: {
          query(desc: { name: string }): Promise<{ state: string }>
        }
      }
    }
  ).credentialsPolyfill
  if (!polyfill) {
    return 'prompt'
  }
  try {
    const status = await polyfill.permissions.query({
      name: 'credentialhandler'
    })
    return status.state
  } catch {
    return 'prompt'
  }
}

/**
 * Registers this wallet as a CHAPI credential handler with the mediator.
 *
 * `installHandler()` calls the mediator's `permissions.request()`, which always
 * shows the "Allow Wallet" prompt. To keep registration effectively run-once we
 * first query the existing permission state (a non-prompting call) and only
 * install the handler when the origin has not already been granted.
 */
export async function registerWallet(): Promise<void> {
  // The mediator origin must match where the handler pages are served from,
  // so the page's own origin is the correct default when no deploy URL is
  // configured.
  const walletOrigin = DEPLOY_URL || window.location.origin
  const mediatedWalletUrl = MEDIATOR_BASE + encodeURIComponent(walletOrigin)
  log.debug('Registering wallet with the mediator', { mediatedWalletUrl })
  try {
    await loadOnce(mediatedWalletUrl)
    if (nativeCredentialsCreate) {
      // Restore a working WebAuthn `create` on the polyfill's Proxy (its set
      // trap lands this on the underlying native container, shadowing the
      // prototype method the Proxy would otherwise return unbound).
      navigator.credentials.create = nativeCredentialsCreate
    }
    if ((await queryHandlerPermission()) === 'granted') {
      log.info('Wallet already registered with browser')
      return
    }
    await installHandler()
    log.info('Wallet registered with browser')
  } catch (err) {
    log.error('Wallet registration failed', { err })
  }
}
