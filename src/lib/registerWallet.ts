import { loadOnce } from 'credential-handler-polyfill'
import { installHandler } from 'web-credential-handler'
import { DEPLOY_URL, MEDIATOR_BASE } from '@/app.config'

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
  const mediatedWalletUrl = MEDIATOR_BASE + encodeURIComponent(DEPLOY_URL)
  console.log(`Registering wallet at ${mediatedWalletUrl}...`)
  try {
    await loadOnce(mediatedWalletUrl)
    if ((await queryHandlerPermission()) === 'granted') {
      console.log('Wallet already registered with browser.')
      return
    }
    await installHandler()
    console.log('Wallet registered with browser.')
  } catch (err) {
    console.error('Wallet registration failed:', err)
  }
}
