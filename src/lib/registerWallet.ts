import { loadOnce } from 'credential-handler-polyfill'
import { installHandler } from 'web-credential-handler'
import { DEPLOY_URL, MEDIATOR_BASE } from '@/app.config'

export async function registerWallet(): Promise<void> {
  const mediatedWalletUrl = MEDIATOR_BASE + encodeURIComponent(DEPLOY_URL)
  console.log(`Registering wallet at ${mediatedWalletUrl}...`)
  try {
    await loadOnce(mediatedWalletUrl)
    await installHandler()
    console.log('Wallet registered with browser.')
  } catch (e) {
    console.error('Wallet registration failed:', e)
  }
}
