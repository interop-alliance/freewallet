import { loadOnce } from 'credential-handler-polyfill'
import { installHandler } from 'web-credential-handler'
import { MEDIATOR } from '@/app.config'

export async function registerWallet(): Promise<void> {
  try {
    await loadOnce(MEDIATOR)
    await installHandler()
    console.log('Wallet registered with browser.')
  } catch (e) {
    console.error('Wallet registration failed:', e)
  }
}
