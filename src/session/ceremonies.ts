/**
 * The typed ceremony vocabulary: wallet-core's shared `CEREMONY_IDS`
 * extended with the app-only ceremonies -- account deletion and the shared
 * wipe executor -- that have no wallet-core counterpart. The ids are
 * code-only: nothing persists them anywhere (not in the account log, not in
 * local storage); they exist so a ceremony can be named consistently in
 * code, tests, and error reporting. The doc counterpart test
 * (`ceremonyInventoryCounterpart.test.ts`) keeps this list and
 * ARCHITECTURE.md's "Ceremony inventory" table in sync.
 */
import { CEREMONY_IDS } from '@interop/wallet-core'

/**
 * The app-only ceremonies: ones with no wallet-core shared half.
 */
export const APP_CEREMONY_IDS = ['account-deletion', 'wallet-wipe'] as const

/**
 * The full freewallet ceremony vocabulary: wallet-core's shared ids plus
 * the app-only ones above.
 */
export const FREEWALLET_CEREMONY_IDS = [
  ...CEREMONY_IDS,
  ...APP_CEREMONY_IDS
] as const

export type FreewalletCeremonyId = (typeof FREEWALLET_CEREMONY_IDS)[number]
