/**
 * Classifies a `wallet-activity` record into the History page's tabs.
 */
import type { WalletActivity } from '@/stores/storageManager'

export type HistoryTab = 'all' | 'credentials' | 'login' | 'applications'

const CREDENTIAL_ACTIVITY_TYPES = ['Create', 'Delete', 'Share', 'Unshare']
const COLLECTION_SHARE_TYPES = ['CollectionShare', 'CollectionUnshare']

/**
 * Sorts one activity into the tab it belongs under, or `'other'` when it
 * doesn't fit any of the specific tabs (shown only under the `all` tab).
 *
 * @param doc {WalletActivity}
 * @returns {Exclude<HistoryTab, 'all'> | 'other'}
 */
export function classifyActivity(
  doc: WalletActivity
): Exclude<HistoryTab, 'all'> | 'other' {
  const types = doc.type ?? []

  const isCredentialEvent =
    types.some(type => CREDENTIAL_ACTIVITY_TYPES.includes(type)) &&
    doc.summary?.startsWith('Credential ')
  if (
    isCredentialEvent ||
    types.some(type => COLLECTION_SHARE_TYPES.includes(type))
  ) {
    return 'credentials'
  }

  if (types.includes('Login')) {
    const object = doc.object as { appConnect?: unknown } | undefined
    return object?.appConnect ? 'applications' : 'login'
  }

  if (types.includes('Revoke')) {
    return 'applications'
  }

  return 'other'
}
