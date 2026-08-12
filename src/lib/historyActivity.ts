/**
 * Classifies a `wallet-activity` record into the History page's tabs.
 */
import type { WalletActivity } from '@/stores/storageManager'

export type HistoryTab = 'all' | 'credentials' | 'login' | 'applications'

const COLLECTION_SHARE_TYPES = ['CollectionShare', 'CollectionUnshare']

export type CredentialActivityVerb =
  'created' | 'deleted' | 'shared' | 'unshared'

const CREDENTIAL_ACTIVITY_VERBS: Record<string, CredentialActivityVerb> = {
  Create: 'created',
  Delete: 'deleted',
  Share: 'shared',
  Unshare: 'unshared'
}

const CREDENTIAL_ACTIVITY_TYPES = Object.keys(CREDENTIAL_ACTIVITY_VERBS)

export interface CredentialActivityInfo {
  cid: string
  title?: string
  verb: CredentialActivityVerb
}

/**
 * Extracts the credential-display fields (cid, title when known, and the
 * past-tense verb) out of a single-credential activity record, or `null`
 * when `doc` isn't one (a collection share, a login, a revoke, ...).
 *
 * `object` carries `{ cid, title }` for records written after the title
 * field was introduced, and a bare cid string for older records -- both
 * shapes are handled so old history entries keep rendering.
 *
 * @param doc {WalletActivity}
 * @returns {CredentialActivityInfo | null}
 */
export function credentialActivityInfo(
  doc: WalletActivity
): CredentialActivityInfo | null {
  const verbType = (doc.type ?? []).find(type =>
    Object.hasOwn(CREDENTIAL_ACTIVITY_VERBS, type)
  )
  if (!verbType || !doc.summary?.startsWith('Credential ')) {
    return null
  }
  const verb = CREDENTIAL_ACTIVITY_VERBS[verbType]
  const object = doc.object
  if (typeof object === 'string') {
    return { cid: object, verb }
  }
  if (object && typeof object === 'object' && 'cid' in object) {
    const { cid, title } = object as { cid: string; title?: string }
    return { cid, title, verb }
  }
  return null
}

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
