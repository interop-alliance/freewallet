/**
 * The archived Resources the content-migration tests feed the import methods:
 * a credential, a contact head, a contact revision, and the two activity
 * shapes the walk classifies. They are shared between the store-level tests
 * and the ceremony's, so both sides argue about the same bodies.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type {
  ContactData,
  ContactHeadPayload,
  ContactRevisionPayload
} from '@interop/social-core'
import type { WalletActivity } from '@/stores/storageManager'

/**
 * The timestamp every fixture carries unless it is given another.
 */
export const FIXTURE_TIMESTAMP = '2024-03-04T05:06:07.000Z'

/**
 * An ordinary archived credential.
 *
 * @param name {string}
 * @returns {IVerifiableCredential}
 */
export function credentialResource(name: string): IVerifiableCredential {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    issuer: 'did:key:z6MkOldWalletIssuer',
    credentialSubject: { id: 'did:key:z6MkOldWalletSubject', name }
  } as unknown as IVerifiableCredential
}

/**
 * An archived contact head, as the old wallet sealed it.
 *
 * @param options {object}
 * @param options.contactId {string}
 * @param options.displayName {string}
 * @param [options.updatedAt] {string}
 * @param [options.writerId] {string}
 * @returns {ContactHeadPayload}
 */
export function headResource({
  contactId,
  displayName,
  updatedAt = FIXTURE_TIMESTAMP,
  writerId = 'old-writer'
}: {
  contactId: string
  displayName: string
  updatedAt?: string
  writerId?: string
}): ContactHeadPayload {
  return {
    contactId,
    updatedAt,
    writerId,
    contact: { displayName } as ContactData
  }
}

/**
 * An archived contact revision, as the old wallet sealed it.
 *
 * @param options {object}
 * @param options.contactId {string}
 * @param options.displayName {string}
 * @param [options.timestamp] {string}
 * @returns {ContactRevisionPayload}
 */
export function revisionResource({
  contactId,
  displayName,
  timestamp = FIXTURE_TIMESTAMP
}: {
  contactId: string
  displayName: string
  timestamp?: string
}): ContactRevisionPayload {
  return {
    contactId,
    action: 'update',
    timestamp,
    writerId: 'old-writer',
    snapshot: { displayName } as ContactData
  }
}

/**
 * An archived activity carrying its own id.
 *
 * @param options {object}
 * @param options.id {string}
 * @param options.summary {string}
 * @returns {WalletActivity}
 */
export function activityResource({
  id,
  summary
}: {
  id: string
  summary: string
}): WalletActivity {
  return {
    id,
    type: ['Create'],
    summary,
    published: FIXTURE_TIMESTAMP
  } as unknown as WalletActivity
}

/**
 * An archived credential activity, in the shape `credentialActivityInfo`
 * classifies.
 *
 * @param options {object}
 * @param options.id {string}
 * @param options.type {string}   `Create`, `Delete`, `Share`, or `Unshare`
 * @param options.cid {string}
 * @returns {WalletActivity}
 */
export function credentialActivityResource({
  id,
  type,
  cid
}: {
  id: string
  type: string
  cid: string
}): WalletActivity {
  return {
    id,
    type: [type],
    summary: `Credential ${type.toLowerCase()}d.`,
    actor: { email: 'old@example.com' },
    object: { cid, title: 'A credential' },
    created: '2024-03-04T05:06:09.000Z'
  } as unknown as WalletActivity
}

/**
 * An archived activity of a type that records an authority event on the old
 * account rather than a credential's own history.
 *
 * @param options {object}
 * @param options.id {string}
 * @param options.type {string}
 * @returns {WalletActivity}
 */
export function authorityActivityResource({
  id,
  type
}: {
  id: string
  type: string
}): WalletActivity {
  return {
    id,
    type: [type],
    summary: `${type} on the old account.`,
    actor: { email: 'old@example.com' },
    object: { origin: 'https://old.example' },
    created: '2024-03-04T05:06:10.000Z'
  } as unknown as WalletActivity
}
