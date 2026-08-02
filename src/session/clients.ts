/**
 * The Settings "wallets connected to this account" listing: Freewallet's glue
 * over the wallet-core enrolled-client enumeration and display labels.
 *
 * - `listAccountClients` -- fetches and locally verifies the account's
 *   world-readable did:webvh log (the same `verifyAccountLog` step every
 *   ceremony uses), enumerates the enrolled clients from it
 *   (`listEnrolledWebvhClients`: keyed on `capabilityInvocation`, so a
 *   recovery code's keyAgreement-only method never appears and apps -- which
 *   are never enrolled -- cannot appear), merges the display labels from
 *   `key-map/client-labels.json`, and marks the row belonging to this
 *   session's own client.
 * - `renameAccountClient` -- writes one label (chosen at enrollment approval,
 *   editable afterwards; the document carries key material, never labels).
 * - `disconnectAccountClient` -- drives the FW-66 revocation cascade from a
 *   listed row (the row with all three key members present is exactly a
 *   `RevokedClientKeys`), then drops the disconnected client's label as
 *   hygiene.
 */
import {
  clientSigningKeyMultibase,
  isWebvhDid,
  listEnrolledWebvhClients,
  type EnrolledWebvhClient
} from '@interop/wallet-core/webvh'
import {
  readClientLabels,
  removeClientLabel,
  setClientLabel
} from '@interop/wallet-core/keys'
import type { Session } from '@/types/auth'
import { verifyAccountLog } from '@/session/recovery'
import {
  revokeEnrolledClient,
  type RevocationOutcome
} from '@/session/revocation'

/**
 * One row of the listing: the log-stated client plus its display state.
 */
export interface AccountClientView extends EnrolledWebvhClient {
  label?: string
  isCurrent: boolean
}

/**
 * Whether this session can list and manage the account's enrolled clients: a
 * configured remote store and a promoted did:webvh account pointer.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {boolean}
 */
export function canManageAccountClients({
  session
}: {
  session: Session
}): boolean {
  return (
    !!session.storage.remoteStore &&
    isWebvhDid(session.profile.accountPointer?.did)
  )
}

/**
 * Resolves the listing preconditions or throws (the UI gates on
 * `canManageAccountClients` first, so a throw here is a programming error).
 *
 * @param session {Session}
 * @returns {object}   the remote store and the account pointer
 */
function requireClientListing(session: Session) {
  const remoteStore = session.storage.remoteStore
  const pointer = session.profile.accountPointer
  if (!remoteStore || !pointer || !isWebvhDid(pointer.did)) {
    throw new Error(
      'Listing enrolled clients requires a promoted did:webvh account and a ' +
        'configured storage server.'
    )
  }
  return { remoteStore, pointer }
}

/**
 * Lists the account's enrolled wallet clients from the locally verified
 * did:webvh log, with labels merged and this session's own client marked. A
 * label-read failure degrades to unlabeled rows (the listing itself only
 * fails when the log cannot be fetched or verified).
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<AccountClientView[]>}
 */
export async function listAccountClients({
  session
}: {
  session: Session
}): Promise<AccountClientView[]> {
  const { remoteStore, pointer } = requireClientListing(session)
  const { log } = await verifyAccountLog({ pointer })
  const clients = listEnrolledWebvhClients({ log })

  const { labels } = await readClientLabels({
    store: remoteStore.clientLabelsStore()
  })
  const { keyAgent } = session.profile
  const ownSigningKey = keyAgent
    ? clientSigningKeyMultibase({ keyAgent })
    : undefined

  return clients.map(client => ({
    ...client,
    label: labels[client.signingKeyMultibase],
    isCurrent: client.signingKeyMultibase === ownSigningKey
  }))
}

/**
 * Sets (or clears, with a blank value) one enrolled client's display label.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.signingKeyMultibase {string}
 * @param options.label {string}
 * @returns {Promise<void>}
 */
export async function renameAccountClient({
  session,
  signingKeyMultibase,
  label
}: {
  session: Session
  signingKeyMultibase: string
  label: string
}): Promise<void> {
  const { remoteStore } = requireClientListing(session)
  await setClientLabel({
    store: remoteStore.clientLabelsStore(),
    signingKeyMultibase,
    label
  })
}

/**
 * Disconnects an enrolled wallet client: the full FW-66 cascade
 * (`revokeEnrolledClient` -- document edit, PUK rotation, collection
 * re-epoch, recovery re-mints, live adoption), then the label dropped as
 * best-effort hygiene. Refuses a row whose active update key the log
 * attribution could not isolate -- disconnecting with a guessed key could
 * revoke another party's authority.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.client {AccountClientView}
 * @returns {Promise<RevocationOutcome>}
 */
export async function disconnectAccountClient({
  session,
  client
}: {
  session: Session
  client: AccountClientView
}): Promise<RevocationOutcome> {
  const { remoteStore } = requireClientListing(session)
  if (!client.updateKeyMultibase) {
    throw new Error(
      "This client's update key could not be attributed from the account " +
        'log, so it cannot be disconnected from here.'
    )
  }
  const outcome = await revokeEnrolledClient({
    session,
    client: {
      signingKeyMultibase: client.signingKeyMultibase,
      keyAgreementKeyMultibase: client.keyAgreementKeyMultibase,
      updateKeyMultibase: client.updateKeyMultibase
    },
    label: client.label
  })
  try {
    await removeClientLabel({
      store: remoteStore.clientLabelsStore(),
      signingKeyMultibase: client.signingKeyMultibase
    })
  } catch (err) {
    console.warn("Could not drop the disconnected client's label:", err)
  }
  return outcome
}
