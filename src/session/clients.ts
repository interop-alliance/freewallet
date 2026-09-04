/**
 * The Settings "wallets connected to this account" listing: Freewallet's
 * session-shaped glue over the shared enrolled-client surface in
 * `@interop/wallet-core/clients`. The listing, the label merge, and the
 * disconnect-eligibility policy live there, so both wallets show the same rows
 * and refuse the same ones for the same reasons; what stays here is only what
 * a `Session` knows -- whether this account is manageable at all, where its
 * log lives, which key is this browser's, and dropping a disconnected client's
 * label afterwards.
 *
 * - `listAccountClients` -- the shared listing, with this session's own client
 *   marked and the label store supplied.
 * - `currentAccountSigningKeys` -- the same verified log reduced to the
 *   enrolled clients' signing-key multibases, for the Applications surface to
 *   check recorded App Connect grant signers against (the current-key-set
 *   rule: a grant signed by a since-disconnected client no longer verifies).
 *   The gating on whether a session HAS a promoted account is app-side, so
 *   this wrapper resolves `undefined` rather than throwing for a guest.
 * - `renameAccountClient` -- writes one label (chosen at enrollment approval,
 *   editable afterwards; the document carries key material, never labels).
 * - `disconnectAccountClient` -- drives the client-revocation epoch cascade
 *   from a listed row, then drops the disconnected client's label as hygiene.
 *
 * Both read paths take their log from the session's verified-log memo
 * (`src/session/verifiedLog.ts`) instead of re-verifying `did.jsonl` per
 * surface, so a label rename -- which reloads the listing afterwards -- costs
 * a labels read and nothing else.
 */
import { clientSigningKeyMultibase } from '@interop/wallet-core/webvh'
import { removeClientLabel, setClientLabel } from '@interop/wallet-core/keys'
import {
  currentAccountSigningKeys as sharedCurrentAccountSigningKeys,
  listAccountClients as sharedListAccountClients,
  revokedClientKeysFor
} from '@interop/wallet-core/clients'
import type { AccountClientView } from '@interop/wallet-core/clients'
import type { Session } from '@/types/auth'
import {
  accountCeremonyContext,
  canRunAccountCeremonies,
  enrolledCeremonyContext,
  type AccountCeremonyContext
} from '@/session/accountCeremonyContext'
import {
  revokeEnrolledClient,
  type RevocationOutcome
} from '@/session/revocation'
import { verifiedAccountLog } from '@/session/verifiedLog'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:clients')

export type { AccountClientView } from '@interop/wallet-core/clients'
export {
  cascadeCompletion,
  disconnectEligibility,
  type DisconnectRefusal
} from '@interop/wallet-core/clients'

/**
 * Whether this session can list and manage the account's enrolled clients:
 * the shared account-ceremony context -- a configured remote store, a
 * promoted did:webvh account pointer, and either this client's own key
 * material or a standing unlock credential's ladder, since Disconnect drives
 * the revocation cascade with exactly one of those two. Deriving the gate
 * from the same resolution the cascade requires is what stops the panel from
 * enabling a Disconnect that then throws.
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
  return canRunAccountCeremonies({ session })
}

/**
 * Which signer would put this session's removal entry on the account log:
 * `client` when an enrolled client's own update keys sign it, `ladder` when a
 * standing credential's rung does. The shared disconnect-eligibility policy
 * takes it, and the two refusals it lifts on the ladder branch (a client
 * disconnecting itself, and the account's last enrolled client) are
 * properties of that signer rather than of the account.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {'client' | 'ladder'}
 */
export function accountSignerKind({
  session
}: {
  session: Session
}): 'client' | 'ladder' {
  return enrolledCeremonyContext({ session }) ? 'client' : 'ladder'
}

/**
 * Resolves the listing preconditions or throws (the UI gates on
 * `canManageAccountClients` first, so a throw here is a programming error).
 *
 * @param session {Session}
 * @returns {Promise<AccountCeremonyContext>}
 */
async function requireClientListing(
  session: Session
): Promise<AccountCeremonyContext> {
  const context = await accountCeremonyContext({ session })
  if (!context) {
    throw new Error(
      'Listing enrolled clients requires an account on a storage server, ' +
        'reached either from a connected browser or with a standing ' +
        'passphrase or passkey.'
    )
  }
  return context
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
  const context = await requireClientListing(session)
  const { remoteStore, pointer } = context
  return await sharedListAccountClients({
    pointer: {
      did: pointer.did,
      spaceId: pointer.spaceId,
      host: pointer.host
    },
    verifiedLog: await verifiedAccountLog({
      profile: session.profile,
      pointer
    }),
    labelsStore: remoteStore.clientLabelsStore(),
    // "This browser" marks the row this session runs AS. A transient session
    // runs as no enrolled client at all, so no row is marked and the chip
    // does not render.
    ...(context.kind === 'enrolled'
      ? {
          ownSigningKeyMultibase: clientSigningKeyMultibase({
            keyAgent: context.keyAgent
          })
        }
      : {})
  })
}

/**
 * The signing-key multibases of the account's currently enrolled wallet
 * clients. Resolves `undefined` when this session has no promoted did:webvh
 * account to check against (a guest or no-storage session); throws when the
 * log cannot be fetched or verified (callers treating the check as
 * best-effort catch and degrade to "unknown").
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<Set<string> | undefined>}
 */
export async function currentAccountSigningKeys({
  session
}: {
  session: Session
}): Promise<Set<string> | undefined> {
  if (!canManageAccountClients({ session })) {
    return undefined
  }
  const { pointer } = await requireClientListing(session)
  return await sharedCurrentAccountSigningKeys({
    pointer: {
      did: pointer.did,
      spaceId: pointer.spaceId,
      host: pointer.host
    },
    verifiedLog: await verifiedAccountLog({
      profile: session.profile,
      pointer
    })
  })
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
  const { remoteStore } = await requireClientListing(session)
  await setClientLabel({
    store: remoteStore.clientLabelsStore(),
    signingKeyMultibase,
    label
  })
}

/**
 * Disconnects an enrolled wallet client: the full revocation cascade
 * (`revokeEnrolledClient` -- document edit, user key rotation, collection
 * re-epoch, recovery re-mints, live adoption), then the label dropped as
 * best-effort hygiene. `revokedClientKeysFor` refuses a row whose active
 * update key the log attribution could not isolate -- disconnecting with a
 * guessed key could revoke another party's authority.
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
  const context = await requireClientListing(session)
  const { remoteStore } = context
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes (the cascade re-wraps the registry); on a settled
  // session the chain resolved long ago.
  await session.registryReady
  const outcome = await revokeEnrolledClient({
    session,
    context,
    client: revokedClientKeysFor({ client }),
    ...(client.label !== undefined ? { label: client.label } : {})
  })
  try {
    await removeClientLabel({
      store: remoteStore.clientLabelsStore(),
      signingKeyMultibase: client.signingKeyMultibase
    })
  } catch (err) {
    log.warn("Could not drop the disconnected client's label", { err })
  }
  return outcome
}
