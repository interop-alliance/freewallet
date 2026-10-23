/**
 * The Settings "wallets connected to this account" listing: Freewallet's
 * session-shaped glue over the shared enrolled-client surface in
 * `@interop/wallet-core/clients`. The listing, the name join, and the
 * disconnect-eligibility policy live there, so both wallets show the same rows
 * and refuse the same ones for the same reasons; what stays here is only what
 * a `Session` knows -- whether this account is manageable at all, where its
 * log lives, which key is this browser's, and how its `connections`
 * directory is reached.
 *
 * - `listAccountClients` -- the shared listing, with this session's own client
 *   marked and the directory's wallet-client entries supplied for names.
 * - `currentAccountSignerCheck` -- the same verified log reduced to the
 *   account DID, the enrolled clients' signing-key multibases, and the
 *   delegated-clients pointer, plus the annex-document resolver, for the
 *   Applications surface and the agent grant renewal to check recorded
 *   grants against (the current-key-set rule: a grant signed by a
 *   since-disconnected client no longer verifies; a transient session's
 *   grant dies with the generation it chains under, and its own leaf is
 *   verified against that generation's annex document). The gating on
 *   whether a session HAS a promoted account is app-side, so this wrapper
 *   resolves `undefined` rather than throwing for a guest.
 * - `renameAccountClient` -- sets the user's `label` on the client's
 *   wallet-client entry (the document carries key material only).
 * - `recordWalletClientEntry` / `recordOwnWalletClientEntry` -- write a
 *   wallet-client entry's names: the approver's at enrollment, and a client
 *   naming itself at signup and self-enrollment.
 * - `disconnectAccountClient` -- drives the client-revocation epoch cascade
 *   from a listed row; the cascade retires the client's entry.
 *
 * Both read paths take their log from the session's verified-log memo
 * (`src/session/verifiedLog.ts`) instead of re-verifying `did.jsonl` per
 * surface, so a rename -- which reloads the listing afterwards -- costs one
 * directory read and nothing else.
 */
import {
  accountLogDids,
  clientSigningKeyMultibase,
  isWebvhDid,
  walletClientDid
} from '@interop/wallet-core/webvh'
import {
  delegatedClientsPointer,
  delegatedClientsPointerHistory,
  readClientAnnexLogOrAbsent
} from '@interop/wallet-core/clientAnnex'
import {
  setConnectionLabel,
  type ConnectionEntry,
  type ReadConnection
} from '@interop/wallet-core/connections'
import { epochKeyIdFor } from '@interop/was-client/edv'
import {
  currentAccountSigningKeys as sharedCurrentAccountSigningKeys,
  listAccountClients as sharedListAccountClients,
  revokedClientKeysFor
} from '@interop/wallet-core/clients'
import type { AccountClientView } from '@interop/wallet-core/clients'
import type { Session } from '@/types/auth'
import { DEFAULT_CLIENT_LABEL } from '@/app.config'
import type { AccountSignerCheck } from '@/lib/connectedApps'
import {
  accountCeremonyContext,
  canRunAccountCeremonies,
  enrolledCeremonyContext,
  sessionAnnexStanding,
  type AccountCeremonyContext
} from '@/session/accountCeremonyContext'
import { namedAnnexReachUnder } from '@/session/annexReach'
import {
  revokeEnrolledClient,
  type RevocationOutcome
} from '@/session/revocation'
import { reportCeremonyTail } from '@/session/menders/ceremonyTail'
import { listConnectionsDirectory } from '@/session/menders/encounterSites'
import { verifiedAccountLog } from '@/session/verifiedLog'
import { isBrowserLocalSession } from '@/session/persistence'
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
 * The `connections` directory's entries, from one listing read: every
 * parseable entry at its own resource id. The read is the writer sweep's
 * encounter site, which starts behind it. Throws when the directory is
 * refused or absent, or the listing fails; the client listing reads that as
 * unnamed rows.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<ConnectionEntry[]>}
 */
export async function readDirectoryEntries({
  session
}: {
  session: Session
}): Promise<ConnectionEntry[]> {
  const { connections } = await readDirectoryListing({ session })
  return connections.map(({ entry }) => entry)
}

/**
 * The `connections` directory as a page reads it: one listing read, every
 * parseable entry at its own resource id, and this Space's container URL the
 * grant checks read (absent on a session with no Space). Every lookup by DID
 * a page makes resolves against this one read, in memory. The read is the
 * writer sweep's encounter site, which starts behind it. Throws when the
 * directory is refused or absent, or the listing fails.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<{ connections: ReadConnection[]; spaceUrl?: string }>}
 */
export async function readDirectoryListing({
  session
}: {
  session: Session
}): Promise<{ connections: ReadConnection[]; spaceUrl?: string }> {
  const listing = await listConnectionsDirectory({ session })
  if (!listing) {
    throw new Error('The connections directory could not be listed.')
  }
  if (listing.unreadable.length > 0 || listing.unparseable.length > 0) {
    // The listings show the entries they can read; a party behind an entry
    // this session cannot open is missing from them until it reads.
    log.warn('Some connections entries could not be read', {
      unreadable: listing.unreadable.length,
      unparseable: listing.unparseable.length
    })
  }
  const { spaceUrl } = session.storage
  return {
    connections: listing.entries,
    ...(spaceUrl !== undefined ? { spaceUrl } : {})
  }
}

/**
 * The did:keys of every wallet client the account document lists or ever
 * listed, from the locally verified did:webvh log. A revoked client's
 * did:key stays public in the log for good, so the set covers it. When this
 * session's account pointer is absent or names no did:webvh, there is no
 * account document. The only wallet client is then this session's own key,
 * so the set holds its did:key (and is empty when the session holds no
 * did:key agent). Throws when the log cannot be fetched or verified.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<Set<string>>}
 */
export async function listedClientDids({
  session
}: {
  session: Session
}): Promise<Set<string>> {
  const pointer = session.profile.accountPointer
  if (!pointer || !isWebvhDid(pointer.did)) {
    const ownDid = session.profile.keyAgent?.id
    return new Set(ownDid?.startsWith('did:key:') ? [ownDid] : [])
  }
  const { log: accountLog } = await verifiedAccountLog({ session, pointer })
  return accountLogDids({ log: accountLog }).clientDids
}

/**
 * Every DID the wallet itself invokes as, for naming a server-observed
 * `createdBy` as the wallet rather than as a foreign creator. This session's
 * own identities come first, from the session alone: the user id, the key
 * agent's did:key, the keyring record's controller (the did:key that
 * created the Space before promotion), the account DID, and on a transient
 * session the client-annex DID every request signs under. When the account
 * names a did:webvh, the locally verified log adds, across every entry, each
 * wallet client's did:key, each ladder VM's bare did:key, and each annex DID
 * the document pointed at, so a revision a since-revoked client or an
 * earlier visit made still reads as the wallet's. A log that cannot be read
 * leaves the session's own set, logged.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<Set<string>>}
 */
export async function walletOwnDids({
  session
}: {
  session: Session
}): Promise<Set<string>> {
  const { profile, persistence } = session
  const pointer = profile.accountPointer
  const dids = new Set<string>()
  const add = (did: string | undefined) => {
    if (did) {
      dids.add(did)
    }
  }
  add(session.user.id)
  add(profile.keyAgent?.id)
  add(profile.accountController)
  add(profile.didWebvh?.did)
  add(pointer?.did)
  if (!isBrowserLocalSession(persistence)) {
    add(persistence.clientAnnex.clientAnnexDid)
  }
  if (!pointer || !isWebvhDid(pointer.did)) {
    return dids
  }
  try {
    const { log: accountLog } = await verifiedAccountLog({ session, pointer })
    const { clientDids, ladderDids } = accountLogDids({ log: accountLog })
    for (const did of [
      ...clientDids,
      ...ladderDids,
      ...delegatedClientsPointerHistory({ log: accountLog })
    ]) {
      dids.add(did)
    }
  } catch (err) {
    log.warn("Could not read the account log for the wallet's own DIDs", {
      err
    })
  }
  return dids
}

/**
 * Writes a wallet client's names on its `wallet-client` entry: `name`, its
 * self-declared or suggested name, and `label`, the user's own. An omitted
 * member is left as stored, and a blank `label` removes it. An absent entry
 * is created only for a client the verified account document lists, which
 * is read here.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.did {string}   the client's did:key
 * @param [options.name] {string}
 * @param [options.label] {string}
 * @returns {Promise<void>}
 */
export async function recordWalletClientEntry({
  session,
  did,
  name,
  label
}: {
  session: Session
  did: string
  name?: string
  label?: string
}): Promise<void> {
  const { pointer } = await requireClientListing(session)
  const enrolledSigningKeys = await sharedCurrentAccountSigningKeys({
    pointer: {
      did: pointer.did,
      spaceId: pointer.spaceId,
      host: pointer.host
    },
    verifiedLog: await verifiedAccountLog({ session, pointer })
  })
  const { store, hmacKey } = await session.storage.connectionsDirectory()
  await setConnectionLabel({
    store,
    hmacKey,
    did,
    kind: 'wallet-client',
    ...(name !== undefined ? { name } : {}),
    ...(label !== undefined ? { label } : {}),
    enrolledSigningKeys
  })
}

/**
 * Writes this session's own client's entry, named by the default platform
 * label: the client names itself at signup and at a self-enrollment, which
 * have no approving screen. Best-effort: a failure is logged and the
 * listing shows the row unnamed. Only an enrolled client has an entry of its
 * own, so any other session writes nothing.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<void>}
 */
export async function recordOwnWalletClientEntry({
  session
}: {
  session: Session
}): Promise<void> {
  try {
    if (!canManageAccountClients({ session })) {
      return
    }
    const context = enrolledCeremonyContext({ session })
    if (!context) {
      return
    }
    await recordWalletClientEntry({
      session,
      did: context.keyAgent.id,
      name: DEFAULT_CLIENT_LABEL
    })
  } catch (err) {
    log.warn("Could not write this client's connections entry", { err })
  }
}

/**
 * Lists the account's enrolled wallet clients from the locally verified
 * did:webvh log, with names joined from the directory's wallet-client
 * entries and this session's own client marked. A directory-read failure
 * degrades to unnamed rows (the listing itself only fails when the log
 * cannot be fetched or verified).
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
  const { pointer } = context
  return await sharedListAccountClients({
    pointer: {
      did: pointer.did,
      spaceId: pointer.spaceId,
      host: pointer.host
    },
    verifiedLog: await verifiedAccountLog({
      session,
      pointer
    }),
    readDirectoryEntries: () => readDirectoryEntries({ session }),
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
 * The account DID, the signing-key multibases of the account's currently
 * enrolled wallet clients, the verified document itself, the annex DID it
 * currently points at (absent when it points at none), and the resolver of
 * a generation's annex document, what a recorded grant is checked against.
 * Resolves `undefined` when this session has no promoted did:webvh account
 * to check against (a guest or no-storage session); throws when the log
 * cannot be fetched or verified (callers treating the check as best-effort
 * catch and degrade to "unknown").
 *
 * The resolver reads the named generation's log under this session's
 * authority (an enrolled client as itself, a ladder-kind session through its
 * credential's sibling delegation) and under the log's chain-head pin. The
 * inbox pass reads the pointed generation's head through it too, so one
 * read serves that and every leaf check under the pointed generation. Any generation of
 * the account's auxiliary Space resolves, not only the pointed one, since a
 * grant under a superseded generation is still renewable while that
 * generation's log stands, and each generation is read once per check,
 * however many grants chain under it. It resolves `undefined` for an absent
 * log (a collected generation), and throws when the log cannot be read,
 * which the proof check propagates so the renewal renews nothing on a
 * failed read.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<AccountSignerCheck | undefined>}
 */
export async function currentAccountSignerCheck({
  session
}: {
  session: Session
}): Promise<AccountSignerCheck | undefined> {
  if (!canManageAccountClients({ session })) {
    return undefined
  }
  const { pointer } = await requireClientListing(session)
  const verifiedLog = await verifiedAccountLog({ session, pointer })
  const currentSigningKeys = await sharedCurrentAccountSigningKeys({
    pointer: {
      did: pointer.did,
      spaceId: pointer.spaceId,
      host: pointer.host
    },
    verifiedLog
  })
  const clientAnnexDid = delegatedClientsPointer({ doc: verifiedLog.doc })
  const readGeneration = async (generationDid: string) => {
    const reach = await namedAnnexReachUnder({
      session,
      pointer,
      clientAnnexDid: generationDid,
      ...sessionAnnexStanding({ session })
    })
    const published = await readClientAnnexLogOrAbsent({
      store: reach.logStore(),
      expectedDid: generationDid
    })
    return published?.doc
  }
  // One read per generation per check; a failed read is not memoized, so
  // the next grant under that generation reads it again.
  const generations = new Map<string, ReturnType<typeof readGeneration>>()
  const annexDocument = ({
    clientAnnexDid: generationDid
  }: {
    clientAnnexDid: string
  }) => {
    let read = generations.get(generationDid)
    if (read === undefined) {
      read = readGeneration(generationDid)
      generations.set(generationDid, read)
      read.catch(() => generations.delete(generationDid))
    }
    return read
  }
  return {
    accountDid: pointer.did,
    currentSigningKeys,
    doc: verifiedLog.doc,
    ...(clientAnnexDid !== undefined ? { clientAnnexDid } : {}),
    annexDocument
  }
}

/**
 * The kids of the account's user key generations, oldest first: each epoch
 * of the verified `key-map/user-key.jsonl` roster is one generation, named
 * in a collection epoch by its `<did:key>#<fingerprint>` kid. A collection
 * key rotation reads them to keep an earlier generation a torn user key
 * rotation left on a roster. Resolves an empty list when this session
 * resolves no account-ceremony context, or the account has no roster yet.
 * Throws when the roster cannot be read or verified.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<string[]>}
 */
export async function accountUserKeyGenerationKids({
  session
}: {
  session: Session
}): Promise<string[]> {
  const context = await accountCeremonyContext({ session })
  if (!context) {
    return []
  }
  const read = await context.rosterStore.read()
  return (read?.descriptor.epochs ?? []).map(epoch => epochKeyIdFor(epoch.id))
}

/**
 * Sets (or clears, with a blank value) the user's `label` for one enrolled
 * client, on its wallet-client entry.
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
  await recordWalletClientEntry({
    session,
    did: walletClientDid({ signingKeyMultibase }),
    label
  })
}

/**
 * Disconnects an enrolled wallet client: the full revocation cascade
 * (`revokeEnrolledClient` -- document edit, user key rotation, collection
 * re-epoch, recovery re-mints, live adoption, and the client's directory
 * entry retired ahead of the audit row). `revokedClientKeysFor` refuses a row whose active
 * update key the log attribution could not isolate -- disconnecting with a
 * guessed key could revoke another party's authority. On the ladder branch
 * the cascade refuses before its removal entry
 * (`GenerationDelegationRenewalError`) when the pre-entry
 * generation-delegation replacement did not install, or when the account
 * document anchors no ladder VM for the acting credential. The removal entry
 * was not published, so the wallet is still connected and a retry is safe.
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
  // Wait out the login-time registry passes rather than racing their
  // read-modify-writes (the cascade re-wraps the registry); on a settled
  // session the chain resolved long ago.
  await session.registryReady
  // The history record names the client as the listing does: the user's
  // label first, then the client's own name.
  const historyLabel = client.label ?? client.name
  const outcome = await revokeEnrolledClient({
    session,
    context,
    client: revokedClientKeysFor({ client }),
    ...(historyLabel !== undefined ? { label: historyLabel } : {})
  })
  // The cascade's ceremony-tail entry, reported from the ceremony's own call
  // site: it carries no registration, so no login chain's runner ever sees
  // it.
  reportCeremonyTail({ ceremony: 'client-revocation', mended: outcome.mended })
  return outcome
}
