/**
 * The replica servers a fresh client-annex generation points at, read off the
 * session's `connections` directory through wallet-core's restate predicate
 * (`restatedReplicaServerDids`). The two enrolled-client swap entry points,
 * the quarterly GC swap and the credential retirement's off-cadence swap,
 * take the list as `replicaServerDids`, and this module is their one read
 * site. Neither caller filters the directory itself, so freewallet and the
 * mobile wallet restate the same set.
 *
 * A directory the session cannot list, or an account signer check the
 * session cannot resolve, throws rather than resolving an empty list: a swap
 * handed none points the fresh generation at no replica, which ends every
 * registered replica server's ladder-signed pull of the account Space.
 */
import {
  readConnections,
  restatedReplicaServerDids
} from '@interop/wallet-core/connections'
import { currentAccountSignerCheck } from '@/session/accountSignerCheck'
import type { Session } from '@/types/auth'

/**
 * The DIDs of the replica servers the next annex generation restates.
 *
 * @param options {object}
 * @param options.session {Session}   a live session holding account authority
 * @returns {Promise<string[]>}   the selected servers' DIDs, empty on an
 *   account with no replica-server entry
 * @throws {Error}   when the directory cannot be listed, the session resolves
 *   no account signer check, or a recorded grant's proof check fails
 */
export async function restatedReplicaServers({
  session
}: {
  session: Session
}): Promise<string[]> {
  const { store, hmacKey } = await session.storage.connectionsDirectory()
  const listing = await readConnections({ store, hmacKey })
  if (!listing) {
    throw new Error(
      'The connections directory could not be listed, so the replica ' +
        'servers to restate are unknown.'
    )
  }
  const entries = listing.entries.map(({ entry }) => entry)
  // Most accounts register no replica server, and the signer check costs a
  // verified account document (a log read on a cold memo), so an account
  // with no entry to select from skips it.
  if (!entries.some(entry => entry.kind === 'replica-server')) {
    return []
  }
  const signerCheck = await currentAccountSignerCheck({ session })
  if (!signerCheck) {
    throw new Error(
      'This session resolves no account signer check, so the replica ' +
        'servers to restate cannot be verified.'
    )
  }
  return await restatedReplicaServerDids({ entries, signerCheck })
}
