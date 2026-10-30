/**
 * The account signer check: what a recorded grant's proof is verified
 * against, resolved from the live session's verified account log. A leaf
 * module, so the modules the mender registry reaches (the annex GC sweep,
 * the credential rotation) can resolve it without importing the client
 * listing, which reaches the registry back.
 */
import {
  delegatedClientsPointer,
  readClientAnnexLogOrAbsent
} from '@interop/wallet-core/clientAnnex'
import type { Session } from '@/types/auth'
import type { AccountSignerCheck } from '@/lib/connectedApps'
import {
  canRunAccountCeremonies,
  requireAccountCeremonyContext,
  sessionAnnexStanding
} from '@/session/accountCeremonyContext'
import { namedAnnexReachUnder } from '@/session/annexReach'
import { verifiedAccountLog } from '@/session/verifiedLog'

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
  if (!canRunAccountCeremonies({ session })) {
    return undefined
  }
  const { pointer } = await requireAccountCeremonyContext({
    session,
    action: 'The account signer check'
  })
  const verifiedLog = await verifiedAccountLog({ session, pointer })
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
    doc: verifiedLog.doc,
    ...(clientAnnexDid !== undefined ? { clientAnnexDid } : {}),
    annexDocument
  }
}
