/**
 * The two standing-credential refreshes the remembered login block runs on a
 * promoted account: the bridge-and-sibling self-refresh, and the recorded
 * ladder rung a self-enrollment just climbed.
 *
 * Both act on the acting credential's own registry entry, and both are
 * best-effort: the delegations they re-mint are annual, and a rung left
 * unrecorded only makes a later disconnect attribution fail closed.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type { VerifiedAccountLog } from '@interop/wallet-core/clients'
import {
  delegationKeyInDocument,
  type PublishedKeyDocument
} from '@interop/wallet-core/webvh'
import {
  attributeLadderRung,
  delegatedClientsDelegationSpaceId,
  mintDelegatedClientsDelegation
} from '@interop/wallet-core/clientAnnex'
import {
  delegateLogWrite,
  delegationProofKeyId,
  zcapExpiring
} from '@interop/wallet-core/recovery'
import { zcapExpires } from '@/lib/zcap'
import type { Session } from '@/types/auth'
import { refreshStandingDelegationFields } from '@/session/unlockMethods'

/**
 * The standing-delegation self-refresh: a standing credential's own login
 * re-mints its bridge delegation -- and the annex-Space sibling, where the
 * record carries one -- when either is stale on either axis: expired or
 * inside the renewal window (the same annual clock and shared predicate as
 * the recovery delegations), or its signer no longer listed under
 * `capabilityDelegation` in the verified account document (the relation a
 * delegation proof verifies against). A self-enrollment leaves every ladder
 * VM standing, so the rot this predicate catches comes from elsewhere -- a
 * credential retirement strikes its own ladder VM. One pass reseals both,
 * re-binds the unlock record, replaces the pair on the live session, and
 * records the fresh members on the registry entry.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.pointer {AccountPointer & { did: string }}   the promoted
 *   pointer this login's log writes address
 * @param options.verifiedLog {Function}   the account log this block already
 *   verified, resolved lazily: it is read only on the not-expiring branch,
 *   where the signer check needs it. An expiring member is re-minted from
 *   the zcaps in hand, so a log the host cannot serve does not stand the
 *   re-mint down
 * @param options.rebindStandingRecord {Function}   the hit's record re-bind
 * @param options.delegation {IZcap}   the record's bridge delegation
 * @param options.standingClientDid {string}   the credential's own DID, the
 *   delegatee of both members
 * @param options.unlockSpaceId {string}   the credential's unlock Space, the
 *   registry entry's match key
 * @param [options.delegatedClients] {IZcap}   the record's annex sibling
 * @param [options.keyAgreementKeyMultibase] {string}   this credential's
 *   key-agreement multibase; an entry recording another credential's (a
 *   pending retirement) is left alone
 * @returns {Promise<'noop' | 'refreshed'>}
 */
export async function refreshStandingDelegations({
  session,
  pointer,
  verifiedLog,
  rebindStandingRecord,
  delegation: standingDelegation,
  delegatedClients: standingDelegatedClients,
  standingClientDid,
  unlockSpaceId,
  keyAgreementKeyMultibase
}: {
  session: Session
  pointer: AccountPointer & { did: string }
  verifiedLog: () => Promise<VerifiedAccountLog>
  rebindStandingRecord: (members: {
    delegation: IZcap
    delegatedClients?: IZcap
  }) => Promise<void>
  delegation: IZcap
  delegatedClients?: IZcap
  standingClientDid: string
  unlockSpaceId: string
  keyAgreementKeyMultibase?: string
}): Promise<'noop' | 'refreshed'> {
  const expiring =
    zcapExpiring({ expires: zcapExpires(standingDelegation) }) ||
    (!!standingDelegatedClients &&
      zcapExpiring({ expires: zcapExpires(standingDelegatedClients) }))
  if (!expiring) {
    // The one branch that needs the account document: nothing is expiring,
    // so the only remaining question is whether the signers are still
    // listed.
    const verified = await verifiedLog()
    const rotted = (member: IZcap) =>
      !delegationKeyInDocument({
        doc: verified.doc as PublishedKeyDocument,
        delegationKeyId: delegationProofKeyId(member)
      })
    if (
      !rotted(standingDelegation) &&
      (!standingDelegatedClients || !rotted(standingDelegatedClients))
    ) {
      return 'noop'
    }
  }
  const delegation = await delegateLogWrite({
    zcapClient: session.profile.zcapClient,
    pointer,
    recoveryClientDid: standingClientDid
  })
  // The sibling reseals in the same pass; its target auxiliary Space id
  // rides in the old delegation (the id's one carrier).
  let delegatedClients
  if (standingDelegatedClients) {
    const clientAnnexSpaceId = delegatedClientsDelegationSpaceId({
      delegation: standingDelegatedClients
    })
    if (clientAnnexSpaceId) {
      delegatedClients = await mintDelegatedClientsDelegation({
        zcapClient: session.profile.zcapClient,
        wasServerUrl: pointer.host,
        clientAnnexSpaceId,
        controller: standingClientDid
      })
    }
  }
  await rebindStandingRecord({
    delegation,
    ...(delegatedClients ? { delegatedClients } : {})
  })
  // The live session acts through the members it carries, so the refreshed
  // ones replace the stale pair there too (a forget run later this session
  // signs through the delegation that verifies).
  if (session.profile.standingUnlock) {
    session.profile.standingUnlock = {
      ...session.profile.standingUnlock,
      delegation,
      ...(delegatedClients ? { delegatedClients } : {})
    }
  }
  await refreshStandingDelegationFields({
    session,
    unlockSpaceId,
    // The entry may still record an earlier credential's standing
    // configuration (a pending retirement); these members are this
    // credential's.
    ...(keyAgreementKeyMultibase ? { keyAgreementKeyMultibase } : {}),
    delegationKeyId: delegationProofKeyId(delegation),
    delegationExpires: zcapExpires(delegation),
    ...(delegatedClients
      ? {
          delegatedClientsKeyId: delegationProofKeyId(delegatedClients),
          delegatedClientsExpires: zcapExpires(delegatedClients)
        }
      : {})
  })
  return 'refreshed'
}

/**
 * After a self-enrollment climbed the update-key ladder, refresh the
 * registry entry's recorded rung to the freshly committed one, so the
 * revocation edit's latent-hash attribution stays answerable. Best-effort: a
 * stale rung only makes that attribution fail closed later, never silently
 * misattribute.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.verified {VerifiedAccountLog}   the account log this block
 *   already verified, which the rung is attributed against
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.unlockSpaceId {string}   the registry entry's match key
 * @param [options.keyAgreementKeyMultibase] {string}   this credential's
 *   key-agreement multibase
 * @returns {Promise<'noop' | 'recorded'>}   `noop` when the ladder's current
 *   rung is not committed in the document
 */
export async function refreshCommittedLadderRung({
  session,
  verified,
  ladderSeed,
  unlockSpaceId,
  keyAgreementKeyMultibase
}: {
  session: Session
  verified: VerifiedAccountLog
  ladderSeed: Uint8Array
  unlockSpaceId: string
  keyAgreementKeyMultibase?: string
}): Promise<'noop' | 'recorded'> {
  const { rung, state } = await attributeLadderRung({
    ladderSeed,
    published: verified
  })
  if (state !== 'committed') {
    return 'noop'
  }
  await refreshStandingDelegationFields({
    session,
    unlockSpaceId,
    ...(keyAgreementKeyMultibase ? { keyAgreementKeyMultibase } : {}),
    updateKeyMultibase: rung.keyMultibase
  })
  return 'recorded'
}
