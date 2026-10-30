/**
 * The standing-credential refreshes the remembered login block runs on a
 * promoted account -- the bridge-and-sibling self-refresh, and the recorded
 * ladder rung a self-enrollment just climbed -- and the one re-mint and
 * record re-bind the self-refresh shares with the last-client transition.
 *
 * Each acts on the acting credential's own registry entry. The login-time
 * refreshes are best-effort: the delegations they re-mint are annual, and a
 * rung left unrecorded only makes a later disconnect attribution fail closed.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { AccountPointer } from '@interop/wallet-core/keyring'
import type { VerifiedAccountLog } from '@interop/wallet-core/clients'
import {
  attributeLadderRung,
  delegationKeyInDocument,
  type PublishedKeyDocument
} from '@interop/wallet-core/webvh'
import {
  delegatedClientsDelegationSpaceId,
  mintDelegatedClientsDelegation
} from '@interop/wallet-core/clientAnnex'
import {
  delegateLogWrite,
  delegationProofKeyId,
  zcapExpiring
} from '@interop/wallet-core/recovery'
import { spaceLocation } from '@/lib/spaceLocation'
import { zcapExpires } from '@/lib/zcap'
import type { Session } from '@/types/auth'
import {
  refreshStandingDelegationFields,
  standingUnlockFields
} from '@/session/unlockMethods'

/**
 * The standing members a re-mint acts on: the live session's standing
 * unlock members with the record re-bind closure present (a hit that
 * exposed none cannot re-seal its record, so nothing here runs for it).
 */
export type RebindableStandingUnlock = NonNullable<
  Session['profile']['standingUnlock']
> & {
  rebindRecord: NonNullable<
    NonNullable<Session['profile']['standingUnlock']>['rebindRecord']
  >
}

/**
 * The standing-delegation self-refresh: a standing credential's own login
 * re-mints its bridge delegation -- and the annex-Space sibling, where the
 * record carries one -- when either is stale on either axis: expired or
 * inside the renewal window (the same annual clock and shared predicate as
 * the recovery delegations), or its signer no longer listed under
 * `capabilityDelegation` in the verified account document (the relation a
 * delegation proof verifies against). A self-enrollment leaves every ladder
 * VM standing, so the rot this predicate catches comes from elsewhere -- a
 * credential retirement strikes its own ladder VM. A stale pair is re-minted
 * under the session's own signer by {@link remintStandingDelegations}.
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
 * @param options.standing {RebindableStandingUnlock}   the credential's
 *   standing members: the pair the staleness predicate reads, and the
 *   identity and re-bind closure a re-mint needs
 * @returns {Promise<'noop' | 'refreshed'>}
 */
export async function refreshStandingDelegations({
  session,
  pointer,
  verifiedLog,
  standing
}: {
  session: Session
  pointer: AccountPointer & { did: string }
  verifiedLog: () => Promise<VerifiedAccountLog>
  standing: RebindableStandingUnlock
}): Promise<'noop' | 'refreshed'> {
  const { delegation, delegatedClients } = standing
  const expiring =
    zcapExpiring({ expires: zcapExpires(delegation) }) ||
    (!!delegatedClients &&
      zcapExpiring({ expires: zcapExpires(delegatedClients) }))
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
      !rotted(delegation) &&
      (!delegatedClients || !rotted(delegatedClients))
    ) {
      return 'noop'
    }
  }
  await remintStandingDelegations({
    session,
    zcapClient: session.profile.zcapClient,
    pointer,
    standing
  })
  return 'refreshed'
}

/**
 * The bridge-and-sibling re-mint and record re-bind: re-mints the bridge
 * delegation -- and the annex-Space sibling, where the record carries one --
 * under the given signer, re-binds the unlock record through the hit's
 * re-bind closure, replaces the pair on the live session, and records the
 * fresh members on the registry entry. The remembered login's self-refresh
 * signs with the session's own zcap client; the last-client transition signs
 * with the ladder VM, the one key its post-removal document still backs.
 * Replacing the live session's pair on the transition is harmless, since a
 * forget tears that session down. Idempotent: a resumed run re-mints and
 * re-binds again.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.zcapClient {ZcapClient}   the signer both members are
 *   delegated by
 * @param options.pointer {AccountPointer}   the pointer the bridge's log
 *   writes address
 * @param options.standing {RebindableStandingUnlock}   the credential's
 *   standing members: the current sibling (absent, the bridge re-binds
 *   alone), the credential's own DID (the delegatee of both members), its
 *   unlock Space (the registry entry's match key), its key-agreement
 *   multibase (an entry recording another credential's, a pending
 *   retirement, is left alone), and the record re-bind closure
 * @returns {Promise<void>}
 */
export async function remintStandingDelegations({
  session,
  zcapClient,
  pointer,
  standing
}: {
  session: Session
  zcapClient: ZcapClient
  pointer: AccountPointer
  standing: RebindableStandingUnlock
}): Promise<void> {
  const standingClientDid = standing.standingClient.clientDid
  const delegation = await delegateLogWrite({
    zcapClient,
    pointer,
    recoveryClientDid: standingClientDid
  })
  // The sibling reseals in the same pass; its target auxiliary Space id
  // rides in the old delegation (the id's one carrier).
  let delegatedClients
  if (standing.delegatedClients) {
    const clientAnnexSpaceId = delegatedClientsDelegationSpaceId({
      delegation: standing.delegatedClients
    })
    if (clientAnnexSpaceId) {
      delegatedClients = await mintDelegatedClientsDelegation({
        zcapClient,
        baseServerUrl: spaceLocation({ spaceUrl: pointer.spaceUrl })
          .baseServerUrl,
        clientAnnexSpaceId,
        controller: standingClientDid
      })
    }
  }
  await standing.rebindRecord({
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
    unlockSpaceId: standing.unlockSpaceId,
    // The entry may still record an earlier credential's standing
    // configuration (a pending retirement); these members are this
    // credential's.
    keyAgreementKeyMultibase: standing.standingClient.keyAgreementKeyMultibase,
    fields: standingUnlockFields({ delegation, delegatedClients })
  })
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
    keyAgreementKeyMultibase,
    fields: { updateKeyMultibase: rung.keyMultibase }
  })
  return 'recorded'
}
