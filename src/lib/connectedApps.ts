/**
 * Connected-parties model for the Applications settings section, read from
 * the `connections` directory (`@interop/wallet-core/connections`): one
 * encrypted entry per party the wallet has dealt with. An app connected
 * through the App Connect CHAPI flow has a `kind: 'app'` entry carrying its
 * attested origin, its canonical app URL, the `app-keys` Resource
 * holding its app key (`appKey`), and every grant it was delegated. An agent
 * that answered an interaction-URL request has a `kind: 'agent'` entry with
 * its grants and no app key. The `wallet-activity` Grant and Revoke rows are
 * audit trail, and nothing here reads them.
 *
 * Every lookup by DID resolves against one directory listing read and
 * matches the decrypted `id` in memory: nothing here GETs the id a DID
 * derives to, so the host never learns which id belongs to which DID. Every
 * grant is read through wallet-core's `connectionGrants`, which drops a grant
 * delegated to another party than the entry's `id` and one targeting another
 * Space, so a planted entry cannot steer a listing or a revocation at another
 * party's capabilities.
 *
 * `listConnectedApps` lists the unretired app entries holding an app key or
 * any grant, and `listConnectedAgents` the unretired agent entries holding a
 * live grant, or an expired one on a collection whose current key epoch still
 * lists the agent. `deriveGrantsState` reads each grant's delegation signer
 * against the account document's current key set (wallet-core's
 * `deriveGrantSignerState`): a grant signed by a since-disconnected wallet
 * client is already dead (the current-key-set rule), so its row lists as
 * orphaned -- "reconnect to use again" -- rather than as live. A grant minted
 * from a transient session is signed by a client-annex per-visit key the
 * document never lists, so it derives as unknown rather than orphaned.
 * `lookupCollectionCreators` answers each app `generator.id` stamp with the
 * entry's name and canonical app URL, `lookupCreatedByParty` answers a
 * server-observed `createdBy` DID with the name of the app or agent entry
 * whose `id` it is, and `findKnownAgents` answers the interaction-URL page's
 * known-agent note.
 *
 * `revokeAppAccess` retires an app: the collections its grants target or its
 * `generator` stamp names are rotated off its recipient key (so it cannot
 * decrypt future writes) with their pull-axis grants revoked indivisibly,
 * then the remaining grants are revoked, then its app key is deleted on the
 * server, then its entry is retired, and then the revocation is recorded.
 * `revokeAgentAccess` runs the same sequence with no app key, behind one
 * first write that empties the entry's channel and outbox. The honest
 * limitation stands: ciphertext a party already fetched stays readable to it
 * -- rotation protects only prospective writes.
 */
import type { CeremonyDetail } from '@interop/wallet-core'
import type { StorageManager } from '@/stores/storageManager'
import type { User } from '@/types/auth'
import {
  deriveGrantSignerState,
  type GrantSignerState
} from '@interop/wallet-core/clients'
import type { AccountSignerCheck } from '@interop/wallet-core/clientAnnex'
import {
  collectionIdInSpace,
  connectionGrants,
  connectionKindOf,
  findConnection,
  grantScopeKey,
  latestIndexPerScope,
  splitGrantsByExpiry,
  type ConnectionEntry,
  type ConnectionGrant,
  type ConnectionsListing,
  type GrantKind,
  type ReadConnection
} from '@interop/wallet-core/connections'
import { delegationProofKeyId } from '@interop/wallet-core/webvh'
import type { IZcap } from '@interop/data-integrity-core'
import type { CollectionGenerator } from '@interop/was-client'
import { appGeneratorIds } from '@/lib/collectionAttribution'
import { EXTERNAL_REQUEST_ORIGIN } from '@/lib/walletRequest/externalRequest'

/**
 * The grant revocation's stage ids for the ceremony event channel, in run
 * order. An app disconnect runs every stage but `remove-grants`. An agent
 * revoke also skips `delete-app-key`. An unshare runs `rotate-recipients`,
 * `revoke-grants`, `remove-grants`, and `record-activity`. Each fires once
 * its write has landed.
 */
export const GRANT_REVOCATION_STAGES = [
  'rotate-recipients',
  'revoke-grants',
  'delete-app-key',
  'retire-entry',
  'remove-grants',
  'record-activity'
] as const

/**
 * One value of {@link GRANT_REVOCATION_STAGES}.
 */
export type GrantRevocationStage = (typeof GRANT_REVOCATION_STAGES)[number]

/**
 * The stage hook a grant revocation's entry point hands down, so the stages
 * are marked where their writes land while the emitter stays at the entry
 * point.
 */
export type GrantRevocationStageHook = (
  stage: GrantRevocationStage,
  detail?: CeremonyDetail
) => void

/**
 * One storage capability a party was granted, as its `connections` entry
 * records it.
 */
export interface AppGrant {
  /**
   * The capability's id.
   */
  id: string
  target: string
  allowedActions: string[]
  /**
   * The capability's own `expires`; empty when it carries none.
   */
  expires: string
  /**
   * The Collection the target addresses, when it is exactly a Collection
   * container URL of this Space; absent for a Resource or a sub-resource
   * target.
   */
  collectionId?: string
  /**
   * The verification-method id that signed the delegation
   * (`zcap.proof.verificationMethod`).
   */
  signerKeyId?: string
  /**
   * `'share'` for a grant the shared-wallet-collection flow wrote, `'grant'`
   * for every other.
   */
  grantKind: GrantKind
  /**
   * When the consent that wrote the grant ran.
   */
  grantedAt: string
  /**
   * The superseded records of the same scope (same grantee, target, and
   * actions), newest first: the records a renewal or a later consent
   * replaced. Present only on a listing's current record, when it has any.
   */
  earlier?: AppGrant[]
}

/**
 * What a recorded grant is checked against, read off the session's verified
 * account document; assembled app-side by `currentAccountSignerCheck`
 * (`src/session/clients.ts`) and read by wallet-core's `grantRevocationSkip`.
 */
export type { AccountSignerCheck } from '@interop/wallet-core/clientAnnex'

/**
 * A connected application: one unretired `kind: 'app'` entry.
 */
export interface ConnectedApp {
  /**
   * The entry's resource id, which keys the detail route.
   */
  resourceId: string
  /**
   * The display name: the user's `label`, else the app's own `name`, else
   * its origin. Absent when the entry carries none of them; a view then
   * shows the shortened DID.
   */
  name?: string
  /**
   * The CHAPI requesting origin the app key is bound to.
   */
  origin?: string
  /**
   * The application URL the app key is scoped to within that origin. Two
   * applications sharing an origin are distinct connected apps.
   */
  appUrl?: string
  /**
   * The app-key credential's subject (self-issued) did:key, the entry's
   * `id`.
   */
  subjectDid: string
  /**
   * The `app-keys` Resource holding the app key, when the entry
   * names one.
   */
  appKey?: string
  /**
   * When the entry was created (`firstSeen`).
   */
  connectedAt?: string
  /**
   * The latest consent's timestamp (`lastSeen`).
   */
  lastConnectedAt?: string
  /**
   * Every grant on the entry, live and expired, newest first.
   */
  grants: AppGrant[]
}

/**
 * A connected agent: one unretired `kind: 'agent'` entry, a grantee that
 * answered an interaction-URL request rather than an App Connect popup, so it
 * has no app key and no origin of its own.
 */
export interface ConnectedAgent {
  /**
   * The entry's resource id, which keys the detail route.
   */
  resourceId: string
  /**
   * The grantee did:key, the entry's `id`.
   */
  controller: string
  /**
   * The display name: the user's `label`, else the self-declared `name` the
   * request carried. Display-only: the requester chose it, and nothing
   * verifies it.
   */
  name?: string
  /**
   * The origin marker an agent grant is recorded under
   * (`EXTERNAL_REQUEST_ORIGIN` -- there is no attested requesting origin on
   * this path).
   */
  origin: string
  /**
   * The latest record per scope on the entry, live and expired, newest
   * first. A superseded record rides under its scope's current one
   * (`earlier`).
   */
  grants: AppGrant[]
  /**
   * When the newest grant was written.
   */
  grantedAt?: string
  /**
   * When the entry was created (`firstSeen`).
   */
  connectedAt?: string
  /**
   * The latest consent's timestamp (`lastSeen`).
   */
  lastConnectedAt?: string
  /**
   * Set when every grant has expired. Such a row is listed only because a
   * grant targets an encrypted collection whose current key epoch still
   * holds the agent's key, until a revocation rotates it away.
   */
  expired?: true
  /**
   * When the owner declined to keep this agent connected (the entry's
   * `declined` marker): left unticked in a ceremony dialog, or declined as
   * an offer. Its detail page offers Restore beside Revoke.
   */
  declined?: string
}

/**
 * The grants of one entry that pass the reader checks. A session with no
 * Space has none: it delegates nothing.
 *
 * @param options {object}
 * @param options.entry {ConnectionEntry}
 * @param [options.spaceUrl] {string}   this Space's container URL
 * @returns {ConnectionGrant[]}
 */
function partyGrants({
  entry,
  spaceUrl
}: {
  entry: ConnectionEntry
  spaceUrl?: string
}): ConnectionGrant[] {
  return spaceUrl === undefined ? [] : connectionGrants({ entry, spaceUrl })
}

/**
 * A grant as the views read it.
 *
 * @param options {object}
 * @param options.grant {ConnectionGrant}
 * @param [options.spaceUrl] {string}   this Space's container URL, which the
 *   collection id is read against; absent on a session with no Space
 * @returns {AppGrant}
 */
function appGrantOf({
  grant,
  spaceUrl
}: {
  grant: ConnectionGrant
  spaceUrl?: string
}): AppGrant {
  const signerKeyId = delegationProofKeyId(grant.zcap as unknown as IZcap)
  const collectionId =
    spaceUrl === undefined
      ? undefined
      : collectionIdInSpace({ target: grant.target, spaceUrl })
  return {
    id: grant.zcapId,
    target: grant.target,
    allowedActions: [grant.allowedAction ?? []].flat(),
    expires: grant.expires ?? '',
    ...(collectionId !== undefined && { collectionId }),
    ...(signerKeyId !== undefined && { signerKeyId }),
    grantKind: grant.grantKind,
    grantedAt: grant.grantedAt
  }
}

/**
 * Grants as the views read them: the latest record per scope (wallet-core's
 * `latestIndexPerScope`), newest first by `grantedAt`, each carrying the
 * superseded records of its scope as `earlier`, newest first. A renewal adds
 * a record beside the one it replaces, so a view reading every record would
 * count one grant twice and name the superseded record's lapse date.
 *
 * @param options {object}
 * @param options.grants {ConnectionGrant[]}
 * @param [options.spaceUrl] {string}   this Space's container URL
 * @returns {AppGrant[]}
 */
function newestFirst({
  grants,
  spaceUrl
}: {
  grants: ConnectionGrant[]
  spaceUrl?: string
}): AppGrant[] {
  const byGrantedAt = (first: AppGrant, second: AppGrant): number =>
    second.grantedAt.localeCompare(first.grantedAt)
  const latest = latestIndexPerScope({ zcaps: grants.map(grant => grant.zcap) })
  const current = new Set(latest.values())
  const earlier = new Map<string, AppGrant[]>()
  grants.forEach((grant, index) => {
    if (current.has(index)) {
      return
    }
    const scope = grantScopeKey({ zcap: grant.zcap })
    const row = appGrantOf({ grant, spaceUrl })
    const held = earlier.get(scope)
    if (held) {
      held.push(row)
    } else {
      earlier.set(scope, [row])
    }
  })
  return [...latest]
    .map(([scope, index]) => {
      const superseded = (earlier.get(scope) ?? []).sort(byGrantedAt)
      return {
        ...appGrantOf({ grant: grants[index]!, spaceUrl }),
        ...(superseded.length > 0 && { earlier: superseded })
      }
    })
    .sort(byGrantedAt)
}

/**
 * The distinct collections of this wallet a party holds a share of, in the
 * grants' order: the ones a disconnect takes its key off. A share grant
 * names a Collection container URL, so one without a collection id is
 * skipped.
 *
 * @param options {object}
 * @param options.grants {AppGrant[]}
 * @returns {string[]}
 */
export function sharedCollectionIds({
  grants
}: {
  grants: AppGrant[]
}): string[] {
  const ids = new Set<string>()
  for (const grant of grants) {
    if (grant.grantKind === 'share' && grant.collectionId !== undefined) {
      ids.add(grant.collectionId)
    }
  }
  return [...ids]
}

/**
 * Sorts rows by their latest consent, newest first.
 *
 * @param rows {Array<{ lastConnectedAt?: string }>}
 * @returns {void}
 */
function sortByLastSeen(rows: Array<{ lastConnectedAt?: string }>): void {
  rows.sort((first, second) =>
    (second.lastConnectedAt ?? '').localeCompare(first.lastConnectedAt ?? '')
  )
}

/**
 * Whether a row's recorded grants still verify under the current-key-set
 * rule (a delegation verifies iff its verification method is in the resolved
 * account document now), over a bare grant list so the app rows and the agent
 * rows share it. The rule is wallet-core's `deriveGrantSignerState`; this
 * binds it to the {@link AppGrant} shape. `orphaned` means the enrolled
 * client that minted the grants has since been disconnected; `unknown`
 * covers nothing to check against AND a grant a transient session minted,
 * whose annex signer the account document never lists.
 *
 * @param options {object}
 * @param options.grants {AppGrant[]}
 * @param [options.signerCheck] {AccountSignerCheck}   the account DID and
 *   the enrolled clients' signing keys, or undefined when no verified
 *   document is available this session
 * @returns {GrantSignerState}
 */
export function deriveGrantsState({
  grants,
  signerCheck
}: {
  grants: Array<Pick<AppGrant, 'signerKeyId'>>
  signerCheck?: AccountSignerCheck
}): GrantSignerState {
  if (!signerCheck) {
    return 'unknown'
  }
  const { accountDid, currentSigningKeys } = signerCheck
  return deriveGrantSignerState({
    signerKeyIds: grants.map(grant => grant.signerKeyId),
    accountDid,
    currentSigningKeys
  })
}

/**
 * A party's display name off its entry: the user's `label`, else the
 * party's own `name`, else an app's origin.
 *
 * @param entry {ConnectionEntry}
 * @returns {string | undefined}
 */
function partyName(entry: ConnectionEntry): string | undefined {
  return entry.label ?? entry.name ?? entry.origin
}

/**
 * Lists the user's connected applications: every unretired `kind: 'app'`
 * entry that holds an app key or any grant. The display name reads the
 * user's `label`, then the app's `name`, then its origin. Rows sort by the
 * latest consent (`lastSeen`), which only a consent moves, so a read does
 * not reorder them.
 *
 * @param options {object}
 * @param options.connections {ReadConnection[]}   the directory's entries,
 *   from one listing read
 * @param [options.spaceUrl] {string}   this Space's container URL, for the
 *   grant checks; absent on a session with no Space
 * @returns {ConnectedApp[]}   sorted latest-connected first
 */
export function listConnectedApps({
  connections,
  spaceUrl
}: {
  connections: ReadConnection[]
  spaceUrl?: string
}): ConnectedApp[] {
  const apps: ConnectedApp[] = []
  for (const { resourceId, entry } of connections) {
    if (
      connectionKindOf(entry) !== 'app' ||
      entry.retired !== undefined ||
      entry.id === undefined
    ) {
      continue
    }
    const grants = partyGrants({ entry, spaceUrl })
    if (entry.appKey === undefined && grants.length === 0) {
      continue
    }
    const name = partyName(entry)
    apps.push({
      resourceId,
      ...(name !== undefined && { name }),
      ...(entry.origin !== undefined && { origin: entry.origin }),
      ...(entry.url !== undefined && { appUrl: entry.url }),
      subjectDid: entry.id,
      ...(entry.appKey !== undefined && { appKey: entry.appKey }),
      connectedAt: entry.firstSeen,
      lastConnectedAt: entry.lastSeen,
      grants: newestFirst({ grants, spaceUrl })
    })
  }
  sortByLastSeen(apps)
  return apps
}

/**
 * The unretired agent entries with at least one grant, as rows, before the
 * expired-row check. A row whose every grant has expired is flagged.
 *
 * @param options {object}
 * @param options.connections {ReadConnection[]}
 * @param [options.spaceUrl] {string}
 * @returns {ConnectedAgent[]}
 */
function agentRows({
  connections,
  spaceUrl
}: {
  connections: ReadConnection[]
  spaceUrl?: string
}): ConnectedAgent[] {
  const agents: ConnectedAgent[] = []
  for (const { resourceId, entry } of connections) {
    if (
      connectionKindOf(entry) !== 'agent' ||
      entry.retired !== undefined ||
      entry.id === undefined
    ) {
      continue
    }
    const grants = partyGrants({ entry, spaceUrl })
    if (grants.length === 0) {
      continue
    }
    const rows = newestFirst({ grants, spaceUrl })
    const name = entry.label ?? entry.name
    const expired = splitGrantsByExpiry({ grants }).live.length === 0
    agents.push({
      resourceId,
      controller: entry.id,
      ...(name !== undefined && { name }),
      origin: EXTERNAL_REQUEST_ORIGIN,
      grants: rows,
      grantedAt: rows[0].grantedAt,
      connectedAt: entry.firstSeen,
      lastConnectedAt: entry.lastSeen,
      ...(expired && { expired: true as const }),
      ...(entry.declined !== undefined && { declined: entry.declined })
    })
  }
  return agents
}

/**
 * Lists the agents holding storage grants answered from an interaction-URL
 * request: every unretired `kind: 'agent'` entry with a live grant. A row
 * whose every grant has already expired is kept, flagged `expired`, while
 * some current key epoch of a collection its grants target still lists the
 * agent: that roster entry does not expire, and only a revocation rotates it
 * away. That check reads the governed descriptor of each distinct collection
 * the expired rows' grants target, once however many rows target it, and
 * only when some row has fully expired. When a collection's key epochs cannot
 * be read the row is kept: hiding a row that may still be revocable is the
 * worse failure. An agent entry with no grants is not listed.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.connections {ReadConnection[]}   the directory's entries,
 *   from one listing read
 * @param [options.spaceUrl] {string}   this Space's container URL
 * @returns {Promise<ConnectedAgent[]>}   sorted latest-connected first
 */
export async function listConnectedAgents({
  storage,
  connections,
  spaceUrl
}: {
  storage: StorageManager
  connections: ReadConnection[]
  spaceUrl?: string
}): Promise<ConnectedAgent[]> {
  const agents = agentRows({ connections, spaceUrl })
  let listed = agents
  const expiredAgents = agents.filter(agent => agent.expired)
  if (expiredAgents.length > 0) {
    const outcomes = await storage.granteeRosterCollections({
      grantees: expiredAgents.map(({ controller, grants }) => ({
        controller,
        targets: grants.map(grant => grant.target)
      }))
    })
    const drop = new Set(
      outcomes
        .filter(
          ({ collectionIds, failed }) =>
            collectionIds.length === 0 && failed === 0
        )
        .map(({ controller }) => controller)
    )
    listed = agents.filter(agent => !drop.has(agent.controller))
  }
  sortByLastSeen(listed)
  return listed
}

/**
 * Which of the given controllers this account has granted storage to
 * through an interaction-URL request: an unretired `kind: 'agent'` entry
 * whose `id` is the controller, holding at least one grant. Each carries the
 * entry's name and the newest grant's `grantedAt`. Matched in memory against
 * one listing read, so the host learns nothing about which DID the page
 * asked after. A wallet-client entry, an app entry, and a retired agent
 * entry answer nothing.
 *
 * The claim it backs is only "you granted this key before and have not
 * revoked it", which holds for an expired grant too. Naming someone else's
 * DID gains a requester nothing, since only the key holder can invoke grants
 * delegated to it, so the result is safe to show without a proof of
 * possession.
 *
 * @param options {object}
 * @param options.connections {ReadConnection[]}   the directory's entries
 * @param [options.spaceUrl] {string}   this Space's container URL
 * @param options.controllers {string[]}   the grantee DIDs to look up
 * @returns {Map<string, { name?: string; grantedAt?: string }>}
 *   the known controllers only
 */
export function findKnownAgents({
  connections,
  spaceUrl,
  controllers
}: {
  connections: ReadConnection[]
  spaceUrl?: string
  controllers: string[]
}): Map<string, { name?: string; grantedAt?: string }> {
  const wanted = new Set(controllers)
  const known = new Map<string, { name?: string; grantedAt?: string }>()
  for (const agent of agentRows({ connections, spaceUrl })) {
    if (!wanted.has(agent.controller)) {
      continue
    }
    known.set(agent.controller, {
      ...(agent.name !== undefined && { name: agent.name }),
      ...(agent.grantedAt !== undefined && { grantedAt: agent.grantedAt })
    })
  }
  return known
}

/**
 * The party behind a server-observed `createdBy` DID, as the wallet's
 * directory names it.
 */
export interface CreatedByParty {
  /**
   * The display name: the user's `label`, else the party's `name`, else an
   * app's origin.
   */
  name: string
  /**
   * The party's entry resource id while the Applications page lists it, for
   * a link to its detail page. A disconnected party has no row, so it
   * carries none.
   */
  resourceId?: string
}

/**
 * The app behind a collection's `generator` stamp, as the wallet's directory
 * names it.
 */
export interface CollectionCreator extends CreatedByParty {
  /**
   * The canonical application URL, which tells apps sharing an origin apart.
   */
  appUrl: string
}

/**
 * What the directory says about the apps that created a set of collections,
 * by the `generator.id` DID stamped on each: the display name and the
 * canonical app URL off the `kind: 'app'` entry whose `id` is that DID,
 * matched in memory against one listing read, with no GET at the id a DID
 * derives to (the host serves `generator.id` in plaintext, and a GET right
 * after would hand it the id-to-DID mapping). A retired entry still names its
 * app, since retirement keeps `name`, `origin`, and `url`; only a listed app
 * carries the `resourceId` a link needs. Only an app stamp (one carrying a
 * `generator.origin`) is looked up. An agent's stamp names itself, and is
 * dropped here. A creator no entry names is absent from the result, and the
 * surface names its origin.
 *
 * @param options {object}
 * @param options.connections {ReadConnection[]}   the directory's entries,
 *   from one listing read
 * @param [options.spaceUrl] {string}   this Space's container URL
 * @param options.generators {Iterable<CollectionGenerator | undefined>}   the
 *   collections' stamps, an unstamped collection's `undefined` included
 * @returns {ReadonlyMap<string, CollectionCreator>}   keyed by `generator.id`
 *   DID
 */
export function lookupCollectionCreators({
  connections,
  spaceUrl,
  generators
}: {
  connections: ReadConnection[]
  spaceUrl?: string
  generators: Iterable<CollectionGenerator | undefined>
}): ReadonlyMap<string, CollectionCreator> {
  const wanted = new Set(appGeneratorIds(generators))
  const creators = new Map<string, CollectionCreator>()
  if (wanted.size === 0) {
    return creators
  }
  const listed = new Set(
    listConnectedApps({ connections, spaceUrl }).map(app => app.resourceId)
  )
  for (const { resourceId, entry } of connections) {
    if (
      connectionKindOf(entry) !== 'app' ||
      entry.id === undefined ||
      !wanted.has(entry.id)
    ) {
      continue
    }
    const name = partyName(entry)
    if (name === undefined || entry.url === undefined) {
      continue
    }
    creators.set(entry.id, {
      name,
      appUrl: entry.url,
      ...(listed.has(resourceId) && { resourceId })
    })
  }
  return creators
}

/**
 * What the directory says about the party behind one server-observed
 * `createdBy` DID: the creator lookup's second half, beside
 * `lookupCollectionCreators`, over the same listing read and the same
 * in-memory match. An app entry and an agent entry each answer the DID that
 * is their `id`, by the same name order as the creator lookup, so a share
 * recipient (recorded on its app or agent entry) answers too. A
 * wallet-client entry answers nothing here: the caller names the wallet's
 * own DIDs first. A retired entry still names its party, and only a listed
 * party carries the `resourceId` a link needs: listed by the same rule as
 * the Applications page, run over the one matched entry, so an expired
 * agent a collection's key epoch still lists links to the detail page that
 * opens it. That rule reads the key epochs only when that agent's grants
 * have all expired. A DID no entry names, or whose entry holds no name,
 * answers `undefined`. Kept apart from `lookupCollectionCreators`, whose
 * map answers app stamps alone, so an agent entry never names an app stamp.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.connections {ReadConnection[]}   the directory's entries,
 *   from one listing read
 * @param [options.spaceUrl] {string}   this Space's container URL
 * @param options.did {string}   the `createdBy` DID
 * @returns {Promise<CreatedByParty | undefined>}
 */
export async function lookupCreatedByParty({
  storage,
  connections,
  spaceUrl,
  did
}: {
  storage: StorageManager
  connections: ReadConnection[]
  spaceUrl?: string
  did: string
}): Promise<CreatedByParty | undefined> {
  const match = connections.find(({ entry }) => {
    const kind = connectionKindOf(entry)
    return (kind === 'app' || kind === 'agent') && entry.id === did
  })
  const name = match && partyName(match.entry)
  if (!match || name === undefined) {
    return undefined
  }
  const only = [match]
  const listed =
    connectionKindOf(match.entry) === 'app'
      ? listConnectedApps({ connections: only, spaceUrl }).length > 0
      : (await listConnectedAgents({ storage, connections: only, spaceUrl }))
          .length > 0
  return {
    name,
    ...(listed && { resourceId: match.resourceId })
  }
}

/**
 * Reads one party's entry off the directory for a revocation: its grants as
 * the reader checks pass them, and the entry itself. An absent entry has no
 * grants.
 *
 * @param options {object}
 * @param options.directory {object}   the listing, as
 *   `StorageManager.readConnectionsListing` returns it
 * @param options.did {string}   the party's DID
 * @returns {{ entry?: ConnectionEntry; grants: ConnectionGrant[] }}
 */
function partyOf({
  directory,
  did
}: {
  directory: { listing: ConnectionsListing; spaceUrl?: string }
  did: string
}): { entry?: ConnectionEntry; grants: ConnectionGrant[] } {
  const entry = findConnection({ listing: directory.listing, did })?.entry
  return {
    ...(entry !== undefined && { entry }),
    grants: entry ? partyGrants({ entry, spaceUrl: directory.spaceUrl }) : []
  }
}

/**
 * The two server-side stages every party revocation shares. The key
 * rotation runs first, so a revoked grantee cannot decrypt future writes,
 * and the capabilities its pull axis confirmed revoked are handed to the
 * grant stage, which counts them without a second POST. The grant stage runs
 * even when some collection could not be re-keyed, so every grant that can
 * be revoked is revoked now. A rotation that left the grantee a recipient of
 * some collection's current epoch then throws, so the caller does not retire
 * the entry and the revoke can be retried. A collection whose rotation landed
 * but whose pull failed is not counted in `rotation.failed`: the grant stage
 * POSTs the capabilities the pull missed and throws if any still fails. So
 * this throws only when some authority remains, a recipient entry or a live
 * grant.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.did {string}   the party's DID
 * @param options.grants {ConnectionGrant[]}   the party's grants
 * @param options.directory {object}   the listing the grants were read from
 * @param options.failureMessage {string}   the error a failed rotation throws
 * @param [options.onStage] {GrantRevocationStageHook}   marks
 *   `rotate-recipients` once every rotation landed, and `revoke-grants` once
 *   the grant stage did; this shared tail emits nothing of its own
 * @returns {Promise<{ outcome: object; rotated: number }>}   the grant
 *   stage's outcome, plus the collections the rotation re-keyed
 */
async function rotateThenRevokeGrants({
  storage,
  did,
  grants,
  directory,
  failureMessage,
  onStage
}: {
  storage: StorageManager
  did: string
  grants: ConnectionGrant[]
  directory: { listing: ConnectionsListing; spaceUrl?: string }
  failureMessage: string
  onStage?: GrantRevocationStageHook
}): Promise<{
  outcome: Awaited<ReturnType<StorageManager['revokeConnectionGrants']>>
  rotated: number
}> {
  const rotation = await storage.revokeCollectionRecipients({
    did,
    grants,
    directory
  })
  if (rotation.failed === 0) {
    onStage?.('rotate-recipients', { rotated: rotation.rotated })
  }
  const outcome = await storage.revokeConnectionGrants({
    grants,
    revokedByRotation: rotation.revokedIds
  })
  onStage?.('revoke-grants', {
    revoked: outcome.revoked,
    skipped: outcome.skipped
  })
  if (rotation.failed > 0) {
    throw new Error(failureMessage)
  }
  return { outcome, rotated: rotation.rotated }
}

/**
 * A revocation refused because the directory holds no entry for the party,
 * so there is no grant record to revoke from.
 */
export class ConnectionEntryMissingError extends Error {
  did: string

  constructor({ did }: { did: string }) {
    super(`The connections directory holds no entry for "${did}".`)
    this.name = 'ConnectionEntryMissingError'
    this.did = did
  }
}

/**
 * Retires an app's live authority on the WAS server: the first stage of the
 * interactive revoke ({@link revokeAppAccess}). The key rotation runs first:
 * for each collection the app's entry has a grant on, or whose
 * `generator.id` names the app, it appends a fresh epoch without the app's
 * key and revokes that collection's pull-axis grants with it. Then the
 * remaining grants are revoked. See
 * {@link rotateThenRevokeGrants} for what a failure in either stage does. An
 * app with no entry throws {@link ConnectionEntryMissingError} before any
 * stage runs.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.subjectDid {string}   the app-key credential's subject DID
 * @param [options.onStage] {GrantRevocationStageHook}
 * @returns {Promise<{ outcome: object; rotated: number; entry:
 *   ConnectionEntry; handledZcapIds: string[] }>}   the grant stage's
 *   outcome, the collections the rotation re-keyed, the entry the grants
 *   were read from, and the ids of every grant this run handled
 */
export async function revokeAppAuthority({
  storage,
  subjectDid,
  onStage
}: {
  storage: StorageManager
  subjectDid: string
  onStage?: GrantRevocationStageHook
}): Promise<{
  outcome: Awaited<ReturnType<StorageManager['revokeConnectionGrants']>>
  rotated: number
  entry: ConnectionEntry
  handledZcapIds: string[]
}> {
  const directory = await storage.readConnectionsListing()
  const { entry, grants } = partyOf({ directory, did: subjectDid })
  if (entry === undefined) {
    throw new ConnectionEntryMissingError({ did: subjectDid })
  }
  const { outcome, rotated } = await rotateThenRevokeGrants({
    storage,
    did: subjectDid,
    grants,
    directory,
    failureMessage:
      'Could not rotate every collection off the app being disconnected.',
    onStage
  })
  return {
    outcome,
    rotated,
    entry,
    handledZcapIds: grants.map(grant => grant.zcapId)
  }
}

/**
 * Revokes a connected app's access, in the order every stage's retry relies
 * on: the collection rotation and the grant POSTs ({@link
 * revokeAppAuthority}), then the confirmed server-side delete of the app key
 * the entry names (`StorageManager.deleteAppKeyResource`), then the entry's
 * retirement, then the Revoke row. A stage that does not land throws before
 * the retirement, so the row stays listed and a retry re-runs every stage:
 * the rotation is idempotent (a collection whose current epoch no longer
 * lists the app is skipped), a re-POSTed grant answered `AlreadyRevokedError`
 * counts as revoked, and a key already deleted reads as absent. The
 * retirement passes the ids of the grants this run handled, so a grant a
 * concurrent consent merged makes it throw and the row stays listed. A
 * Revoke-row failure after the retirement leaves no audit row.
 *
 * Which grants are POSTed is settled by wallet-core's `grantRevocationSkip`
 * against the verified document: an expired grant, an orphaned
 * root-delegated grant, and a grant chained under a parent delegation that
 * has rotted are dead already and skipped without a POST. Every other grant
 * is POSTed, whatever the row's marker, since a grant minted in a transient
 * session derives as unknown while chaining under a generation delegation
 * that stays alive until its own TTL.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.user {User}   the session user (activity actor)
 * @param options.app {ConnectedApp}
 * @param [options.onStage] {GrantRevocationStageHook}   the entry point's
 *   stage marks, one per landed write
 * @returns {Promise<{ revoked: number; withdrawn: number; skipped: number;
 *   rotated: number }>}   the grant outcome, plus the collections the
 *   rotation re-keyed. `withdrawn` counts the grants this call's own POSTs
 *   revoked, leaving out any already revoked
 */
export async function revokeAppAccess({
  storage,
  user,
  app,
  onStage
}: {
  storage: StorageManager
  user: User
  app: ConnectedApp
  onStage?: GrantRevocationStageHook
}): Promise<{
  revoked: number
  withdrawn: number
  skipped: number
  rotated: number
}> {
  const { outcome, rotated, entry, handledZcapIds } = await revokeAppAuthority({
    storage,
    subjectDid: app.subjectDid,
    onStage
  })
  // The key the entry names now, which a consent since the listing may have
  // re-pointed.
  if (entry.appKey !== undefined) {
    await storage.deleteAppKeyResource({
      appKey: entry.appKey,
      did: app.subjectDid
    })
    onStage?.('delete-app-key')
  }
  await storage.retireConnectionEntry({
    did: app.subjectDid,
    handledZcapIds
  })
  onStage?.('retire-entry')
  await storage.addHistoryAppRevoke({
    user,
    origin: app.origin ?? '',
    name: app.name ?? app.subjectDid,
    revoked: outcome.revoked,
    skipped: outcome.skipped
  })
  onStage?.('record-activity')
  return {
    revoked: outcome.revoked,
    withdrawn: outcome.withdrawn,
    skipped: outcome.skipped,
    rotated
  }
}

/**
 * Revokes a connected agent's storage grants. The first write empties the
 * entry's `grantsReceived` and `outbox` in its own compare-and-swap
 * (`StorageManager.clearConnectionChannel`), before any POST: no pass
 * renews or pushes to an entry with no channel, so a revoke torn after it
 * cannot be undone by the next login's renewal. The write is durable and a
 * re-run finds it done. Then the collection rotation and the grant POSTs run
 * on the WAS server, then the agent's entry is retired, then the revocation
 * is recorded. There is no app key to delete. A stage that does not land
 * throws before the retirement, so the row stays listed and a retry re-runs
 * every stage, as on the app path ({@link revokeAppAccess}). Every grant on
 * the entry is POSTed, a superseded renewal included. The rotation covers
 * every collection the entry's grants target, one the agent was admitted to
 * and did not create included, and every collection its `generator` stamp
 * names. The recorded Revoke names the grants the run confirmed revoked; it
 * is audit trail, and the retirement is what takes the row off the listing.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.user {User}   the session user (activity actor)
 * @param options.agent {ConnectedAgent}
 * @param [options.onStage] {GrantRevocationStageHook}   the entry point's
 *   stage marks, one per landed write
 * @returns {Promise<{ revoked: number; withdrawn: number; skipped: number;
 *   rotated: number }>}   the grant outcome, plus the collections the
 *   rotation re-keyed. `withdrawn` counts the grants this call's own POSTs
 *   revoked, leaving out any already revoked
 */
export async function revokeAgentAccess({
  storage,
  user,
  agent,
  onStage
}: {
  storage: StorageManager
  user: User
  agent: ConnectedAgent
  onStage?: GrantRevocationStageHook
}): Promise<{
  revoked: number
  withdrawn: number
  skipped: number
  rotated: number
}> {
  await storage.clearConnectionChannel({ did: agent.controller })
  const directory = await storage.readConnectionsListing()
  const { grants } = partyOf({ directory, did: agent.controller })
  const { outcome, rotated } = await rotateThenRevokeGrants({
    storage,
    did: agent.controller,
    grants,
    directory,
    failureMessage:
      'Could not rotate every collection off the agent being revoked.',
    onStage
  })
  await storage.retireConnectionEntry({
    did: agent.controller,
    handledZcapIds: grants.map(grant => grant.zcapId)
  })
  onStage?.('retire-entry')
  await storage.addHistoryAgentRevoke({
    user,
    origin: agent.origin,
    controller: agent.controller,
    zcaps: outcome.revokedIds.map(id => ({ id })),
    ...(agent.name !== undefined && { actor: { name: agent.name } }),
    revoked: outcome.revoked,
    skipped: outcome.skipped
  })
  onStage?.('record-activity')
  return {
    revoked: outcome.revoked,
    withdrawn: outcome.withdrawn,
    skipped: outcome.skipped,
    rotated
  }
}

/**
 * Retires a party's `connections` entry of any kind once its grants are
 * revoked: the wallet-client disconnect's and the forget's retirement. A
 * wallet-client entry normally carries no grants, and then it is only
 * retired. One that does (a planted entry, or a write before the kind check)
 * does not lose them silently: they are POSTed and their grantee is rotated
 * off their targets first, as an app or agent revocation does, and the
 * retirement passes their ids. Throws what a stage throws, before the
 * retirement.
 *
 * @param options {object}
 * @param options.storage {StorageManager}
 * @param options.did {string}   the party's DID
 * @returns {Promise<void>}
 */
export async function retireConnectionParty({
  storage,
  did
}: {
  storage: StorageManager
  did: string
}): Promise<void> {
  const directory = await storage.readConnectionsListing()
  const { grants } = partyOf({ directory, did })
  if (grants.length > 0) {
    await rotateThenRevokeGrants({
      storage,
      did,
      grants,
      directory,
      failureMessage:
        'Could not rotate every collection off the party being retired.'
    })
  }
  await storage.retireConnectionEntry({
    did,
    handledZcapIds: grants.map(grant => grant.zcapId)
  })
}
