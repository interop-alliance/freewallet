/**
 * Fixtures for the tests that read the `connections` directory through
 * `src/lib/connectedApps.ts`: capabilities shaped the way a consent records
 * them, entries written through wallet-core's own upsert helpers over the
 * in-memory store, the one listing read every reader resolves against, and a
 * `StorageManager` double whose directory methods run over that store.
 *
 * The agent grant fixtures the inbox pass and the agent reconnect tests
 * share are signed for real (`eddsa-jcs-2022`), so the proof check the
 * renewal and the offers reader run verifies their signatures: a grant
 * under the Space root signed by an account key, a grant a transient session
 * minted under a generation delegation, and a fake zcap client that signs
 * the grants it mints the same way.
 */
import { vi } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import { DataIntegrityProof } from '@interop/data-integrity-proof'
import { createSignCryptosuite } from '@interop/ed25519-signature/eddsa-jcs-2022'
import { agentsFromSeed } from '@interop/was-client/identity'
import type { AccountSignerCheck } from '@interop/wallet-core/clientAnnex'
import {
  clearReceivedGrants,
  connectionDidKey,
  connectionSeedTag,
  readConnections,
  recordGrants,
  retireConnection,
  type ConnectionGrant,
  type ConnectionKind,
  type GrantKind,
  type ReadConnection
} from '@interop/wallet-core/connections'
import { webvhSigner } from '@interop/wallet-core/webvh'
import type { StorageManager } from '@/stores/storageManager'
import type { Session } from '@/types/auth'
import { HMAC_KEY, memoryConnectionsStore } from './memoryConnections'

/**
 * The Space every fixture capability targets, as its container URL.
 */
export const SPACE_URL = 'https://was.example/space/s/'

/**
 * A time well past every fixture's clock.
 */
export const FUTURE = '2099-01-01T00:00:00.000Z'

/**
 * A time well before every fixture's clock.
 */
export const PAST = '2000-01-01T00:00:00.000Z'

/**
 * Real Ed25519 did:keys, so a grant's controller derives a recipient kid.
 */
export const AGENT_DID =
  'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
export const OTHER_AGENT_DID =
  'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
export const APP_DID =
  'did:key:z6MkqojacRDqmQgDi4ESKKhGDqnZx4C6cChAbQZXvnUFX7D7'
export const OTHER_APP_DID =
  'did:key:z6MkqEPctyQs9MofPZCw2XdeFi2dTMoMqHKhfoWsfitrnprw'
export const CLIENT_DID =
  'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'

/**
 * The verification method that signed every fixture delegation.
 */
export const WALLET_SIGNER = 'did:webvh:scid:was.example:space:s#z6MkWallet'

/**
 * A delegated capability as a consent records it on an entry.
 *
 * @param options {object}
 * @param options.id {string}
 * @param options.controller {string}   the grantee DID
 * @param [options.collection] {string}   the targeted collection id
 * @param [options.expires] {string}
 * @param [options.allowedAction] {string[]}
 * @returns {object}
 */
export function grantZcap({
  id,
  controller,
  collection = 'notes',
  expires = FUTURE,
  allowedAction = ['GET']
}: {
  id: string
  controller: string
  collection?: string
  expires?: string
  allowedAction?: string[]
}): Record<string, unknown> {
  return {
    '@context': ['https://w3id.org/zcap/v1'],
    id,
    controller,
    parentCapability: `urn:zcap:root:${encodeURIComponent(SPACE_URL)}`,
    invocationTarget: `${SPACE_URL}${collection}/`,
    allowedAction,
    expires,
    proof: {
      type: 'Ed25519Signature2020',
      proofPurpose: 'capabilityDelegation',
      verificationMethod: WALLET_SIGNER,
      capabilityChain: [`urn:zcap:root:${encodeURIComponent(SPACE_URL)}`]
    }
  }
}

/**
 * An in-memory directory whose store's `get` and `list` are spies, so a test
 * can tell a listing read from a GET at a derived id.
 *
 * @returns {object}   the store, its rows, its writes, and the two spies
 */
export function fixtureDirectory() {
  const directory = memoryConnectionsStore()
  const get = vi.spyOn(directory.store, 'get')
  const list = vi.spyOn(directory.store, 'list')
  return { ...directory, get, list }
}

/**
 * One fixture directory.
 */
export type FixtureDirectory = ReturnType<typeof fixtureDirectory>

/**
 * Records a consent on a party's entry, through wallet-core's own
 * `recordGrants`, at a fixed time.
 *
 * @param options {object}
 * @param options.directory {FixtureDirectory}
 * @param options.did {string}
 * @param options.kind {ConnectionKind}
 * @param [options.grants] {Array<object>}   the capabilities, each recorded
 *   as `grantKind`
 * @param [options.grantKind] {GrantKind}
 * @param [options.name] {string}
 * @param [options.origin] {string}
 * @param [options.url] {string}
 * @param [options.appKey] {string}
 * @param [options.at] {string}   the consent's ISO time
 * @returns {Promise<void>}
 */
export async function recordConsent({
  directory,
  did,
  kind,
  grants = [],
  grantKind = 'grant',
  name,
  origin,
  url,
  appKey,
  at = '2026-08-01T00:00:00.000Z'
}: {
  directory: FixtureDirectory
  did: string
  kind: ConnectionKind
  grants?: Array<Record<string, unknown>>
  grantKind?: GrantKind
  name?: string
  origin?: string
  url?: string
  appKey?: string
  at?: string
}): Promise<void> {
  await recordGrants({
    store: directory.store,
    hmacKey: HMAC_KEY,
    did,
    kind,
    spaceUrl: SPACE_URL,
    grants: grants.map(zcap => ({ zcap, grantKind })),
    ...(name !== undefined && { name }),
    ...(origin !== undefined && { origin }),
    ...(url !== undefined && { url }),
    ...(appKey !== undefined && { appKey }),
    now: new Date(at)
  })
}

/**
 * Retires a party's entry, through wallet-core's own `retireConnection`,
 * handling every grant it carries.
 *
 * @param options {object}
 * @param options.directory {FixtureDirectory}
 * @param options.did {string}
 * @param options.zcapIds {string[]}   the grants the retirement handled
 * @returns {Promise<void>}
 */
export async function retireParty({
  directory,
  did,
  zcapIds
}: {
  directory: FixtureDirectory
  did: string
  zcapIds: string[]
}): Promise<void> {
  await retireConnection({
    store: directory.store,
    hmacKey: HMAC_KEY,
    did,
    handledZcapIds: zcapIds,
    spaceUrl: SPACE_URL
  })
}

/**
 * The directory's entries, from one listing read.
 *
 * @param directory {FixtureDirectory}
 * @returns {Promise<ReadConnection[]>}
 */
export async function listedConnections(
  directory: FixtureDirectory
): Promise<ReadConnection[]> {
  const listing = await readConnections({
    store: directory.store,
    hmacKey: HMAC_KEY
  })
  return listing!.entries
}

/**
 * The parsed entry whose `id` is the DID, from one listing read.
 *
 * @param options {object}
 * @param options.directory {FixtureDirectory}
 * @param options.did {string}
 * @returns {Promise<ReadConnection['entry'] | undefined>}
 */
export async function entryOf({
  directory,
  did
}: {
  directory: FixtureDirectory
  did: string
}): Promise<ReadConnection['entry'] | undefined> {
  const connections = await listedConnections(directory)
  return connections.find(({ entry }) => entry.id === did)?.entry
}

/**
 * A `StorageManager` double over a fixture directory: the listing read, the
 * channel clear, and the retirement run wallet-core's own reader and writers
 * over the in-memory store, and the server-side stages are spies that report every grant they
 * are handed as revoked on this call. The rotation reports one collection
 * re-keyed.
 *
 * @param options {object}
 * @param options.directory {FixtureDirectory}
 * @param [options.rosterCollections] {string[] | Error}   what the roster
 *   read reports for each grantee: the collections still listing it, or one
 *   failed read
 * @returns {object}   the double, typed as its spies
 */
export function directoryStorage({
  directory,
  rosterCollections = []
}: {
  directory: FixtureDirectory
  rosterCollections?: string[] | Error
}) {
  const calls: string[] = []
  const storage = {
    calls,
    spaceUrl: SPACE_URL,
    readConnectionsListing: vi.fn(async () => {
      calls.push('readConnectionsListing')
      const listing = await readConnections({
        store: directory.store,
        hmacKey: HMAC_KEY
      })
      return {
        store: directory.store,
        hmacKey: HMAC_KEY,
        listing: listing!,
        spaceUrl: SPACE_URL
      }
    }),
    clearConnectionChannel: vi.fn(async ({ did }: { did: string }) => {
      calls.push('clearConnectionChannel')
      await clearReceivedGrants({
        store: directory.store,
        hmacKey: HMAC_KEY,
        did
      })
    }),
    revokeCollectionRecipients: vi.fn(
      async (_options: { did: string; grants: ConnectionGrant[] }) => {
        calls.push('revokeCollectionRecipients')
        return { collections: 1, rotated: 1, failed: 0, revokedIds: [] }
      }
    ),
    revokeConnectionGrants: vi.fn(
      async ({
        grants
      }: {
        grants: ConnectionGrant[]
        revokedByRotation?: readonly string[]
      }) => {
        calls.push('revokeConnectionGrants')
        return {
          revoked: grants.length,
          withdrawn: grants.length,
          skipped: 0,
          revokedIds: grants.map(grant => grant.zcapId)
        }
      }
    ),
    deleteAppKeyResource: vi.fn(
      async (_options: {
        appKey: string
        did: string
      }): Promise<'deleted' | 'absent' | 'foreign'> => {
        calls.push('deleteAppKeyResource')
        return 'deleted'
      }
    ),
    retireConnectionEntry: vi.fn(
      async ({
        did,
        handledZcapIds
      }: {
        did: string
        handledZcapIds: Iterable<string>
      }) => {
        calls.push('retireConnectionEntry')
        await retireConnection({
          store: directory.store,
          hmacKey: HMAC_KEY,
          did,
          handledZcapIds,
          spaceUrl: SPACE_URL
        })
      }
    ),
    addHistoryAppRevoke: vi.fn(async () => {
      calls.push('addHistoryAppRevoke')
    }),
    addHistoryAgentRevoke: vi.fn(async () => {
      calls.push('addHistoryAgentRevoke')
    }),
    granteeRosterCollections: vi.fn(
      async ({ grantees }: { grantees: Array<{ controller: string }> }) =>
        grantees.map(({ controller }) =>
          rosterCollections instanceof Error
            ? { controller, collectionIds: [], failed: 1 }
            : { controller, collectionIds: rosterCollections, failed: 0 }
        )
    )
  }
  return storage
}

/**
 * The double, as the code under test takes it.
 *
 * @param storage {ReturnType<typeof directoryStorage>}
 * @returns {StorageManager}
 */
export function asStorageManager(
  storage: ReturnType<typeof directoryStorage>
): StorageManager {
  return storage as unknown as StorageManager
}

/**
 * One day, in milliseconds.
 */
export const DAY_MS = 24 * 60 * 60 * 1000

/**
 * The account the agent grant fixtures belong to, its Space's root
 * capability, and the collections and annex generation they name.
 */
export const ACCOUNT_DID = 'did:webvh:scid:was.example:space:s'
export const ROOT = `urn:zcap:root:${encodeURIComponent(SPACE_URL)}`
export const INBOX_URL = `${SPACE_URL}inbox/`
export const NEWS_URL = `${SPACE_URL}news/`
export const AGENT_INBOX = 'https://agent.example/space/a/inbox/'
export const ANNEX_DID =
  'did:webvh:scid:was.example:space:aux:gen-AAAAAAAAAAAAAAAA'
export const POINTED_DELEGATION = 'urn:uuid:generation-delegation-current'
/**
 * A superseded generation of the same auxiliary Space whose log still
 * stands, so a grant minted under it is renewable until the GC collects it.
 */
export const STANDING_ANNEX_DID =
  'did:webvh:scid:was.example:space:aux:gen-CCCCCCCCCCCCCCCC'
/**
 * A generation of the same auxiliary Space the GC collected: no annex
 * document resolves for it.
 */
export const COLLECTED_ANNEX_DID =
  'did:webvh:scid:was.example:space:aux:gen-BBBBBBBBBBBBBBBB'
/**
 * The seed byte of the per-visit key each standing generation's annex
 * document lists under `capabilityDelegation`, and the one {@link annexGrant}
 * signs with by default.
 */
const LISTED_VISIT_SEED = 6

/**
 * An ISO time `days` from now.
 *
 * @param days {number}
 * @returns {string}
 */
export function inDays(days: number): string {
  return new Date(Date.now() + days * DAY_MS).toISOString()
}

/**
 * The account's delegation keys: an enrolled client and a ladder VM the
 * document lists under `capabilityDelegation`, and a struck key it no
 * longer lists.
 */
export type AccountKeyName = 'client' | 'ladder' | 'struck'

/**
 * A delegation signer: its verification method id and its signing function.
 */
type FixtureSigner = ReturnType<typeof webvhSigner>

/**
 * The signer of one fixed seed under a DID.
 *
 * @param options {object}
 * @param options.seedByte {number}   the byte the 32-byte seed repeats
 * @param options.did {string}
 * @returns {Promise<FixtureSigner>}
 */
async function signerOf({
  seedByte,
  did
}: {
  seedByte: number
  did: string
}): Promise<FixtureSigner> {
  const { keyAgent } = await agentsFromSeed({
    seed: new Uint8Array(32).fill(seedByte)
  })
  return webvhSigner({ keyAgent, did })
}

let accountSignerSet: Promise<Record<AccountKeyName, FixtureSigner>> | undefined

/**
 * The account's three delegation signers, derived once.
 *
 * @returns {Promise<Record<AccountKeyName, FixtureSigner>>}
 */
async function accountSigners(): Promise<
  Record<AccountKeyName, FixtureSigner>
> {
  accountSignerSet ??= (async () => ({
    client: await signerOf({ seedByte: 1, did: ACCOUNT_DID }),
    ladder: await signerOf({ seedByte: 2, did: ACCOUNT_DID }),
    struck: await signerOf({ seedByte: 3, did: ACCOUNT_DID })
  }))()
  return await accountSignerSet
}

/**
 * The fragment of a verification method id, which the fixtures' ids carry as
 * the key's multibase.
 *
 * @param vmId {string}
 * @returns {string}
 */
function vmFragment(vmId: string): string {
  return vmId.slice(vmId.indexOf('#') + 1)
}

/**
 * Each account key's multibase, the fragment of its verification method id.
 *
 * @returns {Promise<Record<AccountKeyName, string>>}
 */
export async function accountKeys(): Promise<Record<AccountKeyName, string>> {
  const signers = await accountSigners()
  return {
    client: vmFragment(signers.client.id),
    ladder: vmFragment(signers.ladder.id),
    struck: vmFragment(signers.struck.id)
  }
}

/**
 * The account signer check the agent grant fixtures verify against: the
 * client and the ladder VM under `capabilityDelegation`, the pointer naming {@link ANNEX_DID}, and
 * the annex-document resolver the wallet supplies. The resolver resolves the
 * pointed generation and the superseded {@link STANDING_ANNEX_DID} to a
 * document listing the default visit key under `capabilityDelegation`, and
 * any other generation (the collected one) to `undefined`.
 *
 * @returns {Promise<AccountSignerCheck>}
 */
export async function fixtureSignerCheck(): Promise<AccountSignerCheck> {
  const { client, ladder } = await accountSigners()
  const keys = await accountKeys()
  const annexDocument = async ({
    clientAnnexDid
  }: {
    clientAnnexDid: string
  }) => {
    if (clientAnnexDid !== ANNEX_DID && clientAnnexDid !== STANDING_ANNEX_DID) {
      return undefined
    }
    const visit = await signerOf({
      seedByte: LISTED_VISIT_SEED,
      did: clientAnnexDid
    })
    return {
      id: clientAnnexDid,
      verificationMethod: [
        {
          id: visit.id,
          publicKeyMultibase: vmFragment(visit.id)
        }
      ],
      capabilityDelegation: [visit.id]
    } as never
  }
  return {
    accountDid: ACCOUNT_DID,
    doc: {
      id: ACCOUNT_DID,
      verificationMethod: [
        { id: client.id, publicKeyMultibase: keys.client },
        { id: ladder.id, publicKeyMultibase: keys.ladder }
      ],
      capabilityDelegation: [client.id, ladder.id]
    },
    clientAnnexDid: ANNEX_DID,
    annexDocument
  } as unknown as AccountSignerCheck
}

/**
 * A capability signed for real as a delegation: an `eddsa-jcs-2022`
 * `DataIntegrityProof` for `capabilityDelegation`, carrying the chain.
 *
 * @param options {object}
 * @param options.zcap {object}   the capability, no proof
 * @param options.signer {FixtureSigner}
 * @param options.capabilityChain {unknown[]}   the root id, then the
 *   embedded parent when there is one
 * @returns {Promise<Record<string, unknown>>}
 */
async function signedDelegation({
  zcap,
  signer,
  capabilityChain
}: {
  zcap: Record<string, unknown>
  signer: FixtureSigner
  capabilityChain: unknown[]
}): Promise<Record<string, unknown>> {
  const document = { '@context': ['https://w3id.org/zcap/v1'], ...zcap }
  const suite = new DataIntegrityProof({
    signer: { ...signer, algorithm: 'Ed25519' },
    cryptosuite: createSignCryptosuite()
  } as never)
  const proof = await suite.createProof({
    document: structuredClone(document),
    purpose: {
      update: async (draft: object) => ({
        ...draft,
        proofPurpose: 'capabilityDelegation',
        capabilityChain
      })
    },
    proofSet: [],
    documentLoader: async (url: string) => {
      throw new Error(`No document is served for "${url}".`)
    }
  } as never)
  return { ...document, proof }
}

/**
 * A generation delegation an account key minted to an annex DID.
 *
 * @param [options] {object}
 * @param [options.id] {string}
 * @param [options.controller] {string}   the annex DID
 * @param [options.signer] {AccountKeyName}
 * @param [options.expires] {string}
 * @returns {Promise<Record<string, unknown>>}
 */
export async function generationDelegation({
  id = POINTED_DELEGATION,
  controller = ANNEX_DID,
  signer = 'ladder',
  expires = inDays(330)
}: {
  id?: string
  controller?: string
  signer?: AccountKeyName
  expires?: string
} = {}): Promise<Record<string, unknown>> {
  return await signedDelegation({
    zcap: {
      id,
      controller,
      parentCapability: ROOT,
      invocationTarget: SPACE_URL,
      allowedAction: ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'],
      expires
    },
    signer: (await accountSigners())[signer],
    capabilityChain: [ROOT]
  })
}

/**
 * A grant this account delegated to an agent under the Space root, signed
 * by one of its keys.
 *
 * @param options {object}
 * @param options.id {string}
 * @param [options.controller] {string}
 * @param [options.target] {string}
 * @param [options.actions] {string[]}
 * @param [options.expires] {string}
 * @param [options.signer] {AccountKeyName}
 * @returns {Promise<Record<string, unknown>>}
 */
export async function rootGrant({
  id,
  controller = AGENT_DID,
  target = NEWS_URL,
  actions = ['GET', 'HEAD'],
  expires = inDays(60),
  signer = 'client'
}: {
  id: string
  controller?: string
  target?: string
  actions?: string[]
  expires?: string
  signer?: AccountKeyName
}): Promise<Record<string, unknown>> {
  return await signedDelegation({
    zcap: {
      id,
      controller,
      parentCapability: ROOT,
      invocationTarget: target,
      allowedAction: actions,
      expires
    },
    signer: (await accountSigners())[signer],
    capabilityChain: [ROOT]
  })
}

/**
 * A grant a transient session minted under a generation delegation, which
 * it embeds as the last link of its chain, signed by a per-visit key under
 * the annex DID.
 *
 * @param options {object}
 * @param options.id {string}
 * @param [options.controller] {string}
 * @param [options.target] {string}
 * @param [options.actions] {string[]}
 * @param [options.expires] {string}
 * @param [options.parentId] {string}
 * @param [options.parentController] {string}   the annex DID
 * @param [options.parentSigner] {AccountKeyName}   the parent's signing key
 * @param [options.visitSeed] {number}   the seed byte of the per-visit key
 *   that signs the leaf; the default is the one the generation's annex
 *   document lists, any other is a key it never listed
 * @returns {Promise<Record<string, unknown>>}
 */
export async function annexGrant({
  id,
  controller = AGENT_DID,
  target = NEWS_URL,
  actions = ['GET', 'HEAD'],
  expires = inDays(300),
  parentId = POINTED_DELEGATION,
  parentController = ANNEX_DID,
  parentSigner = 'ladder',
  visitSeed = LISTED_VISIT_SEED
}: {
  id: string
  controller?: string
  target?: string
  actions?: string[]
  expires?: string
  parentId?: string
  parentController?: string
  parentSigner?: AccountKeyName
  visitSeed?: number
}): Promise<Record<string, unknown>> {
  const parent = await generationDelegation({
    id: parentId,
    controller: parentController,
    signer: parentSigner
  })
  return await signedDelegation({
    zcap: {
      id,
      controller,
      parentCapability: parentId,
      invocationTarget: target,
      allowedAction: actions,
      expires
    },
    signer: await signerOf({ seedByte: visitSeed, did: parentController }),
    capabilityChain: [ROOT, parent]
  })
}

/**
 * A channel capability an agent delegates to the wallet's pairwise did:key:
 * POST on the agent's own inbox.
 *
 * @param options {object}
 * @param options.id {string}
 * @param options.controller {string}   the pairwise did:key
 * @param [options.expires] {string}
 * @param [options.target] {string}
 * @returns {Record<string, unknown>}
 */
export function channelZcap({
  id,
  controller,
  expires = inDays(200),
  target = AGENT_INBOX
}: {
  id: string
  controller: string
  expires?: string
  target?: string
}): Record<string, unknown> {
  return {
    id,
    controller,
    parentCapability: 'urn:zcap:root:agent',
    invocationTarget: target,
    allowedAction: ['POST'],
    expires,
    proof: {
      type: 'Ed25519Signature2020',
      proofPurpose: 'capabilityDelegation',
      verificationMethod: 'did:webvh:agent#z6MkAgent',
      capabilityChain: ['urn:zcap:root:agent']
    }
  }
}

/**
 * A fresh pairwise seed, its tag, and its did:key.
 *
 * @returns {Promise<{ seed: string, seedTag: string, did: string }>}
 */
export async function pairwiseSeed(): Promise<{
  seed: string
  seedTag: string
  did: string
}> {
  const seed = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString(
    'base64url'
  )
  const seedTag = await connectionSeedTag({ hmacKey: HMAC_KEY, seed })
  const { did } = await connectionDidKey({ hmacKey: HMAC_KEY, seed, seedTag })
  return { seed, seedTag, did }
}

/**
 * A fake zcap client that mints grants with predictable ids, signed for
 * real: under the root as the enrolled client, and under a generation
 * delegation as a per-visit key, embedding the parent.
 *
 * @param [options] {object}
 * @param [options.idPrefix] {string}   minted ids read
 *   `urn:uuid:<idPrefix>-<n>`
 * @returns {object}   the client and the calls it took
 */
export function fakeZcapClient({
  idPrefix = 'minted'
}: { idPrefix?: string } = {}): {
  zcapClient: Session['profile']['zcapClient']
  calls: Array<Record<string, unknown>>
} {
  const calls: Array<Record<string, unknown>> = []
  const zcapClient = {
    async delegate(options: {
      capability: string | IZcap
      invocationTarget: string
      controller: string
      allowedActions: string[]
      expires: Date
    }) {
      calls.push(options)
      const zcap = {
        id: `urn:uuid:${idPrefix}-${calls.length}`,
        controller: options.controller,
        invocationTarget: options.invocationTarget,
        allowedAction: options.allowedActions,
        expires: options.expires.toISOString()
      }
      if (typeof options.capability === 'string') {
        return await signedDelegation({
          zcap: { ...zcap, parentCapability: options.capability },
          signer: (await accountSigners()).client,
          capabilityChain: [options.capability]
        })
      }
      const parent = options.capability as { id: string; controller: string }
      return await signedDelegation({
        zcap: { ...zcap, parentCapability: parent.id },
        signer: await signerOf({
          seedByte: LISTED_VISIT_SEED,
          did: parent.controller
        }),
        capabilityChain: [ROOT, options.capability]
      })
    }
  } as unknown as Session['profile']['zcapClient']
  return { zcapClient, calls }
}
