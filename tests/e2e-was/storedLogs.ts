/**
 * The store-side reader for the account's capability-gated logs: the user key
 * wrap-set roster (`key-map/user-key.jsonl`) and a client annex generation's
 * log (`<gen-id>/did.jsonl`).
 *
 * Neither is world-readable, and neither can be fetched from a test runner:
 * the roster and the annex sit behind the account's zcap authority, and a
 * transient visit's own authority lives only inside the page. So the
 * assertions read the teaching server's FileSystem backend off disk, the way
 * `storeOracle.ts` already answers "does this Space still exist?". A resource
 * is one file inside its collection directory, named `r.<resource id with
 * dots percent-encoded>.<content type>.<extension>`, holding the stored bytes
 * verbatim.
 *
 * Both logs are JSONL: one entry per line, each entry restating the
 * parameters that hold at its version, so the last line carries the current
 * `updateKeys` and `nextKeyHashes` and the current roster state.
 */
import fs from 'node:fs/promises'
import path from 'node:path'
import { parseVersionedVm, vmFragmentOf } from '@interop/vh-resource-log'
import { storedSpacesDir } from './storeOracle'

/**
 * One stored log entry, in the shape both logs share. Only the members the
 * assertions read are typed.
 */
export interface StoredLogEntry {
  versionId: string
  versionTime?: string
  parameters?: {
    updateKeys?: string[]
    nextKeyHashes?: string[]
  }
  state?: {
    epochs?: Array<{ id: string }>
    currentEpoch?: string
  }
}

/**
 * The stored bytes of one resource, or undefined when the collection holds no
 * such resource (or does not exist).
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param options.resourceId {string}   e.g. `user-key.jsonl`
 * @returns {Promise<string | undefined>}
 */
export async function readStoredResource({
  spaceId,
  collectionId,
  resourceId
}: {
  spaceId: string
  collectionId: string
  resourceId: string
}): Promise<string | undefined> {
  const directory = path.join(storedSpacesDir(), spaceId, collectionId)
  let entries: string[]
  try {
    entries = await fs.readdir(directory)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return undefined
    }
    throw err
  }
  // The backend percent-encodes the dots in a resource id, then appends the
  // encoded content type and an extension, so match on the id prefix alone.
  const prefix = `r.${resourceId.replace(/\./g, '%2E')}.`
  const fileName = entries.find(entry => entry.startsWith(prefix))
  if (fileName === undefined) {
    return undefined
  }
  return await fs.readFile(path.join(directory, fileName), 'utf8')
}

/**
 * A stored JSONL log's entries, oldest first. An absent resource reads as an
 * empty log.
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param options.resourceId {string}
 * @returns {Promise<StoredLogEntry[]>}
 */
export async function readStoredLog({
  spaceId,
  collectionId,
  resourceId
}: {
  spaceId: string
  collectionId: string
  resourceId: string
}): Promise<StoredLogEntry[]> {
  const text = await readStoredResource({ spaceId, collectionId, resourceId })
  if (text === undefined) {
    return []
  }
  return text
    .split('\n')
    .filter(line => line.trim().length > 0)
    .map(line => JSON.parse(line) as StoredLogEntry)
}

/**
 * The user key roster's state right now: how many entries the log holds, the
 * epoch ids it carries, and which one is current. The roster's current epoch
 * IS the current user key, so a rotation shows up as one more epoch id and a
 * moved `currentEpoch`.
 *
 * @param options {object}
 * @param options.spaceId {string}   the account Space id
 * @returns {Promise<{ entries: number, epochIds: string[],
 *   currentEpoch: string | undefined }>}
 */
export async function readUserKeyRoster({
  spaceId
}: {
  spaceId: string
}): Promise<{
  entries: number
  epochIds: string[]
  currentEpoch: string | undefined
}> {
  const log = await readStoredLog({
    spaceId,
    collectionId: 'key-map',
    resourceId: 'user-key.jsonl'
  })
  const head = log[log.length - 1]
  return {
    entries: log.length,
    epochIds: (head?.state?.epochs ?? []).map(epoch => epoch.id),
    currentEpoch: head?.state?.currentEpoch
  }
}

/**
 * A client annex generation's log state: its entry count and the update-key
 * and committed-hash sets that hold at its head. A credential's annex rung is
 * a committed hash there, so a rung commit adds one and a rung strike removes
 * one.
 *
 * @param options {object}
 * @param options.annexSpaceId {string}
 * @param options.generationId {string}   e.g. `gen-Ux3v0kQf9aPmB2hZ`
 * @returns {Promise<{ entries: number, updateKeys: string[],
 *   nextKeyHashes: string[] }>}
 */
export async function readAnnexGeneration({
  annexSpaceId,
  generationId
}: {
  annexSpaceId: string
  generationId: string
}): Promise<{
  entries: number
  updateKeys: string[]
  nextKeyHashes: string[]
}> {
  const log = await readStoredLog({
    spaceId: annexSpaceId,
    collectionId: generationId,
    resourceId: 'did.jsonl'
  })
  const head = log[log.length - 1]
  return {
    entries: log.length,
    updateKeys: head?.parameters?.updateKeys ?? [],
    nextKeyHashes: head?.parameters?.nextKeyHashes ?? []
  }
}

/**
 * The annex Space id and generation id a `#DelegatedClients` pointer names.
 * The pointer is the annex DID, whose method-specific id ends
 * `:space:<spaceId>:<generationId>`.
 *
 * @param options {object}
 * @param options.pointer {string}   the pointer's `serviceEndpoint`
 * @returns {{ annexSpaceId: string, generationId: string }}
 */
export function annexLocationOf({ pointer }: { pointer: string }): {
  annexSpaceId: string
  generationId: string
} {
  const match = /:space:([^:]+):(gen-[^:]+)$/.exec(pointer)
  if (!match) {
    throw new Error(`Not a client annex pointer: "${pointer}".`)
  }
  return {
    annexSpaceId: decodeURIComponent(match[1]!),
    generationId: match[2]!
  }
}

/**
 * An encrypted collection's governing descriptor log's stored lines, oldest
 * first, or an empty list when the collection holds no log. The FileSystem
 * backend keeps the log beside the collection's resources, as
 * `.collectionlog.<collectionId>.json`, a JSON object whose `body` member is
 * the JSONL log verbatim.
 *
 * @param options {object}
 * @param options.spaceId {string}   the account Space id
 * @param options.collectionId {string}   e.g. `contacts`
 * @returns {Promise<string[]>}
 */
async function readCollectionLogLines({
  spaceId,
  collectionId
}: {
  spaceId: string
  collectionId: string
}): Promise<string[]> {
  let text: string
  try {
    text = await fs.readFile(
      path.join(
        storedSpacesDir(),
        spaceId,
        collectionId,
        `.collectionlog.${collectionId}.json`
      ),
      'utf8'
    )
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return []
    }
    throw err
  }
  const { body } = JSON.parse(text) as { body: string }
  return body.split('\n').filter(line => line.trim().length > 0)
}

/**
 * An encrypted collection's governing descriptor log (`<collection>/meta/log`)
 * as the store holds it: its entry count, the current epoch id, and the user
 * key generations that epoch's recipients name.
 *
 * The FileSystem backend keeps the log beside the collection's resources, as
 * `.collectionlog.<collectionId>.json`, a JSON object whose `body` member is
 * the JSONL log verbatim. Each entry restates the whole `encryption` state,
 * so the last line is the head. A recipient's `header.kid` is
 * `<did:key>#<fragment>`, and the roster's epoch ids are the user key
 * generations' did:keys, so the DID half of a kid is the generation it
 * names. An absent log reads as zero entries.
 *
 * @param options {object}
 * @param options.spaceId {string}   the account Space id
 * @param options.collectionId {string}   e.g. `contacts`
 * @returns {Promise<{ entries: number, currentEpoch: string | undefined,
 *   generations: string[] }>}
 */
export async function readCollectionEpoch({
  spaceId,
  collectionId
}: {
  spaceId: string
  collectionId: string
}): Promise<{
  entries: number
  currentEpoch: string | undefined
  generations: string[]
}> {
  const lines = await readCollectionLogLines({ spaceId, collectionId })
  if (lines.length === 0) {
    return { entries: 0, currentEpoch: undefined, generations: [] }
  }
  const head = JSON.parse(lines[lines.length - 1]!) as {
    state?: {
      currentEpoch?: string
      epochs?: Array<{
        id: string
        recipients?: Array<{ header?: { kid?: string } }>
      }>
    }
  }
  const currentEpoch = head.state?.currentEpoch
  const current = head.state?.epochs?.find(epoch => epoch.id === currentEpoch)
  const generations = (current?.recipients ?? [])
    .map(recipient => recipient.header?.kid?.split('#')[0])
    .filter((did): did is string => Boolean(did))
  return { entries: lines.length, currentEpoch, generations }
}

/**
 * The key multibases a document relation names, whether it lists a method by
 * reference or embeds it.
 *
 * @param relation {Array<string | { id: string }> | undefined}
 * @returns {Set<string>}
 */
function keysOf(
  relation: Array<string | { id: string }> | undefined
): Set<string> {
  return new Set(
    (relation ?? [])
      .map(method =>
        vmFragmentOf(typeof method === 'string' ? method : method.id)
      )
      .filter((key): key is string => key !== undefined)
  )
}

/**
 * The account log (`id/did.jsonl`) as the store holds it: each version's
 * `versionId` and the key multibases its document lists under
 * `assertionMethod` and under `capabilityInvocation`, oldest first. Each did:webvh entry's `state` is the
 * whole document at that version, and a verification method's fragment is
 * its public key multibase, so a reference and an embedded method compare as
 * key material.
 *
 * @param options {object}
 * @param options.spaceId {string}   the account Space id
 * @returns {Promise<Array<{ versionId: string, assertionKeys: Set<string>,
 *   invocationKeys: Set<string> }>>}
 */
export async function readAccountLogVersions({
  spaceId
}: {
  spaceId: string
}): Promise<
  Array<{
    versionId: string
    assertionKeys: Set<string>
    invocationKeys: Set<string>
  }>
> {
  const log = (await readStoredLog({
    spaceId,
    collectionId: 'id',
    resourceId: 'did.jsonl'
  })) as Array<
    StoredLogEntry & {
      state?: {
        assertionMethod?: Array<string | { id: string }>
        capabilityInvocation?: Array<string | { id: string }>
      }
    }
  >
  return log.map(entry => ({
    versionId: entry.versionId,
    assertionKeys: keysOf(entry.state?.assertionMethod),
    invocationKeys: keysOf(entry.state?.capabilityInvocation)
  }))
}

/**
 * The account log's latest membership change: the largest index into its
 * versions whose `assertionMethod` key set lost a member against its
 * predecessor's, or `0` when no version ever removed one. This is the index
 * the sealing sweep compares a collection log's head against
 * (`latestAssertionRemovalIndex` in `@interop/vh-resource-log`), computed
 * here from the stored log rather than from a verified controller view.
 *
 * @param options {object}
 * @param options.versions {Array<{ assertionKeys: Set<string> }>}   from
 *   `readAccountLogVersions`
 * @returns {number}
 */
export function latestAssertionRemovalIndexOf({
  versions
}: {
  versions: Array<{ assertionKeys: Set<string> }>
}): number {
  let removalIndex = 0
  versions.forEach(({ assertionKeys }, index) => {
    if (index === 0) {
      return
    }
    for (const key of versions[index - 1]!.assertionKeys) {
      if (!assertionKeys.has(key)) {
        removalIndex = index
        break
      }
    }
  })
  return removalIndex
}

/**
 * An encrypted collection's descriptor log head as the store holds it: the
 * account log version the head entry anchors at, and the key that signed it.
 * A resource log entry's proof names its signer as a versioned
 * verification-method DID URL, `<account did>?versionId=<account versionId>#
 * <key multibase>`, so the anchor and the signer are both read off the head
 * entry's first proof. `anchorIndex` is that versionId's position in the
 * account log, or `-1` when the account log carries no such version. An
 * absent log reads as `undefined`.
 *
 * @param options {object}
 * @param options.spaceId {string}   the account Space id
 * @param options.collectionId {string}   e.g. `contacts`
 * @param options.accountVersionIds {string[]}   the account log's
 *   versionIds, oldest first
 * @returns {Promise<{ entries: number, anchorVersionId: string | undefined,
 *   anchorIndex: number, signerKey: string | undefined } | undefined>}
 */
export async function readCollectionLogHeadAnchor({
  spaceId,
  collectionId,
  accountVersionIds
}: {
  spaceId: string
  collectionId: string
  accountVersionIds: string[]
}): Promise<
  | {
      entries: number
      anchorVersionId: string | undefined
      anchorIndex: number
      signerKey: string | undefined
    }
  | undefined
> {
  const lines = await readCollectionLogLines({ spaceId, collectionId })
  if (lines.length === 0) {
    return undefined
  }
  const head = JSON.parse(lines[lines.length - 1]!) as {
    proof?:
      { verificationMethod?: string } | Array<{ verificationMethod?: string }>
  }
  const proof = Array.isArray(head.proof) ? head.proof[0] : head.proof
  const parsed =
    proof?.verificationMethod === undefined
      ? undefined
      : parseVersionedVm(proof.verificationMethod)
  const anchorVersionId = parsed?.controllerVersionId
  return {
    entries: lines.length,
    anchorVersionId,
    anchorIndex:
      anchorVersionId === undefined
        ? -1
        : accountVersionIds.indexOf(anchorVersionId),
    signerKey: parsed?.keyMultibase
  }
}

/**
 * The encrypted standard collections every signup provisions.
 */
export const ENCRYPTED_STANDARD_COLLECTIONS = [
  'private-credentials',
  'wallet-activity',
  'contacts',
  'contacts-history',
  'app-connections'
]

/**
 * Where every encrypted standard collection's descriptor log head stands
 * against the account log's latest `assertionMethod` removal: the removal's
 * index and versionId, the key set the account document lists under
 * `assertionMethod` and under `capabilityInvocation` at its latest version,
 * and each collection's head
 * anchor (from `readCollectionLogHeadAnchor`). A head is sealed when its
 * `anchorIndex` is at or past `removalIndex`.
 *
 * @param options {object}
 * @param options.spaceId {string}   the account Space id
 * @returns {Promise<{ removalIndex: number, removalVersionId: string,
 *   latestAssertionKeys: Set<string>, latestInvocationKeys: Set<string>,
 *   heads: Record<string,
 *   Awaited<ReturnType<typeof readCollectionLogHeadAnchor>>> }>}
 */
export async function readCollectionSealState({
  spaceId
}: {
  spaceId: string
}): Promise<{
  removalIndex: number
  removalVersionId: string
  latestAssertionKeys: Set<string>
  latestInvocationKeys: Set<string>
  heads: Record<string, Awaited<ReturnType<typeof readCollectionLogHeadAnchor>>>
}> {
  const versions = await readAccountLogVersions({ spaceId })
  const accountVersionIds = versions.map(version => version.versionId)
  const removalIndex = latestAssertionRemovalIndexOf({ versions })
  const heads: Record<
    string,
    Awaited<ReturnType<typeof readCollectionLogHeadAnchor>>
  > = {}
  for (const collectionId of ENCRYPTED_STANDARD_COLLECTIONS) {
    heads[collectionId] = await readCollectionLogHeadAnchor({
      spaceId,
      collectionId,
      accountVersionIds
    })
  }
  return {
    removalIndex,
    removalVersionId: accountVersionIds[removalIndex]!,
    latestAssertionKeys:
      versions[versions.length - 1]?.assertionKeys ?? new Set(),
    latestInvocationKeys:
      versions[versions.length - 1]?.invocationKeys ?? new Set(),
    heads
  }
}
