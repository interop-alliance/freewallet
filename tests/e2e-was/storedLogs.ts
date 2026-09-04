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
