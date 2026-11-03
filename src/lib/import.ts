/**
 * Reads wallet import tarballs and extracts credentials from credentials/*.json,
 * and decides what an archive import does next: the pre-import refusal and
 * the post-import outcome, both pure, so the component that hosts the import
 * only toasts and navigates.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { parseTar } from 'nanotar'
import { MAX_CREDENTIAL_JSON_FILE_BYTES } from '@/app.config'
import { credentialsFromJSON } from '@/lib/credentialsFromJSON'
import {
  CredentialJsonFileError,
  CredentialJsonFileTooLargeError
} from '@/lib/resolveCredentialJsonFiles'
import type { ImportSpaceSummary } from '@/stores/storageManager'

const SPACE_PREFIX = 'space/'
const CREDENTIALS_PREFIX = 'credentials/'

type ParsedTarEntry = ReturnType<typeof parseTar>[number]

function hasPathPrefix(entries: ParsedTarEntry[], prefix: string): boolean {
  return entries.some(entry => entry.name.startsWith(prefix))
}

function isTopLevelJson(path: string, prefix: string): boolean {
  const relative = path.slice(prefix.length)
  return (
    relative.length > 0 &&
    !relative.includes('/') &&
    relative.toLowerCase().endsWith('.json')
  )
}

function credentialJsonEntries(data: Uint8Array): ParsedTarEntry[] {
  return parseTar(data, {
    filter: entry =>
      entry.type === 'file' &&
      entry.name.startsWith(CREDENTIALS_PREFIX) &&
      isTopLevelJson(entry.name, CREDENTIALS_PREFIX)
  }).sort((left, right) => left.name.localeCompare(right.name))
}

function parseCredentialEntry(entry: ParsedTarEntry): IVerifiableCredential[] {
  if (!('data' in entry) || !entry.data) {
    throw new CredentialJsonFileError(
      entry.name,
      new Error('Missing file data.')
    )
  }

  const relative = entry.name.slice(CREDENTIALS_PREFIX.length)
  const body = entry.data

  if (body.byteLength > MAX_CREDENTIAL_JSON_FILE_BYTES) {
    throw new CredentialJsonFileTooLargeError(
      relative,
      MAX_CREDENTIAL_JSON_FILE_BYTES
    )
  }

  try {
    const text = entry.text ?? new TextDecoder().decode(body)
    return credentialsFromJSON(text)
  } catch (err) {
    throw new CredentialJsonFileError(relative, err)
  }
}

export type ImportArchive = {
  hasSpace: boolean
  hasCredentials: boolean
  credentials: IVerifiableCredential[]
}

/**
 * Why an archive import is refused before anything is written, or
 * `undefined` when it may proceed.
 *
 * @param options {object}
 * @param options.archive {ImportArchive}
 * @param options.hasRemoteStorage {boolean}   Whether the session's storage
 *   has a Space the archive's Space data could land in
 * @returns {'unrecognized-archive' | 'space-needs-remote' | undefined}
 */
export function importRefusal({
  archive,
  hasRemoteStorage
}: {
  archive: ImportArchive
  hasRemoteStorage: boolean
}): 'unrecognized-archive' | 'space-needs-remote' | undefined {
  if (!archive.hasSpace && !archive.hasCredentials) {
    return 'unrecognized-archive'
  }
  if (archive.hasSpace && !hasRemoteStorage) {
    return 'space-needs-remote'
  }
  return undefined
}

/**
 * What an archive import does once its Space data, if any, has landed. A
 * parsed credential goes to the accept page; otherwise the import reports.
 * A `credentials/` directory whose entries all failed to parse is reported
 * as a credentials-only import, or noted on a Space import, so the two
 * reporting kinds always carry zero parsed credentials.
 * The archive has passed `importRefusal`, so one with no Space data carries
 * a `credentials/` directory.
 *
 * @param options {object}
 * @param options.archive {ImportArchive}
 * @param [options.spaceSummary] {ImportSpaceSummary}   The Space import's
 *   summary, when the archive carried Space data
 * @returns {object}
 */
export function importOutcome({
  archive,
  spaceSummary
}: {
  archive: ImportArchive
  spaceSummary?: ImportSpaceSummary
}):
  | {
      kind: 'accept-credentials'
      credentials: IVerifiableCredential[]
      spaceSummary?: ImportSpaceSummary
    }
  | {
      kind: 'space-imported'
      spaceSummary: ImportSpaceSummary
      hasCredentials: boolean
    }
  | { kind: 'credentials-only' } {
  const { hasCredentials, credentials } = archive
  if (credentials.length > 0) {
    return { kind: 'accept-credentials', credentials, spaceSummary }
  }
  if (spaceSummary === undefined) {
    return { kind: 'credentials-only' }
  }
  return { kind: 'space-imported', spaceSummary, hasCredentials }
}

export async function parseImportTarFile(file: File): Promise<ImportArchive> {
  const data = new Uint8Array(await file.arrayBuffer())
  const layout = parseTar(data, { metaOnly: true })
  const hasSpace = hasPathPrefix(layout, SPACE_PREFIX)
  const hasCredentials = hasPathPrefix(layout, CREDENTIALS_PREFIX)

  const credentials = hasCredentials
    ? credentialJsonEntries(data).flatMap(parseCredentialEntry)
    : []

  return { hasSpace, hasCredentials, credentials }
}
