/**
 * Reads wallet import tarballs and extracts credentials from credentials/*.json.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { parseTar } from 'nanotar'
import { MAX_CREDENTIAL_JSON_FILE_BYTES } from '@/app.config'
import { credentialsFromJSON } from '@/lib/credentialsFromJSON'
import {
  CredentialJsonFileError,
  CredentialJsonFileTooLargeError
} from '@/lib/resolveCredentialJsonFiles'

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
  }).sort((a, b) => a.name.localeCompare(b.name))
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

export async function parseImportTarFile(file: File): Promise<{
  hasSpace: boolean
  hasCredentials: boolean
  credentials: IVerifiableCredential[]
}> {
  const data = new Uint8Array(await file.arrayBuffer())
  const layout = parseTar(data, { metaOnly: true })
  const hasSpace = hasPathPrefix(layout, SPACE_PREFIX)
  const hasCredentials = hasPathPrefix(layout, CREDENTIALS_PREFIX)

  const credentials = hasCredentials
    ? credentialJsonEntries(data).flatMap(parseCredentialEntry)
    : []

  return { hasSpace, hasCredentials, credentials }
}
