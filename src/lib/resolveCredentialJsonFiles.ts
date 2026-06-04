import type { IVerifiableCredential } from '@interop/data-integrity-core'
import {
  ResolveCredentialsInputError,
  resolveCredentialsInput
} from '@/lib/resolveCredentialsInput'
import { MAX_CREDENTIAL_JSON_FILE_BYTES } from '@/app.config'

export function isJsonCredentialFile(file: File): boolean {
  if (file.name.toLowerCase().endsWith('.json')) {
    return true
  }
  const type = file.type.toLowerCase()
  return type === 'application/json' || type === ''
}

export class CredentialJsonFileTooLargeError extends Error {
  readonly fileName: string
  readonly limitBytes: number

  constructor(fileName: string, limitBytes: number) {
    super(fileName)
    this.name = 'CredentialJsonFileTooLargeError'
    this.fileName = fileName
    this.limitBytes = limitBytes
  }
}

export class CredentialJsonFileError extends Error {
  readonly fileName: string
  readonly cause: unknown

  constructor(fileName: string, cause: unknown) {
    super(fileName)
    this.name = 'CredentialJsonFileError'
    this.fileName = fileName
    this.cause = cause
  }
}

export async function resolveCredentialsFromJsonFiles(
  files: Iterable<File>
): Promise<IVerifiableCredential[]> {
  const jsonFiles = [...files].filter(isJsonCredentialFile)
  if (jsonFiles.length === 0) {
    throw new ResolveCredentialsInputError('invalid_input')
  }

  const credentials: IVerifiableCredential[] = []

  for (const file of jsonFiles) {
    if (file.size > MAX_CREDENTIAL_JSON_FILE_BYTES) {
      throw new CredentialJsonFileTooLargeError(
        file.name,
        MAX_CREDENTIAL_JSON_FILE_BYTES
      )
    }

    try {
      const text = await file.text()
      const resolved = await resolveCredentialsInput(text)
      credentials.push(...resolved)
    } catch (err) {
      if (
        err instanceof ResolveCredentialsInputError ||
        err instanceof CredentialJsonFileTooLargeError
      ) {
        throw err
      }
      throw new CredentialJsonFileError(file.name, err)
    }
  }

  if (credentials.length === 0) {
    throw new ResolveCredentialsInputError('none_found')
  }

  return credentials
}
