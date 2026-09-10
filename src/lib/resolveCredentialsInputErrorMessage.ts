import type { TFunction } from 'i18next'
import type { ResolveCredentialsInputError } from '@/lib/resolveCredentialsInput'
import { errorNameOf } from '@interop/wallet-core/menders'
import { WalletInputUnsupportedError } from '@/lib/resolveWalletInput'
import {
  CredentialJsonFileError,
  CredentialJsonFileTooLargeError
} from '@/lib/resolveCredentialJsonFiles'

export function resolveCredentialsInputErrorMessage(
  err: unknown,
  translate: TFunction,
  context?: { trimmed?: string }
): string {
  if (err instanceof WalletInputUnsupportedError) {
    return translate(
      err.code === 'connect_code'
        ? 'addCredential.errors.connectCode'
        : 'addCredential.errors.unsupportedInput'
    )
  }

  // The vc-display class is matched on `name`: a duplicated copy of the
  // package would make `instanceof` miss it.
  if (errorNameOf(err) === 'ResolveCredentialsInputError') {
    const { code } = err as ResolveCredentialsInputError
    const keys = {
      empty: 'addCredential.errors.empty',
      invalid_input: 'addCredential.errors.invalidInput',
      none_found: 'addCredential.errors.noneFound',
      vpqr_unsupported: 'addCredential.errors.vpqrUnsupported'
    } as const
    return translate(keys[code])
  }

  if (err instanceof CredentialJsonFileTooLargeError) {
    return translate('addCredential.errors.fileTooLarge', {
      fileName: err.fileName,
      limitMb: String(err.limitBytes / (1024 * 1024))
    })
  }

  if (err instanceof CredentialJsonFileError) {
    const prefix = translate('addCredential.errors.fileParse', {
      fileName: err.fileName
    })
    const msg =
      err.cause instanceof Error ? err.cause.message : String(err.cause)
    return `${prefix} ${msg}`
  }

  const trimmed = context?.trimmed?.trimStart() ?? ''
  const isUrl = trimmed.startsWith('https://') || trimmed.startsWith('http://')
  const prefix = isUrl
    ? translate('addCredential.errors.urlFetch')
    : translate('addCredential.errors.jsonParse')
  const msg = err instanceof Error ? err.message : String(err)
  return `${prefix} Error: ${msg}`
}
