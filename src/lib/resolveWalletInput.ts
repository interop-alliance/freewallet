/**
 * The one door every piece of free-form text enters the wallet through: the
 * Add Credential paste box and the QR scanner. The ordered discrimination
 * itself is shared (`classifyWalletInput` / `handleWalletInput` in
 * `@interop/wallet-core/request`), so a grammar one wallet routes is not a
 * grammar the other silently mis-handles -- a connect code read as a
 * credential URL, say.
 *
 * Freewallet implements two of the classified kinds here. `credentials` is the
 * fallback branch and resolves through the CORS-proxied credential resolver as
 * before. `connect-code` is recognized rather than resolved: a wallet connect
 * code is consumed by the enrollment ceremony on the Settings and login
 * screens, so the honest answer to one pasted into the credential box is to
 * say where it belongs instead of failing it as malformed JSON. Every other
 * kind is refused by the shared dispatcher and surfaces as the unsupported
 * message.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { handleWalletInput } from '@interop/wallet-core/request'
import { resolveCredentialsInput } from '@/lib/resolveCredentialsInput'

/**
 * Text that classified as a grammar the credential entry points do not
 * consume. `code` selects the message; `kind` is the classified kind, for
 * logging.
 */
export class WalletInputUnsupportedError extends Error {
  code: 'connect_code' | 'unsupported'
  kind: string

  constructor({
    code,
    kind
  }: {
    code: 'connect_code' | 'unsupported'
    kind: string
  }) {
    super(`Wallet input of kind "${kind}" is not accepted here.`)
    this.name = 'WalletInputUnsupportedError'
    this.code = code
    this.kind = kind
  }
}

/**
 * Classifies free-form input and resolves the credentials it carries.
 *
 * @param text {string}   the pasted or scanned text
 * @returns {Promise<IVerifiableCredential[]>}
 */
export async function resolveWalletInput(
  text: string
): Promise<IVerifiableCredential[]> {
  try {
    return await handleWalletInput<IVerifiableCredential[]>({
      text,
      handlers: {
        credentials: ({ text: raw }) => resolveCredentialsInput(raw),
        connectCode: () => {
          throw new WalletInputUnsupportedError({
            code: 'connect_code',
            kind: 'connect-code'
          })
        }
      }
    })
  } catch (err) {
    if (err instanceof WalletInputUnsupportedError) {
      throw err
    }
    // The shared dispatcher refuses a kind with no handler; everything else is
    // the resolver's own coded error and passes through untouched.
    if (
      err instanceof Error &&
      err.message.startsWith('Unhandled wallet input of kind')
    ) {
      throw new WalletInputUnsupportedError({
        code: 'unsupported',
        kind: err.message
      })
    }
    throw err
  }
}
