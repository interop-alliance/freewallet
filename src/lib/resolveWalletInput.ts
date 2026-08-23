/**
 * The one door every piece of free-form text enters the wallet through: the
 * Add Credential paste box and the QR scanner. The ordered discrimination
 * itself is shared (`classifyWalletInput` / `handleWalletInput` in
 * `@interop/wallet-core/request`), so a grammar one wallet routes is not a
 * grammar the other silently mis-handles -- a connect code read as a
 * credential URL, say.
 *
 * Freewallet implements three of the classified kinds here. `credentials` is
 * the fallback branch and resolves through the CORS-proxied credential
 * resolver as before. `interaction-url` is a request arriving from outside
 * the app (a CLI agent's printed link, a scanned `...?iuv=1` QR): it is not
 * resolved here but handed back as a typed outcome, so the caller routes to
 * the request page (`src/pages/external/ExternalRequestPage.tsx`) -- the
 * deep link the CLI prints lands on the same page, so both entry points
 * share one handler. `connect-code` is recognized rather than resolved: a
 * wallet connect code is consumed by the enrollment ceremony on the Settings
 * and login screens, so the honest answer to one pasted into the credential
 * box is to say where it belongs instead of failing it as malformed JSON.
 * Every other kind is refused by the shared dispatcher and surfaces as the
 * unsupported message.
 *
 * Only the `interaction:` scheme and an http(s) URL carrying `iuv` classify
 * as an interaction URL. A bare exchange URL carries neither and falls to the
 * credential branch, where the fetch fails with the URL-fetch message; the
 * CLI prints the `?iuv=1` form.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { handleWalletInput } from '@interop/wallet-core/request'
import { resolveCredentialsInput } from '@/lib/resolveCredentialsInput'

/**
 * What a piece of free-form input resolved to: credentials to import, or an
 * interaction URL for the request page to open. A handler whose effect is a
 * navigation has no credentials to return, and an empty array would read to
 * the callers as "no credentials found", so the two are kept apart by type.
 */
export type WalletInputOutcome =
  | { kind: 'credentials'; credentials: IVerifiableCredential[] }
  | { kind: 'interaction-url'; url: string }

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
 * Classifies free-form input and resolves it: the credentials it carries, or
 * the interaction URL it is.
 *
 * @param text {string}   the pasted or scanned text
 * @returns {Promise<WalletInputOutcome>}
 */
export async function resolveWalletInput(
  text: string
): Promise<WalletInputOutcome> {
  try {
    return await handleWalletInput<WalletInputOutcome>({
      text,
      handlers: {
        credentials: async ({ text: raw }) => ({
          kind: 'credentials',
          credentials: await resolveCredentialsInput(raw)
        }),
        interactionUrl: ({ text: url }) => ({ kind: 'interaction-url', url }),
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
