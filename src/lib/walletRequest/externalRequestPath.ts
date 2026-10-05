/**
 * The interaction-URL deep-link contract: the in-app route the CLI prints
 * (`--wallet <url>`), the query parameter carrying the percent-encoded
 * interaction URL, and the builder that joins them. Both names are published
 * conventions once a skill ships them. Side-effect free and dependency free,
 * so a Playwright spec can import it without pulling in the logging wiring.
 */

export const EXTERNAL_REQUEST_PATH = '/external/request'
export const EXTERNAL_REQUEST_URL_PARAM = 'url'

/**
 * The in-app path for an interaction URL: the deep link the CLI prints, and
 * where the paste box and the QR scanner send one.
 *
 * @param options {object}
 * @param options.url {string}   the interaction URL
 * @returns {string}
 */
export function externalRequestPath({ url }: { url: string }): string {
  const params = new URLSearchParams({ [EXTERNAL_REQUEST_URL_PARAM]: url })
  return `${EXTERNAL_REQUEST_PATH}?${params.toString()}`
}
