/**
 * Where a Space sits, read off its URL: the base server URL it is served
 * under and its Space id. The server layout fixes a Space at
 * `{base}space/{spaceId}/`, so both are the URL's own segments, and an
 * account pointer (`{ did?, spaceUrl }`) stores neither a host nor a base.
 * Every wallet-core call that takes `baseServerUrl` and `spaceId` reads them
 * through this one helper, over was-client's path rules.
 */
import { baseServerUrlOf, spaceIdOfUrl } from '@interop/was-client/paths'

/**
 * The base server URL and Space id of a Space URL.
 *
 * @param options {object}
 * @param options.spaceUrl {string}   a Space URL (`{base}space/{spaceId}/`)
 * @returns {{ baseServerUrl: string, spaceId: string }}
 * @throws {ValidationError}   was-client's, when `spaceUrl` is not a Space
 *   URL under a base server URL
 */
export function spaceLocation({ spaceUrl }: { spaceUrl: string }): {
  baseServerUrl: string
  spaceId: string
} {
  return {
    baseServerUrl: baseServerUrlOf(spaceUrl),
    spaceId: spaceIdOfUrl(spaceUrl)
  }
}
