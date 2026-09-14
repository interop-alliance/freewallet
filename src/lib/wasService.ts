/**
 * The one service discovery for the configured WAS server: the `HEAD` of the
 * Spaces Repository URL for its `rel="service"` link, then the unsigned read
 * of the linked document. Every `WasClient` this app builds takes the result
 * through its `serviceDescription` option, so no client discovers on its own
 * (each would `HEAD` the base URL, which the server need not answer) and the
 * document is fetched once per page load rather than once per client.
 *
 * This module is the app's only discoverer. A `WasClient` copies the
 * description it was constructed with, so `was.service({ refresh: true })`
 * must not be called on an app-built client: it re-discovers from the base
 * URL, which is exactly the request this module exists to avoid.
 *
 * The discovery is memoized on success only, so entry points are the right
 * place to call it: a chain that threads the result down re-probes nothing
 * after a failure.
 */
import type { ServiceDescription } from '@interop/was-client'
import { discoverService, IncompatibleServerError } from '@interop/was-client'

import { WAS_SPACES_URL, withOneTrailingSlash } from '@/app.config'
import { createLogger } from '@/lib/log'
import { isStorageUnreachable } from '@/lib/storageErrors'

const log = createLogger('fw:was:service')

let pending: Promise<ServiceDescription> | undefined

/**
 * The configured WAS server's service description.
 *
 * @returns {Promise<ServiceDescription>}
 * @throws {Error}   when no WAS server is configured
 * @throws {IncompatibleServerError}   when the server's responses carry no
 *   `service` link, the document is malformed, it lists no version the
 *   client speaks, or the version entry advertises a Spaces Repository URL
 *   other than the configured `VITE_WAS_SERVER_URL` (a server that has moved
 *   its mount is refused by name rather than silently misrouting the KMS,
 *   CORS-proxy, and account-pointer URLs derived from the configured value)
 */
export function wasServiceDescription(): Promise<ServiceDescription> {
  if (!WAS_SPACES_URL) {
    return Promise.reject(new Error('No WAS server is configured.'))
  }
  const configuredSpacesUrl = WAS_SPACES_URL
  if (pending === undefined) {
    const attempt: Promise<ServiceDescription> = discoverService({
      url: configuredSpacesUrl
    })
      .then(({ description, version, features, spacesUrl }) => {
        if (
          spacesUrl !== undefined &&
          withOneTrailingSlash(spacesUrl) !== configuredSpacesUrl
        ) {
          throw new IncompatibleServerError(
            `The server advertises its Spaces Repository at "${spacesUrl}", ` +
              'but VITE_WAS_SERVER_URL is configured as ' +
              `"${configuredSpacesUrl}". Every URL this app derives from ` +
              'the configured value (the KMS facet, the CORS-proxy facet, ' +
              'and the host an account pointer records) would address the ' +
              'wrong mount, so the configured value must be corrected.',
            { requestUrl: configuredSpacesUrl }
          )
        }
        log.debug('Service discovered', {
          url: description.url,
          version,
          features
        })
        return description
      })
      .catch(err => {
        pending = undefined
        throw err
      })
    pending = attempt
  }
  return pending
}

/**
 * The configured WAS server's service description, or `undefined` when the
 * server could not be reached. The offline seam: a login entry point that
 * must keep working off this browser's cached state calls this one, so an
 * unreachable server costs it the description rather than the session,
 * exactly as an unreachable server always did. A server that answers and
 * refuses -- an incompatible version, an advertised Spaces Repository URL
 * other than the configured one -- still rejects, since that is an answer
 * about the server rather than a missing one.
 *
 * @returns {Promise<ServiceDescription | undefined>}
 * @throws {IncompatibleServerError}   on a non-transport discovery refusal
 */
export async function wasServiceDescriptionIfReachable(): Promise<
  ServiceDescription | undefined
> {
  try {
    return await wasServiceDescription()
  } catch (err) {
    if (!isStorageUnreachable(err)) {
      throw err
    }
    log.warn('The WAS server could not be reached for service discovery', {
      err
    })
    return undefined
  }
}
