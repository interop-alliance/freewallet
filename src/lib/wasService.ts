/**
 * The one service discovery for the configured WAS server: the unsigned read
 * of the service description at `{base}service`. Every `PwsClient` this app
 * builds takes the result through its `serviceDescription` option, so no
 * client reads the document on its own and it is fetched once per page load
 * rather than once per client.
 *
 * This module is the app's only discoverer. A `PwsClient` copies the
 * description it was constructed with, so `was.service({ refresh: true })`
 * must not be called on an app-built client: it re-reads the document from
 * the client's base server URL, which is exactly the request this module
 * exists to avoid. The discovery checks the description against the
 * configured base (`url` equal to `{base}service`, `spaces` equal to
 * `{base}spaces/`) before memoizing it, so a server that has moved its mount
 * is refused by name here, ahead of the KMS, CORS-proxy, and did:web URLs
 * derived from the configured value. A `PwsClient` runs the same check on
 * its first request.
 *
 * The discovery is memoized on success only, so entry points are the right
 * place to call it: a chain that threads the result down re-probes nothing
 * after a failure.
 */
import type {
  EncryptionProvider,
  ServiceDescription,
  ServiceInfo
} from '@interop/pws-client'
import {
  IncompatibleServerError,
  readServiceDescription,
  PwsClient
} from '@interop/pws-client'
import type { ZcapClient } from '@interop/ezcap'
import {
  serviceDescriptionUrl,
  spacesRepositoryUrl
} from '@interop/pws-client/paths'

import { WAS_BASE_SERVER_URL } from '@/app.config'
import { createLogger } from '@/lib/log'
import { isStorageUnreachable } from '@/lib/storageErrors'

const log = createLogger('fw:was:service')

let pending: Promise<ServiceInfo> | undefined

/**
 * A `PwsClient` on a storage server named by its base server URL: the
 * configured server, or the one an account's Space URL sits under. The one
 * place the app builds a `PwsClient`, so every client is built the same way
 * and carries the discovered description.
 *
 * @param options {object}
 * @param options.baseServerUrl {string}   the storage server's base server
 *   URL
 * @param options.zcapClient {ZcapClient}
 * @param [options.serviceDescription] {ServiceDescription}
 * @param [options.encryption] {EncryptionProvider}
 * @returns {PwsClient}
 */
export function pwsClientAt({
  baseServerUrl,
  zcapClient,
  serviceDescription,
  encryption
}: {
  baseServerUrl: string
  zcapClient: ZcapClient
  serviceDescription?: ServiceDescription
  encryption?: EncryptionProvider
}): PwsClient {
  return new PwsClient({
    baseServerUrl,
    zcapClient,
    serviceDescription,
    encryption
  })
}

/**
 * The configured WAS server's service description.
 *
 * @returns {Promise<ServiceDescription>}
 * @throws {Error}   as {@link wasServiceInfo}
 */
export async function wasServiceDescription(): Promise<ServiceDescription> {
  const { description } = await wasServiceInfo()
  return description
}

/**
 * What discovery learned about the configured WAS server: the service
 * description, the version entry chosen from it, and its `features` tokens
 * with `hasFeature(token)`. A caller gating on a feature token reads it here.
 *
 * @returns {Promise<ServiceInfo>}
 * @throws {Error}   when no WAS server is configured
 * @throws {IncompatibleServerError}   when the document is malformed, lists
 *   no version the client speaks, or describes a server other than the
 *   configured base (its `url` is not `{base}service`, or its Spaces
 *   Repository URL is not `{base}spaces/`)
 */
export function wasServiceInfo(): Promise<ServiceInfo> {
  if (!WAS_BASE_SERVER_URL) {
    return Promise.reject(new Error('No WAS server is configured.'))
  }
  const baseServerUrl = WAS_BASE_SERVER_URL
  if (pending === undefined) {
    const attempt: Promise<ServiceInfo> = readServiceDescription({
      serviceUrl: serviceDescriptionUrl({ baseServerUrl })
    })
      .then(info => {
        assertDescribesConfiguredServer({ info, baseServerUrl })
        const { description, version, features } = info
        log.debug('Service discovered', {
          url: description.url,
          version,
          features
        })
        return info
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
 * Refuses a service description that does not describe the server at the
 * configured base: its `url` must be `{base}service` and its Spaces
 * Repository URL, when it names one, `{base}spaces/`.
 *
 * @param options {object}
 * @param options.info {ServiceInfo}
 * @param options.baseServerUrl {string}
 * @throws {IncompatibleServerError}
 */
function assertDescribesConfiguredServer({
  info,
  baseServerUrl
}: {
  info: ServiceInfo
  baseServerUrl: string
}): void {
  const expectedUrl = serviceDescriptionUrl({ baseServerUrl })
  if (info.description.url !== expectedUrl) {
    throw new IncompatibleServerError(
      `The service description names itself "${info.description.url}", ` +
        `but the configured base server URL "${baseServerUrl}" places it ` +
        `at "${expectedUrl}".`
    )
  }
  const expectedSpaces = spacesRepositoryUrl({ baseServerUrl })
  if (info.spacesUrl !== undefined && info.spacesUrl !== expectedSpaces) {
    throw new IncompatibleServerError(
      `The service description names the Spaces Repository ` +
        `"${info.spacesUrl}", but the configured base server URL ` +
        `"${baseServerUrl}" places it at "${expectedSpaces}".`
    )
  }
}

/**
 * The configured WAS server's service description, or `undefined` when the
 * server could not be reached. The offline seam: a login entry point that
 * must keep working off this browser's cached state calls this one, so an
 * unreachable server costs it the description rather than the session,
 * exactly as an unreachable server always did. A server that answers and
 * refuses (an incompatible version) still rejects, since that is an answer
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
