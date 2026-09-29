/**
 * An in-memory WAS server behind a stub `ZcapClient`, for tests that drive a
 * real `WasClient` handle end to end: its EDV codec, a chunked write, the
 * create-if-absent `412`, and a read that reassembles chunks. Modeled on
 * was-client's own chunked-put test server.
 *
 * `PUT` stores the body under a fresh `ETag`, refusing an `If-None-Match: *`
 * create over a stored path, or an `If-Match` on a stale `ETag`, with 412.
 * `GET` serves it back (404 when absent). `DELETE` removes a resource
 * together with every chunk stored under it. `failWhen` makes a chosen
 * request fail with its `status` (default 503), to tear a write or fill the
 * Space.
 */
import { WasClient } from '@interop/was-client'
import { createEdvEncryption } from '@interop/was-client/edv'
import { TEST_SERVICE_DESCRIPTION } from '../shared/wasServiceFixture'

export const MEMORY_SERVER_URL = 'http://localhost'

/**
 * The subset of `ZcapClient.request()` arguments the server reads.
 */
export interface MemoryRequestArgs {
  url?: string
  method?: string
  json?: unknown
  body?: unknown
  headers?: Record<string, string>
}

/**
 * Builds the server.
 *
 * @returns {object}   the stored bodies by path, a client builder, and the
 *   failure hook
 */
export function memoryWasServer(): {
  store: Map<string, Uint8Array>
  client: (options: { maxBlobBytes: number; chunkSize: number }) => WasClient
  failWhen: {
    test?: (args: MemoryRequestArgs, path: string) => boolean
    status?: number
  }
  documentsOf: (options: {
    spaceId: string
    collectionId: string
  }) => Array<{ id: string; data: unknown }>
} {
  const store = new Map<string, Uint8Array>()
  const etags = new Map<string, string>()
  let version = 0
  const failWhen: {
    test?: (args: MemoryRequestArgs, path: string) => boolean
    status?: number
  } = {}
  const fail = (status: number): never => {
    throw { status, response: { status } }
  }
  const request = async (args: MemoryRequestArgs): Promise<unknown> => {
    const path = new URL(args.url!).pathname
    const method = args.method ?? 'GET'
    if (failWhen.test?.(args, path)) {
      fail(failWhen.status ?? 503)
    }
    const ifMatch = args.headers?.['if-match']
    if (ifMatch !== undefined && etags.get(path) !== ifMatch) {
      fail(412)
    }
    if (method === 'PUT') {
      if (args.headers?.['if-none-match'] === '*' && store.has(path)) {
        fail(412)
      }
      const body =
        args.body instanceof Uint8Array
          ? args.body
          : new TextEncoder().encode(JSON.stringify(args.json))
      const etag = `"${++version}"`
      store.set(path, body)
      etags.set(path, etag)
      return { status: 204, headers: new Headers({ etag }) }
    }
    if (method === 'DELETE') {
      for (const stored of [...store.keys()]) {
        if (stored === path || stored.startsWith(`${path}/chunks/`)) {
          store.delete(stored)
          etags.delete(stored)
        }
      }
      return { status: 204, headers: new Headers() }
    }
    const bytes = store.get(path)
    if (bytes === undefined) {
      return fail(404)
    }
    const text = new TextDecoder().decode(bytes)
    const isChunk = path.includes('/chunks/')
    return {
      status: 200,
      headers: new Headers({
        'content-type': isChunk
          ? 'application/octet-stream'
          : 'application/jose+json',
        etag: etags.get(path)!
      }),
      ...(!isChunk && { data: JSON.parse(text) }),
      async json() {
        return JSON.parse(text)
      },
      async text() {
        return text
      },
      async arrayBuffer() {
        return bytes.slice().buffer
      }
    }
  }
  const client = ({
    maxBlobBytes,
    chunkSize
  }: {
    maxBlobBytes: number
    chunkSize: number
  }): WasClient =>
    new WasClient({
      serverUrl: MEMORY_SERVER_URL,
      serviceDescription: TEST_SERVICE_DESCRIPTION,
      zcapClient: {
        invocationSigner: { id: 'did:example:alice#key-1' },
        request
      } as unknown as ConstructorParameters<typeof WasClient>[0]['zcapClient'],
      // The fail-closed provider a WASRemoteStore's client carries, with a
      // small blob limit so a test payload takes the chunked path.
      encryption: createEdvEncryption({
        resolveKeys: async () => null,
        maxBlobBytes,
        chunkSize
      })
    })
  const documentsOf = ({
    spaceId,
    collectionId
  }: {
    spaceId: string
    collectionId: string
  }): Array<{ id: string; data: unknown }> => {
    const prefix = `/space/${spaceId}/${collectionId}/`
    return [...store]
      .filter(([path]) => path.startsWith(prefix) && !path.includes('/chunks/'))
      .map(([path, bytes]) => ({
        id: path.slice(prefix.length),
        data: JSON.parse(new TextDecoder().decode(bytes))
      }))
  }
  return { store, client, failWhen, documentsOf }
}
