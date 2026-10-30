/**
 * An in-memory WAS server behind a stub `ZcapClient`, for tests that drive a
 * real `WasClient` handle end to end: its EDV codec, a chunked write, the
 * create-if-absent `412`, and a read that reassembles chunks. Modeled on
 * was-client's own chunked-put test server.
 *
 * `PUT` stores the body under a fresh `ETag`, refusing an `If-None-Match: *`
 * create over a stored path, or an `If-Match` on a stale `ETag`, with 412.
 * `GET` serves it back (404 when absent). `DELETE` removes a resource
 * together with every chunk stored under it. A `POST` of the `changes`
 * profile to a collection's `query` path serves the collection's documents
 * feed in one page, each document with its `ETag`. `failWhen` makes a chosen
 * request fail with its `status` (default 503), to tear a write or fill the
 * Space. Every request is recorded in `requests`, with the capability it
 * invoked under.
 */
import {
  WasClient,
  type ChangesPage,
  type ResourceChangeDocument
} from '@interop/was-client'
import { createEdvEncryption } from '@interop/was-client/edv'
import { TEST_SERVICE_DESCRIPTION } from '../shared/wasServiceFixture'

export const MEMORY_SERVER_URL = 'http://localhost/'

/**
 * The subset of `ZcapClient.request()` arguments the server reads.
 */
export interface MemoryRequestArgs {
  url?: string
  method?: string
  json?: unknown
  body?: unknown
  headers?: Record<string, string>
  capability?: unknown
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
  requests: MemoryRequestArgs[]
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
  const requests: MemoryRequestArgs[] = []
  const request = async (args: MemoryRequestArgs): Promise<unknown> => {
    requests.push(args)
    const path = new URL(args.url!).pathname
    const method = args.method ?? 'GET'
    if (failWhen.test?.(args, path)) {
      fail(failWhen.status ?? 503)
    }
    if (
      method === 'POST' &&
      path.endsWith('/query') &&
      (args.json as { profile?: unknown } | undefined)?.profile === 'changes'
    ) {
      const prefix = path.slice(0, -'query'.length)
      const documents: ResourceChangeDocument[] = [...store]
        .filter(
          ([stored]) =>
            stored.startsWith(prefix) &&
            !stored.slice(prefix.length).includes('/')
        )
        .map(([stored, bytes], position) => ({
          kind: 'resource',
          id: stored.slice(prefix.length),
          // The type `GET` serves the same Resource under.
          contentType: 'application/jose+json',
          deleted: false,
          updatedAt: '2026-10-01T00:00:00.000Z',
          updatedAtCounter: 0,
          originId: 'memory',
          checkpoint: String(position + 1),
          etag: etags.get(stored),
          data: JSON.parse(new TextDecoder().decode(bytes))
        }))
      const page: ChangesPage = { documents, checkpoint: null }
      return {
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        data: page,
        async json() {
          return page
        }
      }
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
      baseServerUrl: MEMORY_SERVER_URL,
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
  return { store, client, failWhen, documentsOf, requests }
}
