// @vitest-environment node
/**
 * Unit tests for the non-CHAPI request entry point's pure half
 * (`src/lib/walletRequest/externalRequest.ts`): the deep-link parser, the
 * exchange-opening error mapping, and the pre-consent refusal matrix (DID
 * Auth, `domain`, `AppConnectQuery`, a foreign delivery endpoint, the grant
 * class allowlist, a plain URL on an encrypted collection the agent cannot
 * read).
 */
import { describe, expect, it, vi } from 'vitest'
import { EphemeralExchangeGoneError } from '@interop/wallet-request'
import { x25519RecipientFromDidKey } from '@interop/was-client/edv'
import {
  barredGrants,
  EXTERNAL_REQUEST_ORIGIN,
  ExternalRequestRefusedError,
  externalRequestPath,
  interactionUrlFromSearch,
  namesExistingCollectionByUrl,
  openExternalRequest,
  precheckExternalRequest,
  unreadableGrants
} from './externalRequest'
import {
  existingCollectionsFrom,
  resolveGrants,
  type ExistingCollections,
  type ResolvedGrant
} from './processZcaps'
import type { IVPRDetails } from './types'

const INTERACTION_URL =
  'https://was.example/workflows/ephemeral/exchanges/abc/protocols?iuv=1'
const EXCHANGE_URL = 'https://was.example/workflows/ephemeral/exchanges/abc'

const ZCAP_QUERY = {
  type: 'AuthorizationCapabilityQuery',
  capabilityQuery: [
    {
      referenceId: 'web',
      reason: 'publish a page',
      allowedAction: ['GET', 'PUT'],
      controller: 'did:key:z6MkAgent',
      invocationTarget: {
        type: 'https://w3id.org/byoe#public-collection',
        name: 'web'
      }
    }
  ]
}

function zcapOnlyRequest(extra: Partial<IVPRDetails> = {}): IVPRDetails {
  return { query: [ZCAP_QUERY], ...extra } as unknown as IVPRDetails
}

function refusalOf(run: () => unknown): string | undefined {
  try {
    run()
    return undefined
  } catch (err) {
    return err instanceof ExternalRequestRefusedError ? err.refusal : 'other'
  }
}

describe('externalRequestPath', () => {
  it('builds the deep link the CLI prints, with the URL percent-encoded', () => {
    const path = externalRequestPath({ url: INTERACTION_URL })
    expect(path.startsWith('/external/request?url=')).toBe(true)
    expect(interactionUrlFromSearch(path.slice(path.indexOf('?')))).toBe(
      INTERACTION_URL
    )
  })
})

describe('interactionUrlFromSearch', () => {
  it('accepts an http(s) interaction URL and the interaction: scheme', () => {
    expect(
      interactionUrlFromSearch(`?url=${encodeURIComponent(INTERACTION_URL)}`)
    ).toBe(INTERACTION_URL)
    const schemed = `interaction:${INTERACTION_URL}`
    expect(
      interactionUrlFromSearch(`?url=${encodeURIComponent(schemed)}`)
    ).toBe(schemed)
  })

  it('refuses a missing parameter, a bare exchange URL, and other schemes', () => {
    expect(interactionUrlFromSearch('')).toBeNull()
    expect(interactionUrlFromSearch('?url=')).toBeNull()
    expect(
      interactionUrlFromSearch(`?url=${encodeURIComponent(EXCHANGE_URL)}`)
    ).toBeNull()
    expect(
      interactionUrlFromSearch(
        `?url=${encodeURIComponent('ftp://was.example/x?iuv=1')}`
      )
    ).toBeNull()
    expect(
      interactionUrlFromSearch(
        `?url=${encodeURIComponent('javascript:alert(1)?iuv=1')}`
      )
    ).toBeNull()
    expect(interactionUrlFromSearch('?url=%2Frelative%3Fiuv%3D1')).toBeNull()
  })
})

describe('openExternalRequest', () => {
  it('opens the exchange behind the interaction URL', async () => {
    const fetch = vi.fn(async (url: string, init?: { method?: string }) => {
      if (url === INTERACTION_URL) {
        return new Response(
          JSON.stringify({ protocols: { vcapi: EXCHANGE_URL } })
        )
      }
      expect(url).toBe(EXCHANGE_URL)
      expect(init?.method).toBe('POST')
      return new Response(
        JSON.stringify({ verifiablePresentationRequest: zcapOnlyRequest() })
      )
    })
    const opened = await openExternalRequest({
      url: INTERACTION_URL,
      fetch: fetch as unknown as typeof globalThis.fetch
    })
    expect(opened.exchangeUrl).toBe(EXCHANGE_URL)
    expect(opened.request.query).toEqual([ZCAP_QUERY])
  })

  it('maps a 404 on the protocols fetch to the gone refusal', async () => {
    const fetch = vi.fn(async () => new Response('', { status: 404 }))
    const thrown = await openExternalRequest({
      url: INTERACTION_URL,
      fetch: fetch as unknown as typeof globalThis.fetch
    }).catch((err: unknown) => err)
    expect(thrown).toBeInstanceOf(ExternalRequestRefusedError)
    expect((thrown as ExternalRequestRefusedError).refusal).toBe('gone')
    expect((thrown as Error).cause).toBeInstanceOf(EphemeralExchangeGoneError)
  })

  it('maps a network failure to unreachable and a bad body to malformed', async () => {
    const down = vi.fn(async () => {
      throw new TypeError('fetch failed')
    })
    await expect(
      openExternalRequest({
        url: INTERACTION_URL,
        fetch: down as unknown as typeof globalThis.fetch
      })
    ).rejects.toMatchObject({ refusal: 'unreachable' })

    const noProtocols = vi.fn(async () => new Response(JSON.stringify({})))
    await expect(
      openExternalRequest({
        url: INTERACTION_URL,
        fetch: noProtocols as unknown as typeof globalThis.fetch
      })
    ).rejects.toMatchObject({ refusal: 'malformedRequest' })
  })

  it('refuses a URL that is not an interaction URL as malformed', async () => {
    await expect(
      openExternalRequest({ url: EXCHANGE_URL })
    ).rejects.toMatchObject({ refusal: 'malformedRequest' })
  })
})

describe('precheckExternalRequest', () => {
  it('passes a zcap-only request through, naming the exchange host for delivery', () => {
    const { profile, deliveryHost } = precheckExternalRequest({
      request: zcapOnlyRequest(),
      exchangeUrl: EXCHANGE_URL
    })
    expect(profile.didAuth).toBe(false)
    expect(profile.appConnect).toBeNull()
    expect(profile.zcapRequests).toHaveLength(1)
    expect(deliveryHost).toBe('was.example')
  })

  it('surfaces the self-declared agent name on the profile', () => {
    const { profile } = precheckExternalRequest({
      request: zcapOnlyRequest({ agent: { name: ' research-bot ' } }),
      exchangeUrl: EXCHANGE_URL
    })
    expect(profile.agent).toEqual({ name: 'research-bot' })
  })

  it('refuses an agent name outside the limits as malformed', () => {
    expect(
      refusalOf(() =>
        precheckExternalRequest({
          request: zcapOnlyRequest({ agent: { name: 'bad\nname' } }),
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('malformedRequest')
  })

  it('refuses an empty query set as malformed', () => {
    expect(
      refusalOf(() =>
        precheckExternalRequest({
          request: { query: [] } as unknown as IVPRDetails,
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('malformedRequest')
  })

  it('refuses an AppConnectQuery with its own reason, ahead of classification', () => {
    const request = {
      query: [
        { type: 'DIDAuthentication' },
        {
          type: 'AppConnectQuery',
          app: { name: 'Editor', appUrl: 'https://app.example/' },
          capabilityQuery: []
        }
      ]
    } as unknown as IVPRDetails
    expect(
      refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('appConnect')
  })

  it('refuses DID Authentication in either spelling', () => {
    const withDomain = {
      query: [{ type: 'DIDAuthentication' }, ZCAP_QUERY],
      challenge: 'abc',
      domain: 'verifier.example'
    } as unknown as IVPRDetails
    const withoutDomain = {
      query: [{ type: 'DIDAuthentication' }, ZCAP_QUERY],
      challenge: 'abc'
    } as unknown as IVPRDetails
    for (const request of [withDomain, withoutDomain]) {
      expect(
        refusalOf(() =>
          precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
        )
      ).toBe('didAuth')
    }
  })

  it('refuses a request with no capability query as nothing requested', () => {
    const request = {
      query: [{ type: 'QueryByExample', credentialQuery: [{ example: {} }] }]
    } as unknown as IVPRDetails
    expect(
      refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('nothingRequested')
  })

  it('maps a null reply body to malformed, not unreachable', async () => {
    const nullBody = vi.fn(async () => new Response('null'))
    await expect(
      openExternalRequest({
        url: INTERACTION_URL,
        fetch: nullBody as unknown as typeof globalThis.fetch
      })
    ).rejects.toMatchObject({ refusal: 'malformedRequest' })
  })

  it('refuses capability queries naming more than one grantee controller', () => {
    const second = {
      ...ZCAP_QUERY.capabilityQuery[0],
      referenceId: 'notes',
      controller: 'did:key:z6MkOtherAgent'
    }
    const request = {
      query: [
        { ...ZCAP_QUERY, capabilityQuery: [ZCAP_QUERY.capabilityQuery[0]] },
        { ...ZCAP_QUERY, capabilityQuery: [second] }
      ]
    } as unknown as IVPRDetails
    expect(
      refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('multipleGrantees')
  })

  it('accepts several capability queries naming the same controller', () => {
    const second = { ...ZCAP_QUERY.capabilityQuery[0], referenceId: 'notes' }
    const request = {
      query: [
        {
          ...ZCAP_QUERY,
          capabilityQuery: [ZCAP_QUERY.capabilityQuery[0], second]
        }
      ]
    } as unknown as IVPRDetails
    expect(
      precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL }).profile
        .zcapRequests
    ).toHaveLength(2)
  })

  it('refuses a domain on any request', () => {
    expect(
      refusalOf(() =>
        precheckExternalRequest({
          request: zcapOnlyRequest({ domain: 'verifier.example' }),
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('domain')
  })

  it('refuses a presentation endpoint on another origin, allows a same-origin one', () => {
    const foreign = zcapOnlyRequest({
      interact: {
        service: [
          {
            type: 'UnmediatedHttpPresentationService2021',
            serviceEndpoint: 'https://attacker.example/collect'
          }
        ]
      }
    } as Partial<IVPRDetails>)
    expect(
      refusalOf(() =>
        precheckExternalRequest({ request: foreign, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('foreignDelivery')

    const sameOrigin = zcapOnlyRequest({
      interact: {
        service: [
          {
            type: 'UnmediatedHttpPresentationService2021',
            serviceEndpoint: 'https://was.example/other/endpoint'
          }
        ]
      }
    } as Partial<IVPRDetails>)
    expect(
      precheckExternalRequest({
        request: sameOrigin,
        exchangeUrl: EXCHANGE_URL
      }).deliveryHost
    ).toBe('was.example')
  })
})

describe('barredGrants', () => {
  // An absent `targetClass` is what makes a target unsatisfiable.
  function grant(targetClass: string | undefined): ResolvedGrant {
    return {
      descriptor: { referenceId: targetClass ?? 'none' },
      target: { targetClass },
      allowedActions: ['GET'],
      write: false
    } as unknown as ResolvedGrant
  }

  it('lets public and private collection grants through', () => {
    expect(
      barredGrants([grant('public-collection'), grant('collection')])
    ).toEqual([])
  })

  it('bars shares and protected-collection targets', () => {
    const barred = barredGrants([
      grant('public-collection'),
      grant('share'),
      grant('protected-collection')
    ])
    expect(barred.map(({ target }) => target.targetClass)).toEqual([
      'share',
      'protected-collection'
    ])
  })

  it('ignores unsatisfiable grants, which delegate nothing', () => {
    expect(barredGrants([grant(undefined)])).toEqual([])
  })
})

describe('unreadableGrants', () => {
  const SPACE = { serverUrl: 'https://was.example/', spaceId: 'abc' }
  const AGENT = 'did:key:z6MkqojacRDqmQgDi4ESKKhGDqnZx4C6cChAbQZXvnUFX7D7'
  const AGENT_KID = x25519RecipientFromDidKey({ did: AGENT }).id!
  const NOTES_URL = `${SPACE.serverUrl}space/${SPACE.spaceId}/notes/`

  /**
   * Resolves one agent grant against a Space snapshot, as the page does
   * after the attribution pass has read it in.
   *
   * @param options {object}
   * @param options.invocationTarget {ResolvedGrant['descriptor']['invocationTarget']}
   * @param options.collections {ExistingCollections}
   * @returns {ResolvedGrant[]}
   */
  function resolve({
    invocationTarget,
    collections
  }: {
    invocationTarget: ResolvedGrant['descriptor']['invocationTarget']
    collections: ExistingCollections
  }): ResolvedGrant[] {
    return resolveGrants({
      zcapRequests: [
        {
          referenceId: 'notes',
          allowedAction: ['GET'],
          invocationTarget,
          controller: AGENT
        }
      ],
      space: SPACE,
      collections
    })
  }

  it('refuses a URL on an encrypted collection whose key epoch omits the agent', () => {
    const grants = resolve({
      invocationTarget: NOTES_URL,
      collections: existingCollectionsFrom([
        { id: 'notes', encrypted: true, recipientIds: new Set(['#other']) }
      ])
    })
    expect(barredGrants(grants)).toEqual([])
    expect(unreadableGrants(grants)).toHaveLength(1)
  })

  it('refuses a Resource URL inside such a collection', () => {
    const grants = resolve({
      invocationTarget: `${NOTES_URL}note-1`,
      collections: existingCollectionsFrom([
        { id: 'notes', encrypted: true, recipientIds: new Set() }
      ])
    })
    expect(unreadableGrants(grants)).toHaveLength(1)
  })

  it('lets a URL through when the key epoch already lists the agent', () => {
    const grants = resolve({
      invocationTarget: NOTES_URL,
      collections: existingCollectionsFrom([
        { id: 'notes', encrypted: true, recipientIds: new Set([AGENT_KID]) }
      ])
    })
    expect(unreadableGrants(grants)).toEqual([])
  })

  it('lets a URL through when the key epoch could not be read', () => {
    // An unread epoch is no evidence the agent is absent; the grant keeps
    // the ciphertext note, as on the popup.
    const grants = resolve({
      invocationTarget: NOTES_URL,
      collections: existingCollectionsFrom([{ id: 'notes', encrypted: true }])
    })
    expect(grants[0]!.target.encrypted).toBe(true)
    expect(unreadableGrants(grants)).toEqual([])
  })

  it('lets a URL on a plaintext or public collection through', () => {
    for (const entry of [
      { id: 'notes', encrypted: false, recipientIds: new Set<string>() },
      { id: 'notes', isPublic: true }
    ]) {
      const grants = resolve({
        invocationTarget: NOTES_URL,
        collections: existingCollectionsFrom([entry])
      })
      expect(unreadableGrants(grants)).toEqual([])
    }
  })

  it('lets a private-collection descriptor on a standard encrypted collection through', () => {
    const grants = resolve({
      invocationTarget: {
        type: 'https://w3id.org/byoe#private-collection',
        name: 'private-credentials'
      },
      collections: existingCollectionsFrom([
        { id: 'private-credentials', recipientIds: new Set() }
      ])
    })
    // Only a URL target is refused here. This one is a protected collection,
    // which the allowlist bars on its own.
    expect(grants[0]!.target.encrypted).toBe(true)
    expect(unreadableGrants(grants)).toEqual([])
  })

  it('waits for the key epochs only for a URL naming an existing collection', () => {
    const collections = existingCollectionsFrom([{ id: 'notes' }])
    expect(
      namesExistingCollectionByUrl({
        grants: resolve({ invocationTarget: NOTES_URL, collections }),
        collections
      })
    ).toBe(true)
    expect(
      namesExistingCollectionByUrl({
        grants: resolve({
          invocationTarget: {
            type: 'https://w3id.org/byoe#private-collection',
            name: 'notes'
          },
          collections
        }),
        collections
      })
    ).toBe(false)
    // A URL naming no existing collection is unsatisfiable and names none.
    const empty = existingCollectionsFrom([])
    expect(
      namesExistingCollectionByUrl({
        grants: resolve({ invocationTarget: NOTES_URL, collections: empty }),
        collections: empty
      })
    ).toBe(false)
  })
})

describe('EXTERNAL_REQUEST_ORIGIN', () => {
  it('is the fixed marker the Grant activity records', () => {
    expect(EXTERNAL_REQUEST_ORIGIN).toBe('n/a (API request)')
  })
})
