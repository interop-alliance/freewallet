// @vitest-environment node
/**
 * Unit tests for the non-CHAPI request entry point's pure half
 * (`src/lib/walletRequest/externalRequest.ts`): the deep-link parser, the
 * exchange-opening error mapping, and the pre-consent refusal matrix (DID
 * Auth, `domain`, `AppConnectQuery`, a foreign delivery endpoint, the grant
 * class allowlist, a plain URL on an encrypted collection the agent cannot
 * read, a grantee that is one of the account's wallet clients), and the
 * connection request's own refusals (its proof, its root `challenge`, its
 * target forms and actions, the inbox it needs, and the server's `created-by`
 * feature).
 */
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent } from '@interop/capability-agent'
import {
  composeCapabilityRequest,
  EphemeralExchangeGoneError,
  signCapabilityRequest
} from '@interop/wallet-request'
import { x25519RecipientFromDidKey } from '@interop/pws-client/edv'
import {
  barredGrants,
  EXTERNAL_REQUEST_ORIGIN,
  ExternalRequestRefusedError,
  interactionUrlFromSearch,
  namesExistingCollectionByUrl,
  openExternalRequest,
  precheckExternalRequest,
  refuseEnrolledClientController,
  refuseUnattributedServer,
  refuseUntrustedInbox,
  unreadableGrants
} from './externalRequest'
import { INBOX_DESCRIPTOR_TYPE } from './connectionRequest'
import { externalRequestPath } from './externalRequestPath'
import {
  existingCollectionsFrom,
  resolveGrants,
  type ExistingCollections,
  type ResolvedGrant
} from './processZcaps'
import type { IVPRDetails, WalletRequestProfile } from './types'

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

async function refusalOf(run: () => unknown): Promise<string | undefined> {
  try {
    await run()
    return undefined
  } catch (err) {
    return err instanceof ExternalRequestRefusedError ? err.refusal : 'other'
  }
}

describe('externalRequestPath', () => {
  it('builds the deep link the CLI prints, with the URL percent-encoded', async () => {
    const path = externalRequestPath({ url: INTERACTION_URL })
    expect(path.startsWith('/external/request?url=')).toBe(true)
    expect(interactionUrlFromSearch(path.slice(path.indexOf('?')))).toBe(
      INTERACTION_URL
    )
  })
})

describe('interactionUrlFromSearch', () => {
  it('accepts an http(s) interaction URL and the interaction: scheme', async () => {
    expect(
      interactionUrlFromSearch(`?url=${encodeURIComponent(INTERACTION_URL)}`)
    ).toBe(INTERACTION_URL)
    const schemed = `interaction:${INTERACTION_URL}`
    expect(
      interactionUrlFromSearch(`?url=${encodeURIComponent(schemed)}`)
    ).toBe(schemed)
  })

  it('refuses a missing parameter, a bare exchange URL, and other schemes', async () => {
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
  it('passes a zcap-only request through, naming the exchange host for delivery', async () => {
    const { profile, deliveryHost } = await precheckExternalRequest({
      request: zcapOnlyRequest(),
      exchangeUrl: EXCHANGE_URL
    })
    expect(profile.didAuth).toBe(false)
    expect(profile.appConnect).toBeNull()
    expect(profile.zcapRequests).toHaveLength(1)
    expect(deliveryHost).toBe('was.example')
  })

  it('surfaces the self-declared agent name on the profile', async () => {
    const { profile } = await precheckExternalRequest({
      request: zcapOnlyRequest({ agent: { name: ' research-bot ' } }),
      exchangeUrl: EXCHANGE_URL
    })
    expect(profile.agent).toEqual({ name: 'research-bot' })
  })

  it('refuses an agent name outside the limits as malformed', async () => {
    expect(
      await refusalOf(() =>
        precheckExternalRequest({
          request: zcapOnlyRequest({ agent: { name: 'bad\nname' } }),
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('malformedRequest')
  })

  it('refuses an empty query set as malformed', async () => {
    expect(
      await refusalOf(() =>
        precheckExternalRequest({
          request: { query: [] } as unknown as IVPRDetails,
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('malformedRequest')
  })

  it('refuses an AppConnectQuery with its own reason, ahead of classification', async () => {
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
      await refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('appConnect')
  })

  it('refuses DID Authentication in either spelling', async () => {
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
        await refusalOf(() =>
          precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
        )
      ).toBe('didAuth')
    }
  })

  it('refuses a request with no capability query as nothing requested', async () => {
    const request = {
      query: [{ type: 'QueryByExample', credentialQuery: [{ example: {} }] }]
    } as unknown as IVPRDetails
    expect(
      await refusalOf(() =>
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

  it('refuses capability queries naming more than one grantee controller', async () => {
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
      await refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('multipleGrantees')
  })

  it('refuses a grantee controller that is a verification method id', async () => {
    const vmController = {
      referenceId: 'notes',
      reason: 'read notes',
      allowedAction: ['GET'],
      controller: 'did:key:z6MkAgent#z6MkAgent',
      invocationTarget: 'https://was.example/space/abc/notes/'
    }
    const request = {
      query: [{ ...ZCAP_QUERY, capabilityQuery: [vmController] }]
    } as unknown as IVPRDetails
    expect(
      await refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('malformedRequest')
  })

  it('refuses a grantee controller that is not an Ed25519 did:key', async () => {
    const request = {
      query: [
        {
          ...ZCAP_QUERY,
          capabilityQuery: [
            {
              ...ZCAP_QUERY.capabilityQuery[0],
              controller: 'did:web:agent.example'
            }
          ]
        }
      ]
    } as unknown as IVPRDetails
    expect(
      await refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('malformedRequest')
  })

  it('accepts several capability queries naming the same controller', async () => {
    const second = { ...ZCAP_QUERY.capabilityQuery[0], referenceId: 'notes' }
    const request = {
      query: [
        {
          ...ZCAP_QUERY,
          capabilityQuery: [ZCAP_QUERY.capabilityQuery[0], second]
        }
      ]
    } as unknown as IVPRDetails
    const { profile } = await precheckExternalRequest({
      request,
      exchangeUrl: EXCHANGE_URL
    })
    expect(profile.zcapRequests).toHaveLength(2)
  })

  it('refuses a domain on any request', async () => {
    expect(
      await refusalOf(() =>
        precheckExternalRequest({
          request: zcapOnlyRequest({ domain: 'verifier.example' }),
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('domain')
  })

  it('refuses a presentation endpoint on another origin, allows a same-origin one', async () => {
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
      await refusalOf(() =>
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
    const { deliveryHost } = await precheckExternalRequest({
      request: sameOrigin,
      exchangeUrl: EXCHANGE_URL
    })
    expect(deliveryHost).toBe('was.example')
  })
})

describe('refuseEnrolledClientController', () => {
  let profile: WalletRequestProfile
  beforeAll(async () => {
    ;({ profile } = await precheckExternalRequest({
      request: zcapOnlyRequest(),
      exchangeUrl: EXCHANGE_URL
    }))
  })

  it('refuses a grantee the account document lists or listed as a wallet client', async () => {
    expect(
      await refusalOf(() =>
        refuseEnrolledClientController({
          profile,
          clientDids: new Set(['did:key:z6MkOther', 'did:key:z6MkAgent'])
        })
      )
    ).toBe('enrolledClient')
  })

  it('passes a grantee outside the set', async () => {
    expect(
      await refusalOf(() =>
        refuseEnrolledClientController({
          profile,
          clientDids: new Set(['did:key:z6MkOther'])
        })
      )
    ).toBeUndefined()
    expect(
      await refusalOf(() =>
        refuseEnrolledClientController({ profile, clientDids: new Set() })
      )
    ).toBeUndefined()
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

  it('lets public and private collection grants through', async () => {
    expect(
      barredGrants([grant('public-collection'), grant('collection')])
    ).toEqual([])
  })

  it('bars shares and protected-collection targets', async () => {
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

  it('ignores unsatisfiable grants, which delegate nothing', async () => {
    expect(barredGrants([grant(undefined)])).toEqual([])
  })
})

describe('unreadableGrants', () => {
  const SPACE_URL = 'https://was.example/space/abc/'
  const AGENT = 'did:key:z6MkqojacRDqmQgDi4ESKKhGDqnZx4C6cChAbQZXvnUFX7D7'
  const AGENT_KID = x25519RecipientFromDidKey({ did: AGENT }).id!
  const NOTES_URL = `${SPACE_URL}notes/`

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
      spaceUrl: SPACE_URL,
      collections
    })
  }

  it('refuses a URL on an encrypted collection whose key epoch omits the agent', async () => {
    const grants = resolve({
      invocationTarget: NOTES_URL,
      collections: existingCollectionsFrom([
        { id: 'notes', encrypted: true, recipientIds: new Set(['#other']) }
      ])
    })
    expect(barredGrants(grants)).toEqual([])
    expect(unreadableGrants(grants)).toHaveLength(1)
  })

  it('refuses a Resource URL inside such a collection', async () => {
    const grants = resolve({
      invocationTarget: `${NOTES_URL}note-1`,
      collections: existingCollectionsFrom([
        { id: 'notes', encrypted: true, recipientIds: new Set() }
      ])
    })
    expect(unreadableGrants(grants)).toHaveLength(1)
  })

  it('lets a URL through when the key epoch already lists the agent', async () => {
    const grants = resolve({
      invocationTarget: NOTES_URL,
      collections: existingCollectionsFrom([
        { id: 'notes', encrypted: true, recipientIds: new Set([AGENT_KID]) }
      ])
    })
    expect(unreadableGrants(grants)).toEqual([])
  })

  it('lets a URL through when the key epoch could not be read', async () => {
    // An unread epoch is no evidence the agent is absent; the grant keeps
    // the ciphertext note, as on the popup.
    const grants = resolve({
      invocationTarget: NOTES_URL,
      collections: existingCollectionsFrom([{ id: 'notes', encrypted: true }])
    })
    expect(grants[0]!.target.encrypted).toBe(true)
    expect(unreadableGrants(grants)).toEqual([])
  })

  it('lets a URL on a plaintext or public collection through', async () => {
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

  it('lets a private-collection descriptor on a standard encrypted collection through', async () => {
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

  it('waits for the key epochs only for a URL naming an existing collection', async () => {
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
  it('is the fixed marker the Grant activity records', async () => {
    expect(EXTERNAL_REQUEST_ORIGIN).toBe('n/a (API request)')
  })
})

describe('connection requests', () => {
  const CHALLENGE = 'connect-challenge-1'
  const AUDIENCE_URL = 'https://was.example/space/abc/friends/'
  let agent: CapabilityAgent
  let other: CapabilityAgent

  beforeAll(async () => {
    agent = await CapabilityAgent.fromSecret({
      secret: 'a connecting agent',
      handle: 'test',
      keyName: 'test-key'
    })
    other = await CapabilityAgent.fromSecret({
      secret: 'some other agent',
      handle: 'test',
      keyName: 'test-key'
    })
  })

  /**
   * The capability queries of a connection request: a read on one audience,
   * named by its container URL, and POST on the inbox.
   *
   * @param options {object}
   * @param options.controller {string}
   * @param [options.audience] {Record<string, unknown>}   overrides on the
   *   audience query
   * @returns {Array<object>}
   */
  function connectionQueries({
    controller,
    audience = {}
  }: {
    controller: string
    audience?: Record<string, unknown>
  }) {
    return [
      {
        referenceId: 'friends',
        allowedAction: ['GET', 'HEAD'],
        controller,
        invocationTarget: AUDIENCE_URL,
        ...audience
      },
      {
        referenceId: 'inbox',
        allowedAction: ['POST'],
        controller,
        invocationTarget: { type: INBOX_DESCRIPTOR_TYPE }
      }
    ]
  }

  /**
   * A connection request signed by its named controller.
   *
   * @param options {object}
   * @param [options.signer] {CapabilityAgent}   the controller, and the key
   *   that signs
   * @param [options.extra] {Record<string, unknown>}   members added before
   *   signing
   * @returns {Promise<IVPRDetails>}
   */
  async function signedConnection({
    signer = agent,
    extra = {}
  }: {
    signer?: CapabilityAgent
    extra?: Record<string, unknown>
  } = {}): Promise<IVPRDetails> {
    const request = {
      ...composeCapabilityRequest({
        capabilityQueries: connectionQueries({ controller: signer.id }),
        challenge: CHALLENGE,
        agent: { name: 'Feed agent' }
      }),
      ...extra
    }
    return (await signCapabilityRequest({
      request,
      signer: signer.getSigner() as never
    })) as unknown as IVPRDetails
  }

  /**
   * The same request with every grantee `controller` replaced.
   *
   * @param options {object}
   * @param options.request {IVPRDetails}
   * @param options.controller {string}
   * @returns {IVPRDetails}
   */
  function withController({
    request,
    controller
  }: {
    request: IVPRDetails
    controller: string
  }): IVPRDetails {
    const copy = structuredClone(request) as unknown as {
      query: Array<{ capabilityQuery: Array<{ controller: string }> }>
    }
    for (const query of copy.query) {
      for (const detail of query.capabilityQuery) {
        detail.controller = controller
      }
    }
    return copy as unknown as IVPRDetails
  }

  it('passes a request signed by its named controller as a connection request', async () => {
    const { profile, requestKind } = await precheckExternalRequest({
      request: await signedConnection(),
      exchangeUrl: EXCHANGE_URL
    })
    expect(requestKind).toBe('connection-request')
    expect(profile.zcapRequests).toHaveLength(2)
  })

  it('runs a request naming no inbox as before, with no proof', async () => {
    const { requestKind } = await precheckExternalRequest({
      request: zcapOnlyRequest(),
      exchangeUrl: EXCHANGE_URL
    })
    expect(requestKind).toBe('interaction-url')
  })

  it('refuses an unsigned connection request', async () => {
    const { proof: _proof, ...unsigned } = (await signedConnection()) as {
      proof?: unknown
    }
    expect(
      await refusalOf(() =>
        precheckExternalRequest({
          request: unsigned as IVPRDetails,
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('connectionUnsigned')
  })

  it('refuses a request signed by a key other than the named controller', async () => {
    const forged = withController({
      request: await signedConnection({ signer: other }),
      controller: agent.id
    })
    expect(
      await refusalOf(() =>
        precheckExternalRequest({ request: forged, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('connectionUnsigned')
  })

  it('refuses a request changed after signing', async () => {
    const tampered = {
      ...(await signedConnection()),
      agent: { name: 'Someone else' }
    } as IVPRDetails
    expect(
      await refusalOf(() =>
        precheckExternalRequest({
          request: tampered,
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('connectionUnsigned')
  })

  it('refuses a challenge carried only inside the query', async () => {
    const request = {
      query: [
        {
          type: 'AuthorizationCapabilityQuery',
          capabilityQuery: connectionQueries({ controller: agent.id }),
          challenge: CHALLENGE
        }
      ]
    } as unknown as IVPRDetails
    expect(
      await refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('connectionWithoutChallenge')
  })

  it('refuses a write grant on any target but the inbox', async () => {
    const request = {
      query: [
        {
          type: 'AuthorizationCapabilityQuery',
          capabilityQuery: connectionQueries({
            controller: agent.id,
            audience: { allowedAction: ['GET', 'PUT'] }
          })
        }
      ],
      challenge: CHALLENGE
    } as unknown as IVPRDetails
    expect(
      await refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('connectionWithWriteGrant')
  })

  it('refuses a descriptor other than the inbox', async () => {
    const request = {
      query: [
        {
          type: 'AuthorizationCapabilityQuery',
          capabilityQuery: connectionQueries({
            controller: agent.id,
            audience: {
              invocationTarget: {
                type: 'https://w3id.org/byoe#private-collection',
                name: 'friends'
              }
            }
          })
        }
      ],
      challenge: CHALLENGE
    } as unknown as IVPRDetails
    expect(
      await refusalOf(() =>
        precheckExternalRequest({ request, exchangeUrl: EXCHANGE_URL })
      )
    ).toBe('connectionTargetForm')
  })

  it('refuses a verbatim copy of a signed request hosted on another origin', async () => {
    const genuine = await signedConnection({
      extra: {
        interact: {
          service: [
            {
              type: 'UnmediatedHttpPresentationService2021',
              serviceEndpoint: 'https://agent.example/exchanges/1'
            }
          ]
        }
      }
    })
    expect(
      await refusalOf(() =>
        precheckExternalRequest({
          request: genuine,
          exchangeUrl: EXCHANGE_URL
        })
      )
    ).toBe('foreignDelivery')
  })
})

describe('refuseUntrustedInbox', () => {
  it('passes a trusted inbox', async () => {
    expect(
      await refusalOf(() => refuseUntrustedInbox({ trust: 'trusted' }))
    ).toBeUndefined()
  })

  it('refuses an absent inbox with noInbox', async () => {
    expect(
      await refusalOf(() => refuseUntrustedInbox({ trust: 'absent' }))
    ).toBe('noInbox')
  })

  it('refuses an untrusted inbox with untrustedInbox', async () => {
    expect(
      await refusalOf(() => refuseUntrustedInbox({ trust: 'untrusted' }))
    ).toBe('untrustedInbox')
  })
})

describe('refuseUnattributedServer', () => {
  /**
   * The service information's `hasFeature` over a fixed token list.
   *
   * @param features {string[]}
   * @returns {{ hasFeature(token: string): boolean }}
   */
  function serviceWith(features: string[]) {
    return { hasFeature: (token: string) => features.includes(token) }
  }

  it('passes a server advertising created-by', async () => {
    expect(
      await refusalOf(() =>
        refuseUnattributedServer({
          service: serviceWith(['listing', 'created-by'])
        })
      )
    ).toBeUndefined()
  })

  it('refuses a server without created-by with noCreatorAttribution', async () => {
    expect(
      await refusalOf(() =>
        refuseUnattributedServer({ service: serviceWith(['listing']) })
      )
    ).toBe('noCreatorAttribution')
  })
})

describe('the inbox grant class', () => {
  const SPACE_URL = 'https://was.example/space/abc/'
  const AGENT = 'did:key:z6MkqojacRDqmQgDi4ESKKhGDqnZx4C6cChAbQZXvnUFX7D7'
  const INBOX_URL = `${SPACE_URL}inbox/`

  /**
   * Resolves one inbox request of the given form and kind.
   *
   * @param options {object}
   * @param options.invocationTarget {ResolvedGrant['descriptor']['invocationTarget']}
   * @param options.allowedAction {string[]}
   * @param [options.requestKind] {'interaction-url' | 'connection-request'}
   * @returns {ResolvedGrant}
   */
  function resolveInbox({
    invocationTarget,
    allowedAction,
    requestKind
  }: {
    invocationTarget: ResolvedGrant['descriptor']['invocationTarget']
    allowedAction: string[]
    requestKind?: 'interaction-url' | 'connection-request'
  }): ResolvedGrant {
    const [grant] = resolveGrants({
      zcapRequests: [
        {
          referenceId: 'inbox',
          allowedAction,
          invocationTarget,
          controller: AGENT
        }
      ],
      spaceUrl: SPACE_URL,
      collections: existingCollectionsFrom([{ id: 'inbox' }]),
      requestKind
    })
    return grant!
  }

  it('passes POST on the inbox only in the inbox class, on a connection request', () => {
    const grant = resolveInbox({
      invocationTarget: { type: INBOX_DESCRIPTOR_TYPE },
      allowedAction: ['POST'],
      requestKind: 'connection-request'
    })
    expect(grant.target.targetClass).toBe('inbox')
    expect(grant.allowedActions).toEqual(['POST'])
    expect(barredGrants([grant])).toEqual([])
  })

  it('leaves the inbox descriptor unsatisfiable on any other request', () => {
    const grant = resolveInbox({
      invocationTarget: { type: INBOX_DESCRIPTOR_TYPE },
      allowedAction: ['POST'],
      requestKind: 'interaction-url'
    })
    expect(grant.target.targetClass).toBeUndefined()
  })

  it('grants no read of the inbox, by descriptor or by URL', () => {
    const byDescriptor = resolveInbox({
      invocationTarget: { type: INBOX_DESCRIPTOR_TYPE },
      allowedAction: ['GET'],
      requestKind: 'connection-request'
    })
    expect(byDescriptor.target.targetClass).toBeUndefined()
    for (const allowedAction of [['GET'], ['POST']]) {
      const byUrl = resolveInbox({
        invocationTarget: INBOX_URL,
        allowedAction,
        requestKind: 'connection-request'
      })
      expect(byUrl.target.targetClass).toBeUndefined()
    }
  })
})
