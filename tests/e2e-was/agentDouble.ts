/**
 * A scripted agent test double for the connection request e2e. It stands in
 * for a third-party agent that connects to a wallet owner: it runs its own
 * WAS Space on the suite's teaching server, owning an `inbox` collection,
 * and presents a separate did:key (its connection key) to the owner.
 *
 * Its half of the contract is hand-built from the agent's obligations rather
 * than from the wallet's own builders, so it can falsify the contract the
 * wallet implements. It signs its connection request with the connection
 * key (`eddsa-jcs-2022`, purpose `authentication`, the proof `challenge`
 * equal to the VPR-root `challenge`). It verifies the response
 * presentation's proof against its `holder` and the challenge it issued. It
 * delegates POST on its own inbox to that `holder` and posts the capability
 * into the owner's inbox as a `Grant` envelope it writes by hand. It reads
 * its own inbox, attributes each message by the server-recorded `createdBy`
 * checked against `actor`, and adopts the capabilities by zcap id, so a
 * repeated delivery is a no-op.
 */
import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { CapabilityAgent } from '@interop/capability-agent'
import * as vc from '@interop/vc'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { DataIntegrityProof } from '@interop/data-integrity-proof'
import { eddsaRdfc2022 } from '@interop/ed25519-signature/eddsa-rdfc-2022'
import {
  httpStatus,
  WasClient,
  type Collection,
  type IZcap as WasZcap,
  type JsonObject
} from '@interop/was-client'
import {
  composeCapabilityRequest,
  createEphemeralExchange,
  documentLoader,
  pollEphemeralExchange,
  signCapabilityRequest,
  type IVPRDetails,
  type IZcap
} from '@interop/wallet-request'
import { spaceIdOfUrl } from '@interop/was-client/paths'
import { INBOX_DESCRIPTOR_TYPE } from '@/lib/walletRequest/connectionRequest'

export const WAS_URL = 'http://localhost:3002'

/**
 * The presentation service type a VPR names its delivery endpoint with.
 */
const PRESENTATION_SERVICE_TYPE = 'UnmediatedHttpPresentationService2021'

/**
 * The lifetime of a channel capability the double issues: well inside the
 * wallet's one-year limit on a received channel.
 */
const CHANNEL_TTL_MS = 30 * 24 * 60 * 60 * 1000

/**
 * The response presentation the wallet answers a connection request with,
 * as far as the double reads it.
 */
export interface ConnectionResponse {
  holder?: string
  zcap?: IZcap[]
  proof?: Record<string, unknown>
  [member: string]: unknown
}

/**
 * One message the double read out of its own inbox.
 */
export interface DoubleInboxMessage {
  resourceId: string
  createdBy?: string
  body: unknown
}

/**
 * Runs one call and reports how the server answered it: `ok` when it
 * resolved, or the refusal's status (`0` when the error carries none).
 *
 * @param call {Function}
 * @returns {Promise<'ok' | number>}
 */
export async function outcomeOf(
  call: () => Promise<unknown>
): Promise<'ok' | number> {
  try {
    await call()
    return 'ok'
  } catch (err) {
    return httpStatus(err) ?? 0
  }
}

/**
 * The agent test double: its Space controller key, its connection key
 * toward the owner, its own Space and inbox, and what it has adopted.
 */
export class AgentDouble {
  readonly name: string
  readonly controllerKey: CapabilityAgent
  readonly connectionKey: CapabilityAgent
  readonly spaceId: string
  readonly inbox: Collection
  /**
   * Every capability the double adopted out of its inbox, by zcap id.
   */
  readonly adopted = new Map<string, IZcap>()
  /**
   * How many deliveries named a zcap id already adopted.
   */
  repeatedDeliveries = 0

  constructor({
    name,
    controllerKey,
    connectionKey,
    spaceId,
    inbox
  }: {
    name: string
    controllerKey: CapabilityAgent
    connectionKey: CapabilityAgent
    spaceId: string
    inbox: Collection
  }) {
    this.name = name
    this.controllerKey = controllerKey
    this.connectionKey = connectionKey
    this.spaceId = spaceId
    this.inbox = inbox
  }

  /**
   * Mints the double's two keys and provisions its own Space, controlled by
   * the controller key, with a plaintext `inbox` collection.
   *
   * @param options {object}
   * @param options.name {string}   the self-declared name its requests carry
   * @returns {Promise<AgentDouble>}
   */
  static async create({ name }: { name: string }): Promise<AgentDouble> {
    const controllerKey = await CapabilityAgent.fromSeed({
      seed: crypto.getRandomValues(new Uint8Array(32)),
      handle: 'agent-double-space'
    })
    const connectionKey = await CapabilityAgent.fromSeed({
      seed: crypto.getRandomValues(new Uint8Array(32)),
      handle: 'agent-double-connection'
    })
    const was = WasClient.fromSigner({
      baseServerUrl: WAS_URL,
      signer: controllerKey.getSigner()
    })
    const space = await was.createSpace({ name: `${name} space` })
    const inbox = await space.createCollection({ id: 'inbox', name: 'Inbox' })
    return new AgentDouble({
      name,
      controllerKey,
      connectionKey,
      spaceId: spaceIdOfUrl(space.url),
      inbox
    })
  }

  /**
   * The double's own inbox container URL.
   *
   * @returns {string}
   */
  get inboxUrl(): string {
    return this.inbox.url
  }

  /**
   * A was-client signing as the connection key, the controller of every
   * grant the owner delegates to the double.
   *
   * @returns {WasClient}
   */
  agentClient(): WasClient {
    return WasClient.fromSigner({
      baseServerUrl: WAS_URL,
      signer: this.connectionKey.getSigner()
    })
  }

  /**
   * The double's connection request: reads (GET and HEAD) on each audience,
   * named by its container URL, and POST on the owner's inbox, named by the
   * `#inbox` descriptor, with the `challenge` at the VPR root. Signed by the
   * connection key unless `sign` is false. `endpoint`, when given, names the
   * presentation endpoint inside the signed body.
   *
   * @param options {object}
   * @param options.audienceUrls {string[]}
   * @param options.challenge {string}
   * @param [options.sign] {boolean}
   * @param [options.endpoint] {string}
   * @returns {Promise<IVPRDetails>}
   */
  async connectionRequest({
    audienceUrls,
    challenge,
    sign = true,
    endpoint
  }: {
    audienceUrls: string[]
    challenge: string
    sign?: boolean
    endpoint?: string
  }): Promise<IVPRDetails> {
    const controller = this.connectionKey.id
    const request = composeCapabilityRequest({
      agent: { name: this.name },
      challenge,
      capabilityQueries: [
        ...audienceUrls.map(url => ({
          referenceId: 'audience',
          allowedAction: ['GET', 'HEAD'],
          controller,
          invocationTarget: url
        })),
        {
          referenceId: 'inbox',
          allowedAction: ['POST'],
          controller,
          invocationTarget: { type: INBOX_DESCRIPTOR_TYPE }
        }
      ]
    })
    if (endpoint !== undefined) {
      request.interact = {
        service: [
          { type: PRESENTATION_SERVICE_TYPE, serviceEndpoint: endpoint }
        ]
      }
    }
    if (!sign) {
      return request
    }
    return await signCapabilityRequest({
      request,
      signer: this.connectionKey.getSigner()
    })
  }

  /**
   * Stores a request on a fresh ephemeral exchange.
   *
   * @param options {object}
   * @param options.request {IVPRDetails}
   * @returns {Promise<{ exchangeUrl: string, interactionUrl: string }>}
   */
  async storeRequest({
    request
  }: {
    request: IVPRDetails
  }): Promise<{ exchangeUrl: string; interactionUrl: string }> {
    return await createEphemeralExchange({ serverUrl: WAS_URL, request })
  }

  /**
   * Polls an exchange for the wallet's response presentation.
   *
   * @param options {object}
   * @param options.exchangeUrl {string}
   * @returns {Promise<ConnectionResponse>}
   */
  async awaitResponse({
    exchangeUrl
  }: {
    exchangeUrl: string
  }): Promise<ConnectionResponse> {
    const response = (await pollEphemeralExchange({
      exchangeUrl,
      timeoutMs: 60_000,
      intervalMs: 1000
    })) as { verifiablePresentation?: ConnectionResponse }
    if (!response?.verifiablePresentation) {
      throw new Error('The exchange completed with no presentation.')
    }
    return response.verifiablePresentation
  }

  /**
   * Verifies the response presentation before anything is delegated to its
   * holder: the proof is made by a key of the `holder` did:key, over the
   * challenge the double issued, with no `domain`. Returns the holder.
   * Throws when any check fails.
   *
   * @param options {object}
   * @param options.presentation {ConnectionResponse}
   * @param options.challenge {string}
   * @returns {Promise<string>}
   */
  async verifyResponse({
    presentation,
    challenge
  }: {
    presentation: ConnectionResponse
    challenge: string
  }): Promise<string> {
    const { holder, proof } = presentation
    if (typeof holder !== 'string' || !holder.startsWith('did:key:')) {
      throw new Error('The response names no did:key holder.')
    }
    if (!proof || typeof proof !== 'object') {
      throw new Error('The response carries no proof.')
    }
    if (proof.domain !== undefined) {
      throw new Error('The response proof carries a domain.')
    }
    if (proof.challenge !== challenge) {
      throw new Error('The response proof answers another challenge.')
    }
    if (!String(proof.verificationMethod).startsWith(`${holder}#`)) {
      throw new Error('The response proof is not made by the holder.')
    }
    const suite =
      proof.type === 'DataIntegrityProof'
        ? new DataIntegrityProof({ cryptosuite: eddsaRdfc2022 })
        : new Ed25519Signature2020()
    const result = (await vc.verify({
      presentation: presentation as never,
      challenge,
      suite,
      documentLoader
    } as never)) as { verified: boolean; error?: unknown }
    if (!result.verified) {
      throw new Error('The response presentation did not verify.', {
        cause: result.error
      })
    }
    return holder
  }

  /**
   * Delegates POST on the double's own inbox to the owner's pairwise
   * did:key: the channel capability.
   *
   * @param options {object}
   * @param options.holder {string}
   * @returns {Promise<IZcap>}
   */
  async issueChannel({ holder }: { holder: string }): Promise<IZcap> {
    return (await this.inbox.grant({
      to: holder,
      actions: ['POST'],
      expires: new Date(Date.now() + CHANNEL_TTL_MS)
    })) as unknown as IZcap
  }

  /**
   * The `Grant` envelope carrying capabilities, written by hand.
   *
   * @param options {object}
   * @param options.zcaps {IZcap[]}
   * @returns {object}
   */
  grantEnvelope({ zcaps }: { zcaps: IZcap[] }): Record<string, unknown> {
    return {
      type: 'Grant',
      actor: this.connectionKey.id,
      object: { zcaps }
    }
  }

  /**
   * POSTs a body into the owner's inbox, invoking the inbox grant as the
   * connection key, under `application/json`.
   *
   * @param options {object}
   * @param options.inboxGrant {IZcap}
   * @param options.body {object}
   * @returns {Promise<void>}
   */
  async postToOwner({
    inboxGrant,
    body
  }: {
    inboxGrant: IZcap
    body: Record<string, unknown>
  }): Promise<void> {
    const inbox = this.agentClient().fromCapability(
      inboxGrant as unknown as WasZcap
    ) as Collection
    await inbox.add(body as JsonObject, { contentType: 'application/json' })
  }

  /**
   * Reads every message in the double's own inbox, deletes it, and adopts
   * each capability of a Grant envelope whose `actor` is the server-recorded
   * creator, by zcap id. Returns what was read.
   *
   * @returns {Promise<DoubleInboxMessage[]>}
   */
  async readOwnInbox(): Promise<DoubleInboxMessage[]> {
    const read: DoubleInboxMessage[] = []
    for await (const item of this.inbox.listItems()) {
      const resource = this.inbox.resource(item.id)
      const meta = (await resource.meta()) as { createdBy?: string } | null
      const body = await resource.get()
      read.push({
        resourceId: item.id,
        ...(meta?.createdBy !== undefined && { createdBy: meta.createdBy }),
        body
      })
      const envelope = body as {
        type?: unknown
        actor?: unknown
        object?: { zcaps?: IZcap[] }
      } | null
      if (
        envelope?.type === 'Grant' &&
        typeof envelope.actor === 'string' &&
        envelope.actor === meta?.createdBy
      ) {
        for (const zcap of envelope.object?.zcaps ?? []) {
          if (this.adopted.has(zcap.id)) {
            this.repeatedDeliveries += 1
          } else {
            this.adopted.set(zcap.id, zcap)
          }
        }
      }
      await resource.delete()
    }
    return read
  }
}

/**
 * A relay on another origin than the exchange a request names: an
 * interaction endpoint and an exchange serving one stored request verbatim,
 * with the CORS headers a browser needs. It stands in for a phishing host
 * re-serving a genuine signed request.
 *
 * @param options {object}
 * @param options.request {IVPRDetails}   served verbatim
 * @returns {Promise<{ interactionUrl: string, close: () => Promise<void> }>}
 */
export async function startRelay({
  request
}: {
  request: IVPRDetails
}): Promise<{ interactionUrl: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    res.setHeader('access-control-allow-origin', '*')
    res.setHeader('access-control-allow-headers', '*')
    res.setHeader('access-control-allow-methods', 'GET, POST, OPTIONS')
    if (req.method === 'OPTIONS') {
      res.writeHead(204).end()
      return
    }
    const { port } = server.address() as AddressInfo
    const exchangeUrl = `http://127.0.0.1:${port}/exchanges/relay`
    const path = new URL(req.url ?? '/', exchangeUrl).pathname
    res.setHeader('content-type', 'application/json')
    if (req.method === 'GET' && path === '/exchanges/relay/protocols') {
      res.end(JSON.stringify({ protocols: { vcapi: exchangeUrl } }))
      return
    }
    if (req.method === 'POST' && path === '/exchanges/relay') {
      req.resume()
      res.end(JSON.stringify({ verifiablePresentationRequest: request }))
      return
    }
    res.writeHead(404).end('{}')
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as AddressInfo
  return {
    interactionUrl: `http://127.0.0.1:${port}/exchanges/relay/protocols?iuv=1`,
    close: async () =>
      await new Promise<void>(resolve => server.close(() => resolve()))
  }
}
