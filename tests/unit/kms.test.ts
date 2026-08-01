// @vitest-environment node
/**
 * Unit tests for WebKMS keystore provisioning (`src/lib/kms.ts`):
 * discovery via list-by-controller,
 * creation on first login, and failure propagation. The zcap client is
 * stubbed per house pattern; keystore creation is spied on the real
 * `KmsClient` static.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { CapabilityAgent, KmsClient } from '@interop/webkms-client'
import type { ZcapClient } from '@interop/ezcap'
import { ensureKeystore, promoteKeystoreController } from '@/lib/kms'

const KMS_SERVER_URL = 'https://kms.example.test/kms'
const KEYSTORES_URL = `${KMS_SERVER_URL}/keystores`

async function testKeyAgent(): Promise<CapabilityAgent> {
  return await CapabilityAgent.fromSecret({
    secret: 'correct horse battery staple',
    handle: 'test',
    keyName: 'test-key'
  })
}

/**
 * Builds a ZcapClient stub whose `request` resolves to a keystore listing.
 */
function zcapClientListing(results: Array<{ id: string }>) {
  const request = vi.fn().mockResolvedValue({ data: { results } })
  return { zcapClient: { request } as unknown as ZcapClient, request }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('ensureKeystore', () => {
  it('binds to an existing keystore found by listing (no creation)', async () => {
    const keyAgent = await testKeyAgent()
    const keystoreId = `${KEYSTORES_URL}/z19uMCiPNET4YbcPpBcab5mEE`
    const { zcapClient, request } = zcapClientListing([{ id: keystoreId }])
    const createSpy = vi.spyOn(KmsClient, 'createKeystore')

    const keystoreAgent = await ensureKeystore({
      kmsServerUrl: KMS_SERVER_URL,
      keyAgent,
      zcapClient
    })

    expect(request).toHaveBeenCalledWith({
      url: `${KEYSTORES_URL}?controller=${encodeURIComponent(keyAgent.id)}`,
      method: 'GET',
      action: 'read'
    })
    expect(createSpy).not.toHaveBeenCalled()
    expect(keystoreAgent.keystoreId).toBe(keystoreId)
    expect(keystoreAgent.kmsClient.keystoreId).toBe(keystoreId)
    expect(keystoreAgent.capabilityAgent).toBe(keyAgent)
  })

  it('creates a keystore when the listing is empty (first login)', async () => {
    const keyAgent = await testKeyAgent()
    const keystoreId = `${KEYSTORES_URL}/z1A2b3C4d5E6f7G8h9J1kMnPq`
    const { zcapClient } = zcapClientListing([])
    const createSpy = vi.spyOn(KmsClient, 'createKeystore').mockResolvedValue({
      id: keystoreId,
      controller: keyAgent.id,
      sequence: 0,
      kmsModule: 'local-v1'
    })

    const keystoreAgent = await ensureKeystore({
      kmsServerUrl: KMS_SERVER_URL,
      keyAgent,
      zcapClient
    })

    expect(createSpy).toHaveBeenCalledWith({
      url: KEYSTORES_URL,
      config: { sequence: 0, controller: keyAgent.id },
      invocationSigner: expect.objectContaining({
        sign: expect.any(Function)
      })
    })
    expect(keystoreAgent.keystoreId).toBe(keystoreId)
    expect(keystoreAgent.kmsClient.keystoreId).toBe(keystoreId)
  })

  it('propagates a listing failure (caller decides severity)', async () => {
    const keyAgent = await testKeyAgent()
    const request = vi.fn().mockRejectedValue(new Error('kms unreachable'))
    const zcapClient = { request } as unknown as ZcapClient

    await expect(
      ensureKeystore({ kmsServerUrl: KMS_SERVER_URL, keyAgent, zcapClient })
    ).rejects.toThrow('kms unreachable')
  })

  it('falls back to the did:key listing for a not-yet-promoted keystore', async () => {
    const keyAgent = await testKeyAgent()
    const webvhDid = 'did:webvh:zQmScid:kms.example.test:space:abc:id'
    const keystoreId = `${KEYSTORES_URL}/z19uFallbackKeystore`
    // The promoted-controller listing misses; the did:key fallback hits.
    const request = vi.fn().mockResolvedValue({ data: { results: [] } })
    const fallbackRequest = vi
      .fn()
      .mockResolvedValue({ data: { results: [{ id: keystoreId }] } })
    const createSpy = vi.spyOn(KmsClient, 'createKeystore')

    const keystoreAgent = await ensureKeystore({
      kmsServerUrl: KMS_SERVER_URL,
      keyAgent,
      zcapClient: { request } as unknown as ZcapClient,
      controller: webvhDid,
      capabilityAgent: { id: webvhDid } as never,
      fallbackZcapClient: {
        request: fallbackRequest
      } as unknown as ZcapClient
    })

    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({
        url: `${KEYSTORES_URL}?controller=${encodeURIComponent(webvhDid)}`
      })
    )
    expect(fallbackRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        url: `${KEYSTORES_URL}?controller=${encodeURIComponent(keyAgent.id)}`
      })
    )
    expect(createSpy).not.toHaveBeenCalled()
    expect(keystoreAgent.keystoreId).toBe(keystoreId)
    // Bound as the did:key so its invocations verify against the
    // still-unpromoted keystore config.
    expect(keystoreAgent.capabilityAgent).toBe(keyAgent)
  })
})

describe('promoteKeystoreController', () => {
  const webvhDid = 'did:webvh:zQmScid:kms.example.test:space:abc:id'

  function stubKeystoreAgent(config: { controller: string }) {
    const signer = { sign: vi.fn() }
    const getKeystore = vi.fn().mockResolvedValue({
      id: 'ks-1',
      sequence: 3,
      controller: config.controller
    })
    const updateKeystore = vi.fn().mockResolvedValue(undefined)
    return {
      keystoreAgent: {
        kmsClient: { getKeystore, updateKeystore },
        capabilityAgent: { getSigner: () => signer }
      } as never,
      getKeystore,
      updateKeystore
    }
  }

  it('writes the bumped config naming the did:webvh', async () => {
    const { keystoreAgent, updateKeystore } = stubKeystoreAgent({
      controller: 'did:key:z6MkOldController'
    })

    const promoted = await promoteKeystoreController({
      keystoreAgent,
      controller: webvhDid
    })

    expect(promoted).toBe(true)
    expect(updateKeystore).toHaveBeenCalledWith(
      expect.objectContaining({
        config: expect.objectContaining({
          sequence: 4,
          controller: webvhDid
        })
      })
    )
  })

  it('no-ops when the keystore already names the controller', async () => {
    const { keystoreAgent, updateKeystore } = stubKeystoreAgent({
      controller: webvhDid
    })

    const promoted = await promoteKeystoreController({
      keystoreAgent,
      controller: webvhDid
    })

    expect(promoted).toBe(false)
    expect(updateKeystore).not.toHaveBeenCalled()
  })
})
