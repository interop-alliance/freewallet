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
import { ensureKeystore } from '@/lib/kms'

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
})
