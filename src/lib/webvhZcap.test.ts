// @vitest-environment node
/**
 * Unit tests for the did:webvh signing identities, as freewallet consumes them
 * from `@interop/wallet-core/webvh`: the promoted keyId shape, signer
 * delegation to the client's key, and the promotion marker predicate.
 */
import { describe, expect, it, vi } from 'vitest'
import {
  clientSigningKeyMultibase,
  isWebvhDid,
  webvhCapabilityAgent,
  webvhSigner
} from '@interop/wallet-core/webvh'
import type { ICapabilityAgent } from '@/types/auth'

const WEBVH_DID = 'did:webvh:zQmScid:example.test:space:abc:id'
const CLIENT_PKM = 'z6MkfakeClientSigningKey'

function fakeKeyAgent(): {
  keyAgent: ICapabilityAgent
  sign: ReturnType<typeof vi.fn>
} {
  const sign = vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3]))
  const signer = {
    id: `did:key:${CLIENT_PKM}#${CLIENT_PKM}`,
    type: 'Ed25519VerificationKey2020',
    sign
  }
  const keyAgent: ICapabilityAgent = {
    id: `did:key:${CLIENT_PKM}`,
    handle: 'test',
    getSigner: () => signer,
    getVerificationKeyPair: () => ({
      type: 'Ed25519VerificationKey2020',
      controller: `did:key:${CLIENT_PKM}`,
      publicKeyMultibase: CLIENT_PKM
    })
  }
  return { keyAgent, sign }
}

describe('clientSigningKeyMultibase', () => {
  it('reads the multibase out of the did:key id', () => {
    const { keyAgent } = fakeKeyAgent()
    expect(clientSigningKeyMultibase({ keyAgent })).toBe(CLIENT_PKM)
  })

  it('refuses a non-did:key agent id', () => {
    const { keyAgent } = fakeKeyAgent()
    keyAgent.id = WEBVH_DID
    expect(() => clientSigningKeyMultibase({ keyAgent })).toThrow(
      'Not a did:key agent id'
    )
  })
})

describe('webvhSigner', () => {
  it('names this client verification method in the did:webvh document', async () => {
    const { keyAgent, sign } = fakeKeyAgent()
    const signer = webvhSigner({ keyAgent, did: WEBVH_DID })

    expect(signer.id).toBe(`${WEBVH_DID}#${CLIENT_PKM}`)
    const data = new Uint8Array([9])
    await signer.sign({ data })
    expect(sign).toHaveBeenCalledWith({ data })
  })
})

describe('webvhCapabilityAgent', () => {
  it('presents the client key under the did:webvh identity', () => {
    const { keyAgent } = fakeKeyAgent()
    const agent = webvhCapabilityAgent({ keyAgent, did: WEBVH_DID })

    expect(agent.id).toBe(WEBVH_DID)
    expect(agent.getSigner().id).toBe(`${WEBVH_DID}#${CLIENT_PKM}`)
    expect(agent.getVerificationKeyPair().publicKeyMultibase).toBe(CLIENT_PKM)
  })
})

describe('isWebvhDid', () => {
  it('marks only did:webvh ids as promoted', () => {
    expect(isWebvhDid(WEBVH_DID)).toBe(true)
    expect(isWebvhDid(`did:key:${CLIENT_PKM}`)).toBe(false)
    expect(isWebvhDid(undefined)).toBe(false)
  })
})
