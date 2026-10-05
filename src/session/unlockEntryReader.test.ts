// @vitest-environment node
/**
 * What `unlockEntryReaderFor` mints: a GET-only child of the stored
 * management zcap naming the keyring RECORD, for both kinds of acting
 * session, the only shape the server's client-annex clause admits for a
 * Resource read. The target, the action set, the delegatee, and the sender
 * are pinned here.
 */
import { describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'
import type { UnlockMethod } from '@/session/unlockMethods'
import type { ZcapClient } from '@interop/ezcap'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  WAS_SERVER_URL: 'https://was.example'
}))

const { unlockEntryReaderFor } = await import('@/session/unlockMethods')

const SPACE_URL = 'https://was.example/space/sp1/'
const ACCOUNT_DID = 'did:webvh:example:account'

/**
 * A delegating client whose `delegate` records each child it is asked for.
 *
 * @returns {object}   the client and the recorded delegation options
 */
function recordingClient(): {
  zcapClient: ZcapClient
  delegated: Record<string, unknown>[]
} {
  const delegated: Record<string, unknown>[] = []
  const zcapClient = {
    delegate: vi.fn(async (options: Record<string, unknown>) => {
      delegated.push(options)
      return { id: 'urn:zcap:child', ...options }
    })
  } as unknown as ZcapClient
  return { zcapClient, delegated }
}

/**
 * A passphrase entry whose stored management zcap names the account DID.
 *
 * @param options {object}
 * @param [options.allowedAction] {string[]}
 * @returns {object}
 */
function entry({
  allowedAction = ['GET', 'PUT', 'DELETE']
}: {
  allowedAction?: string[]
} = {}): UnlockMethod {
  return {
    type: 'passphrase',
    unlockSpaceId: 'sp1',
    manageCapability: {
      id: 'urn:zcap:parent',
      controller: ACCOUNT_DID,
      invocationTarget: SPACE_URL,
      allowedAction
    }
  } as unknown as UnlockMethod
}

describe('unlockEntryReaderFor (the ladder-anchored read)', () => {
  it('names the keyring record on a GET-only child', async () => {
    const { zcapClient, delegated } = recordingClient()
    const invoker = { invoker: true } as unknown as ZcapClient

    const reader = unlockEntryReaderFor({
      session: {} as Session,
      signer: { zcapClient, invoker, controller: 'did:key:zLadderBare' }
    })
    const result = await reader(entry())

    expect(typeof result).toBe('object')
    expect((result as { zcapClient: ZcapClient }).zcapClient).toBe(invoker)
    expect(delegated).toHaveLength(1)
    expect(delegated[0].invocationTarget).toBe(
      `${SPACE_URL}keyring/keyring.json`
    )
    expect(delegated[0].allowedActions).toEqual(['GET'])
    expect(delegated[0].controller).toBe('did:key:zLadderBare')
  })

  it('resolves the refusal for a parent that carries no GET', async () => {
    const { zcapClient, delegated } = recordingClient()

    const reader = unlockEntryReaderFor({
      session: {} as Session,
      signer: {
        zcapClient,
        invoker: zcapClient,
        controller: 'did:key:zLadderBare'
      }
    })

    await expect(reader(entry({ allowedAction: ['DELETE'] }))).resolves.toBe(
      'unsupported-capability'
    )
    expect(delegated).toHaveLength(0)
  })
})

describe('unlockEntryReaderFor (an enrolled session)', () => {
  it("mints a GET child of the stored parent through the session's own signer", async () => {
    const { zcapClient, delegated } = recordingClient()
    const session = {
      profile: {
        keyAgent: { id: 'did:key:zEnrolledClient' },
        accountPointer: { did: ACCOUNT_DID },
        zcapClient
      }
    } as unknown as Session

    const reader = unlockEntryReaderFor({ session })
    const result = await reader(entry())

    // The session's root zcapClient signs as the account DID the parent
    // names, so it both delegates the child and sends it.
    expect((result as { zcapClient: ZcapClient }).zcapClient).toBe(zcapClient)
    expect(delegated).toHaveLength(1)
    expect(delegated[0].capability).toMatchObject({ id: 'urn:zcap:parent' })
    expect(delegated[0].controller).toBe(ACCOUNT_DID)
    expect(delegated[0].allowedActions).toEqual(['GET'])
    expect(delegated[0].invocationTarget).toBe(
      `${SPACE_URL}keyring/keyring.json`
    )
  })

  it('refuses a parent naming a delegatee the session cannot act as', async () => {
    const { zcapClient, delegated } = recordingClient()
    const session = {
      profile: {
        keyAgent: { id: 'did:key:zEnrolledClient' },
        accountPointer: { did: 'did:webvh:example:other' },
        zcapClient
      }
    } as unknown as Session

    const reader = unlockEntryReaderFor({ session })

    await expect(reader(entry())).resolves.toBe('foreign-controller')
    expect(delegated).toHaveLength(0)
  })
})
