// @vitest-environment node
/**
 * What `unlockEntryReaderFor` mints for a ladder-anchored session: a GET-only
 * child of the stored management zcap naming the keyring RECORD, rather than
 * the Space Metadata object the bare `GET` child names. The server's
 * client-annex clause admits a Resource read only in that shape, so the
 * target and the action set are pinned here.
 */
import { describe, expect, it, vi } from 'vitest'
import type { Session } from '@/types/auth'
import type { ZcapClient } from '@interop/ezcap'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<Record<string, unknown>>()),
  WAS_SERVER_URL: 'https://was.example'
}))

const { unlockEntryReaderFor } = await import('@/session/unlockMethods')

const SPACE_URL = 'https://was.example/space/sp1/'

describe('unlockEntryReaderFor (the ladder-anchored keyring read)', () => {
  it('names the keyring record on a GET-only child', async () => {
    const delegated: Record<string, unknown>[] = []
    const zcapClient = {
      delegate: vi.fn(async (options: Record<string, unknown>) => {
        delegated.push(options)
        return { id: 'urn:zcap:child', ...options }
      })
    } as unknown as ZcapClient
    const invoker = { invoker: true } as unknown as ZcapClient

    const reader = unlockEntryReaderFor({
      session: {} as Session,
      signer: { zcapClient, invoker, controller: 'did:key:zLadderBare' }
    })

    const result = await reader({
      type: 'passphrase',
      unlockSpaceId: 'sp1',
      manageCapability: {
        id: 'urn:zcap:parent',
        controller: 'did:webvh:example:account',
        invocationTarget: SPACE_URL,
        allowedAction: ['GET', 'PUT', 'DELETE']
      }
    } as unknown as Parameters<typeof reader>[0])

    expect(result?.zcapClient).toBe(invoker)
    expect(delegated).toHaveLength(1)
    expect(delegated[0].invocationTarget).toBe(
      `${SPACE_URL}keyring/keyring.json`
    )
    expect(delegated[0].allowedActions).toEqual(['GET'])
    expect(delegated[0].controller).toBe('did:key:zLadderBare')
  })
})
