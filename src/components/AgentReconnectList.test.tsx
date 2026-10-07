/**
 * The agent list a ceremony's dialog shows, driven through the backup
 * credential removal: the removal lists the agents its ladder VM signed
 * for, each ticked by default; once the removal resolves, an unticked agent
 * is marked declined and the ticked ones are restored. A failed removal
 * declines nothing. A removal that cuts off no agent shows the same dialog
 * with no list. The forget's `ends` mode carries no tick.
 */
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import '@/i18n'
import type { Session } from '@/types/auth'

const calls = vi.hoisted(() => [] as string[])

vi.mock('@/session/backupCredential', () => ({
  listBackupCredentialEntries: vi.fn(async () => [
    {
      type: 'backup-credential',
      unlockSpaceId: 'unlock-space-backup',
      label: 'Backup one',
      createdAt: '2026-09-01T00:00:00Z',
      keyAgreementKeyMultibase: 'z6LSbackup',
      updateKeyMultibase: 'z6MkRung0'
    }
  ]),
  removeAccountBackupCredential: vi.fn(async () => {
    calls.push('remove')
  })
}))

vi.mock('@/session/credentialRotation', () => ({
  retiredCredentialWithdrawnKeys: vi.fn(async () => [
    'did:webvh:scid:host#z6MkLadder'
  ])
}))

vi.mock('@/session/agentReconnect', () => ({
  agentsSignedByWithdrawnAuthority: vi.fn(async () => [
    { resourceId: 'r-news', did: 'did:key:zNews', name: 'News agent' },
    { resourceId: 'r-feed', did: 'did:key:zFeed', name: 'Feed agent' }
  ]),
  declineAgents: vi.fn(async ({ dids }: { dids: string[] }) => {
    calls.push(`decline:${dids.join(',')}`)
    return { declined: dids, failed: [] }
  }),
  reconnectAgents: vi.fn(async ({ dids }: { dids: string[] }) => {
    calls.push(`reconnect:${dids.join(',')}`)
    return {
      agents: dids.map(did => ({ did, outcome: 'restored' })),
      entries: [],
      outcome: {}
    }
  })
}))

const { BackupCredentialsSection } = await import('./BackupCredentialsSection')
const { AgentReconnectList } = await import('./AgentReconnectList')
const agentReconnect = await import('@/session/agentReconnect')

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean
}

const SESSION = { registryReady: Promise.resolve() } as unknown as Session

describe('the agent list in a ceremony dialog', () => {
  let container: HTMLDivElement
  let root: Root
  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true
    calls.length = 0
    container = document.createElement('div')
    document.body.append(container)
    root = createRoot(container)
  })
  afterEach(async () => {
    await act(async () => {
      root.unmount()
    })
    container.remove()
    vi.restoreAllMocks()
  })

  /**
   * Lets pending promises and the effects behind them settle.
   *
   * @returns {Promise<void>}
   */
  async function settle(): Promise<void> {
    for (let round = 0; round < 3; round += 1) {
      await act(async () => {
        await Promise.resolve()
      })
    }
  }

  /**
   * The open dialog, which MUI portals to the document body.
   *
   * @returns {HTMLElement}
   */
  function dialog(): HTMLElement {
    const found = document.body.querySelector<HTMLElement>('[role="dialog"]')
    if (!found) {
      throw new Error('No dialog open.')
    }
    return found
  }

  it('lists the agents the removed ladder VM signed for, ticked, and declines the unticked one', async () => {
    await act(async () => {
      root.render(<BackupCredentialsSection session={SESSION} />)
    })
    await settle()
    await act(async () => {
      container.querySelector('button')!.click()
    })
    await settle()

    expect(
      agentReconnect.agentsSignedByWithdrawnAuthority
    ).toHaveBeenCalledWith({
      session: SESSION,
      keys: ['did:webvh:scid:host#z6MkLadder']
    })
    const boxes = [
      ...dialog().querySelectorAll<HTMLInputElement>('input[type="checkbox"]')
    ]
    expect(boxes.map(box => box.getAttribute('aria-label'))).toEqual([
      'News agent',
      'Feed agent'
    ])
    expect(boxes.every(box => box.checked)).toBe(true)

    await act(async () => {
      boxes[1].click()
    })
    const removeButton = [...dialog().querySelectorAll('button')].find(
      button => button.textContent !== 'Cancel'
    )!
    await act(async () => {
      removeButton.click()
    })
    await settle()

    expect(calls).toEqual([
      'remove',
      'decline:did:key:zFeed',
      'reconnect:did:key:zNews'
    ])
  })

  it('writes no decline when the removal fails', async () => {
    const backupCredential = await import('@/session/backupCredential')
    vi.mocked(
      backupCredential.removeAccountBackupCredential
    ).mockImplementationOnce(async () => {
      calls.push('remove')
      throw new Error('The removal failed.')
    })
    await act(async () => {
      root.render(<BackupCredentialsSection session={SESSION} />)
    })
    await settle()
    await act(async () => {
      container.querySelector('button')!.click()
    })
    await settle()

    const boxes = [
      ...dialog().querySelectorAll<HTMLInputElement>('input[type="checkbox"]')
    ]
    await act(async () => {
      boxes[1].click()
    })
    const removeButton = [...dialog().querySelectorAll('button')].find(
      button => button.textContent !== 'Cancel'
    )!
    await act(async () => {
      removeButton.click()
    })
    await settle()

    expect(calls).toEqual(['remove'])
  })

  it('confirms with no list when the removal cuts off no agent', async () => {
    vi.mocked(
      agentReconnect.agentsSignedByWithdrawnAuthority
    ).mockResolvedValueOnce([])
    await act(async () => {
      root.render(<BackupCredentialsSection session={SESSION} />)
    })
    await settle()
    await act(async () => {
      container.querySelector('button')!.click()
    })
    await settle()

    expect(dialog().querySelector('input[type="checkbox"]')).toBeNull()
    const removeButton = [...dialog().querySelectorAll('button')].find(
      button => button.textContent !== 'Cancel'
    )!
    await act(async () => {
      removeButton.click()
    })
    await settle()

    expect(calls).toEqual(['remove', 'reconnect:'])
  })

  it('states that the access ends, with no tick, in the forget mode', async () => {
    await act(async () => {
      root.render(
        <AgentReconnectList
          agents={[{ resourceId: 'r', did: 'did:key:zNews', name: 'News' }]}
          mode="ends"
          isTicked={() => true}
          onToggle={() => {}}
        />
      )
    })

    expect(container.querySelector('input[type="checkbox"]')).toBeNull()
    expect(container.textContent).toContain('News')
    expect(container.textContent).toContain('ends the access')
  })

  it('renders nothing for no agents', async () => {
    await act(async () => {
      root.render(
        <AgentReconnectList
          agents={[]}
          mode="tick"
          isTicked={() => true}
          onToggle={() => {}}
        />
      )
    })

    expect(container.textContent).toBe('')
  })
})
