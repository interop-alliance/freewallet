/**
 * The backup credentials panel holds its removal disabled while Settings
 * mends the unlock-methods registry, and enables it once the mend settles.
 */
import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import '@/i18n'
import type { Session } from '@/types/auth'

vi.mock('@/session/backupCredential', () => ({
  listBackupCredentialEntries: vi.fn(async () => [
    {
      type: 'backup-credential',
      unlockSpaceId: 'unlock-space-backup',
      label: 'Backup one',
      createdAt: '2026-09-01T00:00:00Z'
    }
  ]),
  removeAccountBackupCredential: vi.fn(async () => undefined)
}))

const { BackupCredentialsSection } = await import('./BackupCredentialsSection')

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean
}

const SESSION = { registryReady: Promise.resolve() } as unknown as Session

describe('BackupCredentialsSection', () => {
  let container: HTMLDivElement
  let root: Root
  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.append(container)
    root = createRoot(container)
  })
  afterEach(async () => {
    await act(async () => {
      root.unmount()
    })
    container.remove()
  })

  /**
   * Renders the panel and returns its one remove button.
   *
   * @param options {object}
   * @param options.registryRepairing {boolean}
   * @returns {Promise<HTMLButtonElement>}
   */
  async function render({
    registryRepairing
  }: {
    registryRepairing: boolean
  }): Promise<HTMLButtonElement> {
    await act(async () => {
      root.render(
        <BackupCredentialsSection
          session={SESSION}
          registryRepairing={registryRepairing}
        />
      )
    })
    await act(async () => {
      await Promise.resolve()
    })
    const button = container.querySelector('button')
    if (!button) {
      throw new Error('No remove button rendered.')
    }
    return button
  }

  it('disables removal while the registry is being repaired', async () => {
    expect((await render({ registryRepairing: true })).disabled).toBe(true)
    expect((await render({ registryRepairing: false })).disabled).toBe(false)
  })
})
