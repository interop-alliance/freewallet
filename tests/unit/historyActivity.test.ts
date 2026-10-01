import { describe, expect, it } from 'vitest'
import type { WalletActivity } from '@/stores/storageManager'
import { classifyActivity, credentialActivityInfo } from '@/lib/historyActivity'

function activity(doc: Partial<WalletActivity>): WalletActivity {
  return doc as WalletActivity
}

describe('credentialActivityInfo', () => {
  it('reads the cid and title out of an object payload', () => {
    const info = credentialActivityInfo(
      activity({
        type: ['Create'],
        summary: 'Credential added',
        object: { cid: 'abc', title: 'Diploma' }
      })
    )
    expect(info).toEqual({ cid: 'abc', title: 'Diploma', verb: 'created' })
  })

  it('returns null for an Object.prototype key such as toString', () => {
    expect(
      credentialActivityInfo(
        activity({
          type: ['toString'],
          summary: 'Credential added',
          object: { cid: 'abc' }
        })
      )
    ).toBeNull()
  })

  it('agrees with classifyActivity on prototype keys', () => {
    const doc = activity({
      type: ['constructor'],
      summary: 'Credential added',
      object: { cid: 'abc' }
    })
    expect(credentialActivityInfo(doc)).toBeNull()
    expect(classifyActivity(doc)).toBe('other')
  })
})

describe('classifyActivity', () => {
  it('sorts an App Connect Grant under applications', () => {
    expect(
      classifyActivity(
        activity({
          type: ['Grant'],
          summary: 'Connected Demo App (https://app.example) to wallet.',
          object: {
            origin: 'https://app.example',
            zcaps: [],
            appConnect: { name: 'Demo App', firstRun: false }
          }
        })
      )
    ).toBe('applications')
  })

  it('sorts an agent Grant under applications', () => {
    expect(
      classifyActivity(
        activity({
          type: ['Grant'],
          summary: 'Granted storage access to research-bot.',
          object: {
            origin: 'n/a (API request)',
            zcaps: [],
            actor: { name: 'research-bot' }
          }
        })
      )
    ).toBe('applications')
  })

  it('sorts a plain Login under login', () => {
    expect(
      classifyActivity(
        activity({
          type: ['Login'],
          summary: 'Logged in to https://rp.example with wallet.',
          object: { origin: 'https://rp.example', zcaps: [] }
        })
      )
    ).toBe('login')
    expect(
      classifyActivity(
        activity({ type: ['Login'], summary: 'Logged in to wallet.' })
      )
    ).toBe('login')
  })

  it('sorts a Revoke under applications', () => {
    expect(
      classifyActivity(
        activity({ type: ['Revoke'], summary: 'Revoked agent access.' })
      )
    ).toBe('applications')
  })
})
