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

  it('accepts a bare cid string from older records', () => {
    const info = credentialActivityInfo(
      activity({
        type: ['Delete'],
        summary: 'Credential deleted',
        object: 'abc'
      })
    )
    expect(info).toEqual({ cid: 'abc', verb: 'deleted' })
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
