import { describe, expect, it } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { getSubject } from '@/lib/viewMappers/getSubject'

describe('getSubject', () => {
  it('returns the subject object directly when it is not an array', () => {
    const credential = {
      credentialSubject: { id: 'did:example:123', name: 'Alice' }
    } as unknown as IVerifiableCredential
    expect(getSubject(credential)).toEqual({
      id: 'did:example:123',
      name: 'Alice'
    })
  })

  it('returns the first entry when the subject is an array', () => {
    const credential = {
      credentialSubject: [{ name: 'First' }, { name: 'Second' }]
    } as unknown as IVerifiableCredential
    expect(getSubject(credential)).toEqual({ name: 'First' })
  })

  it('returns undefined for an empty subject array', () => {
    const credential = {
      credentialSubject: []
    } as unknown as IVerifiableCredential
    expect(getSubject(credential)).toBeUndefined()
  })
})
