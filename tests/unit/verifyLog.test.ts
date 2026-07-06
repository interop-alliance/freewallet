import { describe, expect, it } from 'vitest'
import { getVerifyLogFromPayload } from '@/lib/viewMappers/verifyLog'

describe('getVerifyLogFromPayload', () => {
  it('reads the log from the first result entry', () => {
    const log = [{ id: 'valid_signature' }, { id: 'expiration' }]
    expect(getVerifyLogFromPayload({ results: [{ log }] })).toEqual(log)
  })

  it('falls back to a top-level log when results has none', () => {
    const log = [{ id: 'registered_issuer' }]
    expect(getVerifyLogFromPayload({ log })).toEqual(log)
  })

  it('prefers the first-result log over a top-level log', () => {
    const resultLog = [{ id: 'from-result' }]
    const topLog = [{ id: 'from-top' }]
    expect(
      getVerifyLogFromPayload({ results: [{ log: resultLog }], log: topLog })
    ).toEqual(resultLog)
  })

  it('returns an empty array when no log is present', () => {
    expect(getVerifyLogFromPayload({})).toEqual([])
  })

  it('returns an empty array when the log fields are not arrays', () => {
    expect(
      getVerifyLogFromPayload({ results: [{ log: 'nope' as never }], log: 42 })
    ).toEqual([])
  })
})
