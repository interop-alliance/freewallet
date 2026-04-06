// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { cidFrom, bufferToBase64Url } from '../src/lib/cidFrom'

describe('bufferToBase64Url', () => {
  it('converts a known buffer to the correct base64url string', () => {
    // [0, 255, 128] → standard base64 "AP+A" → url-safe "AP-A"
    const buf = new Uint8Array([0, 255, 128]).buffer
    expect(bufferToBase64Url(buf)).toBe('AP-A')
  })

  it('produces no +, /, or = characters', () => {
    // Use bytes whose standard base64 contains + and /
    const buf = new Uint8Array([251, 239, 190]).buffer
    const result = bufferToBase64Url(buf)
    expect(result).not.toMatch(/[+/=]/)
  })

  it('returns an empty string for an empty buffer', () => {
    expect(bufferToBase64Url(new ArrayBuffer(0))).toBe('')
  })
})

describe('cidFrom', () => {
  it('returns a non-empty string', async () => {
    const result = await cidFrom({ doc: { hello: 'world' } })
    expect(typeof result).toBe('string')
    expect(result.length).toBeGreaterThan(0)
  })

  it('output contains only URL-safe base64 characters', async () => {
    const result = await cidFrom({ doc: { hello: 'world' } })
    expect(result).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('is deterministic — same input yields same CID', async () => {
    const doc = { a: 1, b: 'test', c: true }
    const r1 = await cidFrom({ doc })
    const r2 = await cidFrom({ doc })
    expect(r1).toBe(r2)
  })

  it('different documents produce different CIDs', async () => {
    const r1 = await cidFrom({ doc: { x: 1 } })
    const r2 = await cidFrom({ doc: { x: 2 } })
    expect(r1).not.toBe(r2)
  })

  it('is stable across key orderings (canonical form)', async () => {
    const r1 = await cidFrom({ doc: { a: 1, b: 2 } })
    const r2 = await cidFrom({ doc: { b: 2, a: 1 } })
    expect(r1).toBe(r2)
  })
})
