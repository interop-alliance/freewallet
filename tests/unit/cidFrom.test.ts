// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { bufferToBase64Url } from '../../src/lib/cidFrom'

// The content-id derivation (`cidFrom` / `contentCid`) now lives in
// `@interop/was-client/sync` and is covered by that package's own tests; only
// the local `bufferToBase64Url` byte-encoding helper remains here.
describe('bufferToBase64Url', () => {
  it('converts a known buffer to the correct base64url string', () => {
    // [0, 255, 128] -> standard base64 "AP+A" -> url-safe "AP-A"
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

  it('accepts a Uint8Array directly and matches its ArrayBuffer', () => {
    const bytes = new Uint8Array([0, 255, 128])
    expect(bufferToBase64Url(bytes)).toBe('AP-A')
    expect(bufferToBase64Url(bytes)).toBe(bufferToBase64Url(bytes.buffer))
  })
})
