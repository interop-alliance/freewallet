import { describe, expect, it } from 'vitest'
import { initials } from '@/lib/viewMappers/initials'

describe('initials', () => {
  it('returns two uppercase initials for a two-word name', () => {
    expect(initials('Alice Bob')).toBe('AB')
  })

  it('returns a single initial for a one-word name', () => {
    expect(initials('Alice')).toBe('A')
  })

  it('uses only the first two words for longer names', () => {
    expect(initials('alice bob carol dave')).toBe('AB')
  })

  it('uppercases lowercase names', () => {
    expect(initials('john doe')).toBe('JD')
  })

  it('collapses multiple spaces between words', () => {
    expect(initials('Alice    Bob')).toBe('AB')
  })

  it('returns a question mark for an empty string', () => {
    expect(initials('')).toBe('?')
  })
})
