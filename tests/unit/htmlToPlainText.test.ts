import { describe, expect, it } from 'vitest'
import { htmlToPlainText } from '@/lib/viewMappers/htmlToPlainText'

describe('htmlToPlainText', () => {
  it('returns an empty string for empty input', () => {
    expect(htmlToPlainText('')).toBe('')
  })

  it('returns an empty string for whitespace-only input', () => {
    expect(htmlToPlainText('   \n\t ')).toBe('')
  })

  it('returns trimmed plain text unchanged when there are no tags', () => {
    expect(htmlToPlainText('  hello world  ')).toBe('hello world')
  })

  it('strips a single HTML tag pair', () => {
    expect(htmlToPlainText('<p>Hello</p>')).toBe('Hello')
  })

  it('strips nested tags and collapses whitespace', () => {
    const raw = '<div><p>Line one</p>\n  <p>Line two</p></div>'
    expect(htmlToPlainText(raw)).toBe('Line one Line two')
  })

  it('decodes HTML entities via the DOM parser', () => {
    expect(htmlToPlainText('<span>A &amp; B</span>')).toBe('A & B')
  })

  it('collapses runs of whitespace inside markup', () => {
    expect(htmlToPlainText('<b>foo</b>    <i>bar</i>')).toBe('foo bar')
  })
})
