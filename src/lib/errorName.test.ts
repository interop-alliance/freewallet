/**
 * The cross-package error rule: an error class that crosses a package
 * boundary (`@interop/*`) is matched on its `name`, through wallet-core's
 * `errorNameOf`, and not by `instanceof`. A linked checkout or a duplicate
 * through the dependency tree gives the throwing package a class object the
 * app never imported, so an `instanceof` check silently misses and takes the
 * wrong branch (a rebase-able conflict becomes a hard error, a try-again
 * refusal becomes a generic failure). Subclasses override `name`, so a site
 * that must catch a subtype names every concrete subclass (`isPreconditionFailed`
 * in `src/lib/storageErrors.ts` is the pattern).
 *
 * This test IS the guard: every `instanceof <Name>` in `src/` must name a
 * class this app defines, or a platform built-in. A new `instanceof` against
 * an imported class fails it. Errors defined in this app keep `instanceof`.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const platformClasses = new Set([
  'Error',
  'TypeError',
  'RangeError',
  'SyntaxError',
  'DOMException',
  'Uint8Array',
  'ArrayBuffer',
  'Blob',
  'File',
  'Date',
  'Promise',
  'Response',
  'URL',
  'HTMLElement',
  'HTMLInputElement',
  'Element',
  'Node',
  'Map',
  'Set',
  'RegExp'
])

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      out.push(...sourceFiles(full))
    } else if (/\.(ts|tsx)$/.test(entry) && !/\.test\.tsx?$/.test(entry)) {
      out.push(full)
    }
  }
  return out
}

describe('cross-package errors are matched on name', () => {
  it('every instanceof in src/ names a class this app defines', () => {
    const files = sourceFiles(join(__dirname, '..'))
    const localClasses = new Set<string>()
    for (const file of files) {
      for (const match of readFileSync(file, 'utf8').matchAll(
        /\bclass\s+([A-Za-z0-9_]+)/g
      )) {
        localClasses.add(match[1])
      }
    }
    const offenders: string[] = []
    for (const file of files) {
      const lines = readFileSync(file, 'utf8').split('\n')
      lines.forEach((line, index) => {
        // Prose mentions of the word carry no operand.
        if (/^\s*(\/\/|\*|\/\*)/.test(line)) {
          return
        }
        for (const match of line.matchAll(/\binstanceof\s+([A-Za-z0-9_.]+)/g)) {
          const name = match[1]
          if (platformClasses.has(name) || localClasses.has(name)) {
            continue
          }
          offenders.push(`${file}:${index + 1}: instanceof ${name}`)
        }
      })
    }
    expect(offenders).toEqual([])
  })
})
