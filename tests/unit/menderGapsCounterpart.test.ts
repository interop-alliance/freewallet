// @vitest-environment node
/**
 * The gap allowlist's doc counterpart: ARCHITECTURE.md's open-gaps
 * paragraph (the three bullet lists under "Ceremony inventory") names one
 * invariant id per bullet in backticks, and that id set equals the declared
 * gaps' id set under the compound key, one bullet per row. The allowlist
 * only shrinks: retiring a row takes a review that also rewrites the
 * ARCHITECTURE.md bullet.
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { INVARIANT_IDS, type InvariantId } from '@interop/wallet-core/menders'
import { MENDER_GAPS } from '../../src/session/menders/index.js'

/**
 * The bullets of the open-gaps paragraph, each joined to one string.
 */
function openGapBullets(): string[] {
  const doc = readFileSync(
    path.resolve(__dirname, '..', '..', 'ARCHITECTURE.md'),
    'utf8'
  )
  const start = doc.indexOf('The open gaps come in three classes')
  const end = doc.indexOf('One bound is not an open gap', start)
  expect(start).toBeGreaterThan(-1)
  expect(end).toBeGreaterThan(start)
  const bullets: string[] = []
  for (const line of doc.slice(start, end).split('\n')) {
    if (line.startsWith('- ')) {
      bullets.push(line.slice(2))
    } else if (line.startsWith('  ') && bullets.length > 0) {
      bullets[bullets.length - 1] += ` ${line.trim()}`
    }
  }
  return bullets
}

function namedId(bullet: string): InvariantId | undefined {
  const known = new Set<string>(INVARIANT_IDS)
  const ids = [...bullet.matchAll(/`([a-z0-9-]+)`/g)]
    .map(match => match[1]!)
    .filter(token => known.has(token))
  expect(ids.length, bullet).toBe(1)
  return ids[0] as InvariantId
}

describe('the open-gaps paragraph', () => {
  it('names one declared gap per bullet, and the allowlist names nothing else', () => {
    const bullets = openGapBullets()
    const docIds = bullets.map(namedId).sort()
    const declaredIds = MENDER_GAPS.map(gap => gap.invariant).sort()
    expect(docIds).toEqual(declaredIds)
  })
})
