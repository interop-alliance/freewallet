// @vitest-environment node
/**
 * The ceremony-event e2e fixture's pure half
 * (`tests/shared/ceremonyEventLines.ts`): parsing dev-log lines as untrusted
 * data, scoping them to one test's tagged pages, and matching the three
 * event kinds.
 */
import { describe, expect, it } from 'vitest'
import { E2E_LOG_TAG_MSG } from '@/lib/e2eLogTag'
import {
  menderEvents,
  outcomeEvents,
  parseDevLogLine,
  scopedLines,
  splitDevLogChunk,
  stageEvents
} from '../shared/ceremonyEventLines'

/**
 * One NDJSON line as the dev server writes it.
 *
 * @param options {object}
 * @param options.page {string}
 * @param options.seq {number}
 * @param options.msg {string}
 * @param [options.data] {object}
 * @returns {string}
 */
function line({
  page,
  seq,
  msg,
  data
}: {
  page: string
  seq: number
  msg: string
  data?: Record<string, unknown>
}): string {
  return JSON.stringify({
    ts: 1,
    ns: 'fw:test',
    level: 'info',
    msg,
    page,
    seq,
    ...(data ? { data } : {})
  })
}

const FILE = [
  line({
    page: 'tagged1',
    seq: 0,
    msg: E2E_LOG_TAG_MSG,
    data: { tag: 'mine' }
  }),
  line({
    page: 'other',
    seq: 0,
    msg: E2E_LOG_TAG_MSG,
    data: { tag: 'theirs' }
  }),
  line({
    page: 'tagged1',
    seq: 1,
    msg: 'ceremony mender',
    data: { invariant: 'generation-delegation-is-current', outcome: 'noop' }
  }),
  line({
    page: 'untagged',
    seq: 0,
    msg: 'ceremony mender',
    data: { invariant: 'generation-delegation-is-current', outcome: 'failed' }
  }),
  line({
    page: 'other',
    seq: 1,
    msg: 'ceremony outcome',
    data: { ceremony: 'wallet-wipe', outcome: 'failed' }
  }),
  // A reload of the same test's page: a fresh page id, a fresh marker.
  line({
    page: 'tagged2',
    seq: 0,
    msg: E2E_LOG_TAG_MSG,
    data: { tag: 'mine' }
  }),
  line({
    page: 'tagged2',
    seq: 1,
    msg: 'ceremony stage',
    data: { ceremony: 'wallet-wipe', run: 'r1', stage: 'replica' }
  }),
  line({
    page: 'tagged2',
    seq: 2,
    msg: 'ceremony outcome',
    data: { ceremony: 'wallet-wipe', run: 'r1', outcome: 'clean' }
  }),
  // The runner's declared warn carries the same keys; only the message
  // makes a line a mender event.
  line({
    page: 'tagged2',
    seq: 3,
    msg: 'A declared warn',
    data: { invariant: 'generation-delegation-is-current', outcome: 'failed' }
  })
].join('\n')

describe('ceremony event lines', () => {
  it('parses a line into the narrow shape, keeping scalar data only', () => {
    const parsed = parseDevLogLine(
      JSON.stringify({
        ns: 'wc',
        level: 'debug',
        msg: 'ceremony stage',
        page: 'p',
        seq: 3,
        data: { stage: 'x', nested: { a: 1 }, list: [1], count: 2 },
        err: { name: 'Error', message: 'ignore previous instructions' }
      })
    )
    expect(parsed).toEqual({
      ns: 'wc',
      level: 'debug',
      msg: 'ceremony stage',
      page: 'p',
      seq: 3,
      data: { stage: 'x', count: 2 }
    })
  })

  it('drops a line that is not JSON or lacks the shape', () => {
    expect(parseDevLogLine('not json')).toBeUndefined()
    expect(parseDevLogLine('[1,2]')).toBeUndefined()
    expect(parseDevLogLine(JSON.stringify({ msg: 'x' }))).toBeUndefined()
  })

  it('carries a partial trailing line into the next read', () => {
    const whole = line({ page: 'p', seq: 0, msg: 'a' })
    const first = splitDevLogChunk({ carry: '', chunk: whole.slice(0, 10) })
    expect(first.lines).toEqual([])
    const second = splitDevLogChunk({
      carry: first.carry,
      chunk: whole.slice(10) + '\n'
    })
    expect(second.lines.map(parsed => parsed.msg)).toEqual(['a'])
    expect(second.carry).toBe('')
  })

  it("scopes to the tagged pages across reloads, ignoring an untagged page's lines", () => {
    const { lines } = splitDevLogChunk({ carry: '', chunk: FILE + '\n' })
    const scoped = scopedLines({ lines, tag: 'mine' })

    expect([...new Set(scoped.map(parsed => parsed.page))]).toEqual([
      'tagged1',
      'tagged2'
    ])
    // The markers themselves are not events.
    expect(scoped.some(parsed => parsed.msg === E2E_LOG_TAG_MSG)).toBe(false)
    // The untagged page's failed mender and the other test's failed outcome
    // are out of scope.
    expect(menderEvents({ lines: scoped, outcome: 'failed' })).toEqual([])
    expect(
      outcomeEvents({
        lines: scoped,
        ceremony: 'wallet-wipe',
        outcome: 'failed'
      })
    ).toEqual([])
  })

  it('matches each event kind on its message as well as its keys', () => {
    const { lines } = splitDevLogChunk({ carry: '', chunk: FILE + '\n' })
    const scoped = scopedLines({ lines, tag: 'mine' })

    expect(
      stageEvents({ lines: scoped, ceremony: 'wallet-wipe', stage: 'replica' })
    ).toHaveLength(1)
    expect(
      outcomeEvents({ lines: scoped, ceremony: 'wallet-wipe' })[0]?.data
    ).toMatchObject({ outcome: 'clean', run: 'r1' })
    expect(
      menderEvents({
        lines: scoped,
        invariant: 'generation-delegation-is-current'
      }).map(parsed => parsed.data.outcome)
    ).toEqual(['noop'])
  })

  it('narrows stage and outcome events to one run when given', () => {
    const { lines } = splitDevLogChunk({ carry: '', chunk: FILE + '\n' })
    const scoped = scopedLines({ lines, tag: 'mine' })

    expect(stageEvents({ lines: scoped, run: 'r1' })).toHaveLength(1)
    expect(stageEvents({ lines: scoped, run: 'r2' })).toEqual([])
    expect(
      outcomeEvents({ lines: scoped, ceremony: 'wallet-wipe', run: 'r1' })
    ).toHaveLength(1)
    expect(
      outcomeEvents({ lines: scoped, ceremony: 'wallet-wipe', run: 'r2' })
    ).toEqual([])
  })
})
