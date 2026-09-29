/**
 * The pure half of the ceremony-event e2e fixture (`ceremonyEvents.ts`):
 * parsing the dev server's NDJSON log file, scoping its lines to the pages
 * one test tagged, and matching the three ceremony event kinds.
 *
 * Every line is untrusted data. Any same-machine process can append to the
 * file, and `data` and `err` carry server-owned text, so a line is parsed
 * into a narrow shape, a line that does not fit is dropped, and nothing in
 * one is ever acted on beyond the match.
 *
 * The three event filters are generic over any line carrying a `msg` and a
 * `data` object, so the unit-test capture (`tests/unit/ceremonyEventCapture.ts`)
 * runs the same matching over `@interop/logger`'s `LogEvent`.
 */
import { E2E_LOG_TAG_MSG } from '@/lib/e2eLogTag'

/**
 * The localStorage key `@interop/logger` reads its debug filter from, and
 * the filter the fixture sets there before a page's first navigation, so
 * stage events and `noop` mender entries (both debug) reach the file.
 */
export const LOGGER_FILTER_KEY = 'interop:logger'
export const LOGGER_FILTER = 'fw:*,wc'

/**
 * The three event messages the channel emits.
 */
export const CEREMONY_STAGE_MSG = 'ceremony stage'
export const CEREMONY_OUTCOME_MSG = 'ceremony outcome'
export const CEREMONY_MENDER_MSG = 'ceremony mender'

/**
 * One parsed dev-log line: the fields the fixture reads, with `data` kept
 * as scalars only.
 */
export interface DevLogLine {
  ns: string
  level: string
  msg: string
  page: string
  seq: number
  data: Record<string, string | number | boolean>
}

/**
 * Parses one NDJSON line into a {@link DevLogLine}, or `undefined` when it is
 * not JSON or lacks the shape. `data` keeps only its scalar members.
 *
 * @param text {string}
 * @returns {DevLogLine | undefined}
 */
export function parseDevLogLine(text: string): DevLogLine | undefined {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    return undefined
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return undefined
  }
  const record = value as Record<string, unknown>
  const { ns, level, msg, page, seq } = record
  if (
    typeof ns !== 'string' ||
    typeof level !== 'string' ||
    typeof msg !== 'string' ||
    typeof page !== 'string' ||
    typeof seq !== 'number'
  ) {
    return undefined
  }
  const data: Record<string, string | number | boolean> = {}
  const raw = record.data
  if (typeof raw === 'object' && raw !== null && !Array.isArray(raw)) {
    for (const [key, member] of Object.entries(raw)) {
      if (
        typeof member === 'string' ||
        typeof member === 'number' ||
        typeof member === 'boolean'
      ) {
        data[key] = member
      }
    }
  }
  return { ns, level, msg, page, seq, data }
}

/**
 * Splits a chunk of the file into complete lines, parsed, and the trailing
 * partial line to carry into the next read.
 *
 * @param options {object}
 * @param options.carry {string}   the partial line the previous read left
 * @param options.chunk {string}   the newly read text
 * @returns {{ lines: DevLogLine[], carry: string }}
 */
export function splitDevLogChunk({
  carry,
  chunk
}: {
  carry: string
  chunk: string
}): { lines: DevLogLine[]; carry: string } {
  const parts = (carry + chunk).split('\n')
  const rest = parts.pop() ?? ''
  const lines: DevLogLine[] = []
  for (const part of parts) {
    const line = parseDevLogLine(part)
    if (line) {
      lines.push(line)
    }
  }
  return { lines, carry: rest }
}

/**
 * The lines one test's tagged pages wrote: the `page` ids whose marker line
 * carries `tag`, across every page and reload, and every line stamped with
 * one of them. The markers themselves are left out.
 *
 * @param options {object}
 * @param options.lines {DevLogLine[]}
 * @param options.tag {string}
 * @returns {DevLogLine[]}
 */
export function scopedLines({
  lines,
  tag
}: {
  lines: DevLogLine[]
  tag: string
}): DevLogLine[] {
  const pages = new Set(
    lines
      .filter(line => line.msg === E2E_LOG_TAG_MSG && line.data.tag === tag)
      .map(line => line.page)
  )
  return lines.filter(
    line => pages.has(line.page) && line.msg !== E2E_LOG_TAG_MSG
  )
}

/**
 * The shape the event filters read: a dev-log line or a captured `LogEvent`.
 */
export interface EventLine {
  msg: string
  data?: unknown
}

/**
 * The line's `data` as a record, empty when it carries none.
 *
 * @param line {EventLine}
 * @returns {Record<string, unknown>}
 */
function dataOf(line: EventLine): Record<string, unknown> {
  return typeof line.data === 'object' && line.data !== null
    ? (line.data as Record<string, unknown>)
    : {}
}

/**
 * The stage events of one ceremony, of one stage and one run when given.
 *
 * @param options {object}
 * @param options.lines {EventLine[]}   scoped lines
 * @param [options.ceremony] {string}
 * @param [options.stage] {string}
 * @param [options.run] {string | number | boolean}
 * @returns {Line[]}
 */
export function stageEvents<Line extends EventLine>({
  lines,
  ceremony,
  stage,
  run
}: {
  lines: Line[]
  ceremony?: string
  stage?: string
  run?: string | number | boolean
}): Line[] {
  return lines.filter(line => {
    const data = dataOf(line)
    return (
      line.msg === CEREMONY_STAGE_MSG &&
      (ceremony === undefined || data.ceremony === ceremony) &&
      (stage === undefined || data.stage === stage) &&
      (run === undefined || data.run === run)
    )
  })
}

/**
 * The outcome events of one ceremony, of one outcome when given.
 *
 * @param options {object}
 * @param options.lines {EventLine[]}   scoped lines
 * @param [options.ceremony] {string}
 * @param [options.outcome] {string}
 * @param [options.run] {string | number | boolean}
 * @returns {Line[]}
 */
export function outcomeEvents<Line extends EventLine>({
  lines,
  ceremony,
  outcome,
  run
}: {
  lines: Line[]
  ceremony?: string
  outcome?: string
  run?: string | number | boolean
}): Line[] {
  return lines.filter(line => {
    const data = dataOf(line)
    return (
      line.msg === CEREMONY_OUTCOME_MSG &&
      (ceremony === undefined || data.ceremony === ceremony) &&
      (outcome === undefined || data.outcome === outcome) &&
      (run === undefined || data.run === run)
    )
  })
}

/**
 * The mender events of one invariant, of one outcome when given. Filtered
 * on the message as well as the keys, since the runner's declared warn and
 * other lines carry `invariant` and `outcome` too.
 *
 * @param options {object}
 * @param options.lines {EventLine[]}   scoped lines
 * @param [options.invariant] {string}
 * @param [options.outcome] {string}
 * @returns {Line[]}
 */
export function menderEvents<Line extends EventLine>({
  lines,
  invariant,
  outcome
}: {
  lines: Line[]
  invariant?: string
  outcome?: string
}): Line[] {
  return lines.filter(line => {
    const data = dataOf(line)
    return (
      line.msg === CEREMONY_MENDER_MSG &&
      (invariant === undefined || data.invariant === invariant) &&
      (outcome === undefined || data.outcome === outcome)
    )
  })
}
