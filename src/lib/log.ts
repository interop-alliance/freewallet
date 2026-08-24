/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * The app's logging seam over `@interop/logger`. Every module creates its
 * namespaced logger through this module's re-exported {@link createLogger},
 * so importing it anywhere -- the app shell and the CHAPI popup pages
 * alike, which sit outside the shell -- runs the bootstrap wiring exactly
 * once: wallet-core's `setLogger`, and in dev builds the NDJSON dev sink
 * plus the ring buffer behind the `window.__fwLog` devtools handle.
 *
 * The dev wiring is gated on `import.meta.env.MODE === 'development'`,
 * never bare `DEV` (true under vitest, which would start flush timers and
 * POST batches inside unit tests). The filter source is the package's own
 * guarded localStorage READ; nothing here writes durable state, so the
 * module is safe in a transient session.
 */
import {
  addSink,
  createLogger,
  ndjsonSink,
  ringBufferSink,
  setFilter
} from '@interop/logger'
import type { Logger } from '@interop/logger'
import { setLogger } from '@interop/wallet-core'

export { createLogger }

/**
 * A per-stage stopwatch for a ceremony: each `mark(stage)` logs one info
 * event carrying the stage name, the milliseconds since the previous mark
 * (or since the timer was created), and the running total. Filter on
 * `event: 'Stage timing'` to pull a ceremony's whole profile out of the
 * ring buffer or the NDJSON file.
 *
 * @param options {object}
 * @param options.log {Logger}   the calling module's namespaced logger
 * @param options.ceremony {string}   a label naming the timed sequence
 * @returns {(stage: string) => void}
 */
export function stageTimer({
  log,
  ceremony
}: {
  log: Logger
  ceremony: string
}): (stage: string) => void {
  const startedAt = performance.now()
  let previous = startedAt
  return function mark(stage: string): void {
    const now = performance.now()
    log.info('Stage timing', {
      ceremony,
      stage,
      ms: Math.round(now - previous),
      totalMs: Math.round(now - startedAt)
    })
    previous = now
  }
}

/**
 * HMR re-evaluates this module with a fresh module scope, so the
 * wired-once guard rides globalThis: sinks must never double-install.
 */
const WIRED_FLAG = '__fwLogWired'

function wireOnce(): void {
  const host = globalThis as Record<string, unknown>
  if (host[WIRED_FLAG] === true) {
    return
  }
  host[WIRED_FLAG] = true
  setLogger(createLogger('wc'))
  if (import.meta.env.MODE === 'development') {
    addSink(ndjsonSink({ url: '/__interop-logger' }))
    const { sink, snapshot, clear } = ringBufferSink()
    addSink(sink)
    host.__fwLog = { snapshot, setFilter, clear }
  }
}

wireOnce()
