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
 * guarded localStorage READ; nothing here writes stored state, so the
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
import { setLogger, stageNotifier } from '@interop/wallet-core'
import type { StageNotifier } from '@interop/wallet-core'

export { createLogger }

/**
 * A per-stage stopwatch for a ceremony: each `mark(stage)` logs one info
 * event carrying the stage name, the milliseconds since the previous mark
 * (or since the timer was created), and the running total. Filter on
 * `event: 'Stage timing'` to pull a ceremony's whole profile out of the
 * ring buffer or the NDJSON file.
 *
 * The figure is the span that ENDED at the mark, so a mark names its stage
 * truthfully only when it sits at that stage's end AND the stage before it
 * is marked too. An unmarked boundary silently attaches its whole span to
 * the next name: two marks around a nine-stage ceremony reported two
 * plausible, wrong figures until FW-385. Mark every boundary, or accept
 * that a name covers everything since the previous one.
 *
 * A delta cannot measure a stage that OVERLAPS its neighbour: two
 * concurrent stages double-count and their figures sum past the elapsed
 * time. A concurrent stage therefore reports a span of its own through
 * {@link stageSpan}, and its mark here names only the join where the
 * ceremony waited for it.
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
 * Times one stage from an explicit start rather than from the previous mark:
 * called where the stage BEGINS, it returns the closer that logs the span it
 * measured. What a concurrent stage needs, since a delta between marks
 * measures the wrong thing once two stages overlap (see {@link stageTimer}).
 *
 * The event is `Stage span` rather than `Stage timing`, so a ceremony's
 * profile stays the sum of its deltas and an overlapping stage's real cost
 * is still readable beside it.
 *
 * @param options {object}
 * @param options.log {Logger}   the calling module's namespaced logger
 * @param options.ceremony {string}   a label naming the timed sequence
 * @param options.stage {string}   the stage being measured
 * @returns {() => void}   call at the stage's end
 */
export function stageSpan({
  log,
  ceremony,
  stage
}: {
  log: Logger
  ceremony: string
  stage: string
}): () => void {
  const startedAt = performance.now()
  return function endSpan(): void {
    log.info('Stage span', {
      ceremony,
      stage,
      ms: Math.round(performance.now() - startedAt)
    })
  }
}

/**
 * Composes a stage timer with an optional observational stage notifier (the
 * lobby page's progress feed) into the single `mark` a ceremony calls at
 * every stage boundary. The notifier half is wallet-core's own
 * `stageNotifier`, the adapter its ceremonies already wrap a supplied
 * `onStage` in: an absent notifier becomes a no-op and a throwing one is
 * swallowed with a warn, so telemetry can never tear the ceremony it
 * watches. Composing it rather than repeating the swallow here is what
 * keeps one notifier from being guarded twice at two different levels.
 *
 * @param options {object}
 * @param options.log {Logger}   the calling module's namespaced logger
 * @param options.ceremony {string}   a label naming the timed sequence
 * @param [options.onStage] {StageNotifier}
 * @returns {(stage: string) => void}
 */
export function stageMarker({
  log,
  ceremony,
  onStage
}: {
  log: Logger
  ceremony: string
  onStage?: StageNotifier
}): (stage: string) => void {
  const time = stageTimer({ log, ceremony })
  const notify = stageNotifier(onStage)
  return function mark(stage: string): void {
    time(stage)
    notify(stage)
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
