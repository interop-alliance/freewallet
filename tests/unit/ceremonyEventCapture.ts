/**
 * A unit-test capture of the ceremony event channel: a capture sink on
 * `@interop/logger` with the debug filter on for freewallet's namespaces, so
 * stage events and `noop` outcomes (both debug) are dispatched rather than
 * silently dropped, and readers over the three event kinds. The readers run
 * the e2e fixture's own filters (`tests/shared/ceremonyEventLines.ts`).
 */
import { expect } from 'vitest'
import { addSink, captureSink, configure } from '@interop/logger'
import type { LogEvent } from '@interop/logger'
import {
  CEREMONY_MENDER_MSG,
  CEREMONY_OUTCOME_MSG,
  CEREMONY_STAGE_MSG,
  menderEvents,
  outcomeEvents,
  stageEvents
} from '../shared/ceremonyEventLines'

/**
 * The three event messages, for picking the channel's events out of
 * everything else the capture holds.
 */
const CEREMONY_MSGS = new Set([
  CEREMONY_STAGE_MSG,
  CEREMONY_OUTCOME_MSG,
  CEREMONY_MENDER_MSG
])

/**
 * Starts a capture. Call `stop()` in the test's cleanup.
 *
 * @returns {object}   the captured events, the readers, and `stop`
 */
export function captureCeremonyEvents(): {
  events: LogEvent[]
  stages: (ceremony: string) => LogEvent[]
  stageNames: (ceremony: string) => string[]
  outcomes: (ceremony: string) => LogEvent[]
  soleOutcome: (ceremony: string) => LogEvent
  menders: (invariant?: string) => LogEvent[]
  serialized: () => string
  stop: () => void
} {
  configure({ filter: 'fw:*' })
  const capture = captureSink()
  const remove = addSink(capture.sink)
  const stages = (ceremony: string) =>
    stageEvents({ lines: capture.events, ceremony })
  const outcomes = (ceremony: string) =>
    outcomeEvents({ lines: capture.events, ceremony })
  return {
    events: capture.events,
    stages,
    // The stage ids of one ceremony's stage events, in emission order.
    stageNames: ceremony =>
      stages(ceremony).map(event => (event.data as { stage: string }).stage),
    outcomes,
    // The one outcome event of a ceremony, asserting there is exactly one.
    soleOutcome: ceremony => {
      const found = outcomes(ceremony)
      expect(found).toHaveLength(1)
      return found[0]!
    },
    menders: invariant => menderEvents({ lines: capture.events, invariant }),
    // Every ceremony event captured, serialized, for the redaction checks.
    serialized: () =>
      JSON.stringify(
        capture.events.filter(event => CEREMONY_MSGS.has(event.msg))
      ),
    stop: () => {
      remove()
      configure({ filter: null })
    }
  }
}
