/**
 * The ceremony-tail report's consumer (`src/session/menders/ceremonyTail.ts`).
 * A ceremony-tail entry carries no registration, so no login chain's runner
 * ever sees it; this helper is what applies the runner's warn discipline to
 * the entries a ceremony reports from its own call site.
 */
import { describe, expect, it } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
import type { LogEvent } from '@interop/logger'

import { reportCeremonyTail } from '@/session/menders/ceremonyTail'
import { freewalletMenderRegistry } from '@/session/menders'

const ANNEX_INVENTORY = 'retired-credential-leaves-no-annex-inventory' as const
const GENERATION_DELEGATION = 'generation-delegation-is-current' as const

/**
 * Runs one report with a sink attached and hands back what it dispatched.
 *
 * @param entries {Array<object>}   the report to hand the consumer
 * @returns {Array<LogEvent>}
 */
function reported(entries: Parameters<typeof reportCeremonyTail>[0]['mended']) {
  const capture = captureSink()
  const remove = addSink(capture.sink)
  try {
    reportCeremonyTail({ mended: entries })
  } finally {
    remove()
  }
  return capture.events.filter(
    (event: LogEvent) => event.ns === 'fw:session:registry'
  )
}

describe('reportCeremonyTail', () => {
  it("warns with the invariant's declared warn on a failure", () => {
    const events = reported([
      {
        invariant: ANNEX_INVENTORY,
        ceremonies: ['unlock-credential-rotation'],
        outcome: 'failed',
        detail: { action: 'skipped' },
        errorName: 'TypeError'
      }
    ])

    expect(events).toHaveLength(1)
    const [event] = events
    expect(event?.level).toBe('warn')
    // The declared string, read from the registry rather than restated here:
    // the whole point is that a tail entry and a chain entry warn alike.
    expect(event?.msg).toBe(
      freewalletMenderRegistry.byId(ANNEX_INVENTORY)?.warn
    )
    expect(event?.data).toMatchObject({
      invariant: ANNEX_INVENTORY,
      trigger: 'ceremony-tail',
      outcome: 'failed',
      errorName: 'TypeError',
      detail: { action: 'skipped' }
    })
  })

  it('warns on a refusal, carrying its reason', () => {
    const events = reported([
      {
        invariant: GENERATION_DELEGATION,
        ceremonies: ['client-revocation'],
        outcome: 'refused',
        detail: { reason: 'no-pointer' }
      }
    ])

    expect(events).toHaveLength(1)
    expect(events[0]?.level).toBe('warn')
    expect(events[0]?.msg).toBe(
      freewalletMenderRegistry.byId(GENERATION_DELEGATION)?.warn
    )
    expect(events[0]?.data).toMatchObject({
      outcome: 'refused',
      detail: { reason: 'no-pointer' }
    })
  })

  it('reports a clean or no-op entry at info', () => {
    const events = reported([
      {
        invariant: GENERATION_DELEGATION,
        ceremonies: ['client-revocation'],
        outcome: 'clean'
      },
      {
        invariant: ANNEX_INVENTORY,
        ceremonies: ['unlock-credential-rotation'],
        outcome: 'noop'
      }
    ])

    expect(events.map((event: LogEvent) => event.level)).toEqual([
      'info',
      'info'
    ])
    expect(events[0]?.data).toMatchObject({
      invariant: GENERATION_DELEGATION,
      trigger: 'ceremony-tail',
      outcome: 'clean'
    })
  })

  it('reports every entry of a multi-entry report, in order', () => {
    const events = reported([
      {
        invariant: GENERATION_DELEGATION,
        ceremonies: ['client-revocation'],
        outcome: 'noop'
      },
      {
        invariant: ANNEX_INVENTORY,
        ceremonies: ['unlock-credential-rotation'],
        outcome: 'failed'
      }
    ])

    expect(events.map((event: LogEvent) => event.level)).toEqual([
      'info',
      'warn'
    ])
  })
})
