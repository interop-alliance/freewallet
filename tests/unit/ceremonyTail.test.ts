/**
 * The ceremony-tail report's consumer (`src/session/menders/ceremonyTail.ts`).
 * A ceremony-tail entry carries no registration, so no login chain's runner
 * ever sees it; this helper is what applies the runner's warn discipline to
 * the entries a ceremony reports from its own call site, and what emits each
 * entry's `'ceremony mender'` event.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { addSink, captureSink, configure } from '@interop/logger'
import type { LogEvent } from '@interop/logger'

import { reportCeremonyTail } from '@/session/menders/ceremonyTail'
import { freewalletMenderRegistry } from '@/session/menders'
import { CEREMONY_MENDER_MSG, menderEvents } from '../shared/ceremonyEventLines'

const ANNEX_INVENTORY = 'retired-credential-leaves-no-annex-inventory' as const
const GENERATION_DELEGATION = 'generation-delegation-is-current' as const

/**
 * Runs one report with a sink attached and hands back what it dispatched.
 *
 * @param options {object}
 * @param options.ceremony {string}   the ceremony that ran
 * @param options.mended {Array<object>}   the report to hand the consumer
 * @returns {Array<LogEvent>}
 */
function reported({
  ceremony,
  mended
}: Parameters<typeof reportCeremonyTail>[0]): LogEvent[] {
  const capture = captureSink()
  const remove = addSink(capture.sink)
  try {
    reportCeremonyTail({ ceremony, mended })
  } finally {
    remove()
  }
  return capture.events.filter(
    (event: LogEvent) => event.ns === 'fw:session:registry'
  )
}

describe('reportCeremonyTail', () => {
  afterEach(() => {
    configure({ filter: null })
  })

  it("warns with the invariant's declared warn on a failure", () => {
    const events = reported({
      ceremony: 'unlock-credential-rotation',
      mended: [
        {
          invariant: ANNEX_INVENTORY,
          ceremonies: ['unlock-credential-rotation'],
          outcome: 'failed',
          detail: { action: 'skipped' },
          errorName: 'TypeError'
        }
      ]
    })

    const declared = events.filter(event => event.msg !== CEREMONY_MENDER_MSG)
    expect(declared).toHaveLength(1)
    const [event] = declared
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

  it('emits one mender event per entry, matching the entry reported', () => {
    const events = reported({
      ceremony: 'unlock-credential-rotation',
      mended: [
        {
          invariant: ANNEX_INVENTORY,
          ceremonies: ['unlock-credential-rotation'],
          outcome: 'failed',
          detail: { action: 'skipped' },
          errorName: 'TypeError'
        }
      ]
    })

    const [event, ...rest] = menderEvents({ lines: events })
    expect(rest).toEqual([])
    expect(event?.level).toBe('error')
    expect(event?.data).toEqual({
      invariant: ANNEX_INVENTORY,
      outcome: 'failed',
      errorName: 'TypeError',
      action: 'skipped',
      ceremony: 'unlock-credential-rotation'
    })
    // The tail site holds no emitter of the ceremony's run, and the entry's
    // `ceremonies` array is not carried.
    expect(event?.data).not.toHaveProperty('run')
    expect(event?.data).not.toHaveProperty('ceremonies')
  })

  it('warns on a refusal, carrying its reason', () => {
    const events = reported({
      ceremony: 'client-revocation',
      mended: [
        {
          invariant: GENERATION_DELEGATION,
          ceremonies: ['client-revocation'],
          outcome: 'refused',
          detail: { reason: 'no-pointer' }
        }
      ]
    })

    expect(events.map(event => event.level)).toEqual(['warn', 'warn'])
    expect(events[0]?.msg).toBe(
      freewalletMenderRegistry.byId(GENERATION_DELEGATION)?.warn
    )
    expect(events[0]?.data).toMatchObject({
      outcome: 'refused',
      detail: { reason: 'no-pointer' }
    })
    expect(menderEvents({ lines: events })[0]?.data).toMatchObject({
      invariant: GENERATION_DELEGATION,
      outcome: 'refused',
      reason: 'no-pointer',
      ceremony: 'client-revocation'
    })
  })

  it('reports a clean entry through its mender event alone, at info', () => {
    const events = reported({
      ceremony: 'client-revocation',
      mended: [
        {
          invariant: GENERATION_DELEGATION,
          ceremonies: ['client-revocation'],
          outcome: 'clean'
        }
      ]
    })

    // The former info line is replaced by the event.
    expect(events).toHaveLength(1)
    expect(events[0]?.msg).toBe(CEREMONY_MENDER_MSG)
    expect(events[0]?.level).toBe('info')
    expect(events[0]?.data).toEqual({
      invariant: GENERATION_DELEGATION,
      outcome: 'clean',
      ceremony: 'client-revocation'
    })
  })

  it('emits a no-op entry at debug, seen only with the filter on', () => {
    const mended = [
      {
        invariant: ANNEX_INVENTORY,
        ceremonies: ['unlock-credential-rotation' as const],
        outcome: 'noop' as const
      }
    ]
    expect(
      reported({ ceremony: 'unlock-credential-rotation', mended })
    ).toEqual([])

    configure({ filter: 'fw:*' })
    const events = reported({ ceremony: 'unlock-credential-rotation', mended })
    expect(events).toHaveLength(1)
    expect(events[0]?.level).toBe('debug')
    expect(events[0]?.data).toMatchObject({
      invariant: ANNEX_INVENTORY,
      outcome: 'noop'
    })
  })

  it('reports every entry of a multi-entry report, in order', () => {
    const events = reported({
      ceremony: 'unlock-credential-rotation',
      mended: [
        {
          invariant: GENERATION_DELEGATION,
          ceremonies: ['unlock-credential-rotation'],
          outcome: 'clean'
        },
        {
          invariant: ANNEX_INVENTORY,
          ceremonies: ['unlock-credential-rotation'],
          outcome: 'failed'
        }
      ]
    })

    expect(
      menderEvents({ lines: events }).map(event => [
        event.level,
        (event.data as { invariant: string }).invariant
      ])
    ).toEqual([
      ['info', GENERATION_DELEGATION],
      ['error', ANNEX_INVENTORY]
    ])
  })
})
