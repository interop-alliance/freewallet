/**
 * The dead-pointer prompt's state, shared by every login surface that
 * renders it: the refusal carrying this credential's sign-in data removal
 * (or none), the removal run on the user's accept, and its busy flag. A
 * page takes the offer from a failed attempt's error, clears it when the
 * next attempt starts, and renders the outcome its own way. Declining is
 * simply not clicking: the record stays, and a later attempt offers this
 * again.
 */
import { useState } from 'react'
import { DeadAccountPointerError } from '@/session/deadAccountPointer'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:ui:dead-pointer')

/**
 * React hook for the dead-pointer removal offer.
 *
 * @returns {object}   `deadPointer` (the refusal, or `null`), `offerFrom`
 *   (takes the offer from an attempt's error, clearing it on any other),
 *   `clear`, `busy`, and `remove`, which runs the refusal's removal and
 *   resolves to its outcome, or to `null` on a failure (logged here)
 */
export function useDeadPointerRemoval() {
  const [deadPointer, setDeadPointer] =
    useState<DeadAccountPointerError | null>(null)
  const [busy, setBusy] = useState(false)

  function offerFrom(err: unknown) {
    setDeadPointer(err instanceof DeadAccountPointerError ? err : null)
  }

  function clear() {
    setDeadPointer(null)
  }

  async function remove(): Promise<{ unlockSpaceDeleted: boolean } | null> {
    if (!deadPointer || busy) {
      return null
    }
    setBusy(true)
    try {
      const outcome = await deadPointer.removeSignInData()
      setDeadPointer(null)
      return outcome
    } catch (err) {
      log.error('Removing the dead pointer sign-in data failed', { err })
      return null
    } finally {
      setBusy(false)
    }
  }

  return { deadPointer, offerFrom, clear, busy, remove }
}
