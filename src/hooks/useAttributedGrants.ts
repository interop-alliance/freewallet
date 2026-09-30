/**
 * The consent screen's resolved grants, shared by the CHAPI get popup and the
 * interaction-URL request page: the first resolution pass shown at once, then
 * replaced by the second pass with the existing collections' attribution read
 * in (`attributeExistingCollections`). A caller that has already awaited the
 * attribution pass (the interaction-URL page, whose refusal needs it) shows
 * the result directly. A later call supersedes an earlier pass, so a
 * superseded pass's late result is dropped rather than written over a newer
 * one.
 */

import { useCallback, useRef, useState } from 'react'
import { attributeExistingCollections } from '@/lib/walletRequest/attributeExistingCollections'
import { createLogger } from '@/lib/log'
import type {
  resolveGrants,
  ResolvedGrant
} from '@/lib/walletRequest/processZcaps'
import type { Session } from '@/types/auth'

const log = createLogger('fw:request:attribution')

/**
 * @returns {{ grants: ResolvedGrant[], attributeGrants: (options: {
 *   resolution: Parameters<typeof resolveGrants>[0], grants:
 *   ResolvedGrant[], storage: Session['storage'], appKeys?:
 *   Awaited<ReturnType<Session['storage']['listAppKeys']>> }) => void,
 *   showGrants: (grants: ResolvedGrant[]) => void }}
 *   the grants to render; the call that shows a first pass's grants and
 *   starts the attribution pass behind them, handed the caller's app-key
 *   listing when it already holds one; and the call that shows grants
 *   already attributed, with no pass behind them
 */
export function useAttributedGrants(): {
  grants: ResolvedGrant[]
  attributeGrants: (options: {
    resolution: Parameters<typeof resolveGrants>[0]
    grants: ResolvedGrant[]
    storage: Session['storage']
    appKeys?: Awaited<ReturnType<Session['storage']['listAppKeys']>>
  }) => void
  showGrants: (grants: ResolvedGrant[]) => void
} {
  const [grants, setGrants] = useState<ResolvedGrant[]>([])
  const runRef = useRef(0)

  const attributeGrants = useCallback(
    ({
      resolution,
      grants: firstPass,
      storage,
      appKeys
    }: {
      resolution: Parameters<typeof resolveGrants>[0]
      grants: ResolvedGrant[]
      storage: Session['storage']
      appKeys?: Awaited<ReturnType<Session['storage']['listAppKeys']>>
    }) => {
      const run = ++runRef.current
      setGrants(firstPass)
      attributeExistingCollections({
        resolution,
        grants: firstPass,
        storage,
        appKeys
      })
        .then(attributed => {
          if (attributed && runRef.current === run) {
            setGrants(attributed)
          }
        })
        .catch((err: unknown) => {
          log.warn('Could not attribute the existing collections', { err })
        })
    },
    []
  )

  const showGrants = useCallback((attributed: ResolvedGrant[]) => {
    // Supersedes any pass still in flight.
    runRef.current++
    setGrants(attributed)
  }, [])

  return { grants, attributeGrants, showGrants }
}
