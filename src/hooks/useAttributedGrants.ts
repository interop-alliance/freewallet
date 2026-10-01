/**
 * The consent screen's resolved grants, shared by the CHAPI get popup and the
 * interaction-URL request page: the first resolution pass shown at once, then
 * replaced by the second pass with the existing collections' attribution read
 * in (`attributeExistingCollections`). The call hands the second pass back
 * as well, for a caller whose refusal needs it (the interaction-URL page). A
 * later call supersedes an earlier pass, so a superseded pass's late result
 * is dropped rather than written over a newer one.
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
 *   Awaited<ReturnType<Session['storage']['listAppKeys']>> }) =>
 *   Promise<ResolvedGrant[]> }}
 *   the grants to render, and the call that shows a first pass's grants and
 *   starts the attribution pass behind them, handed the caller's app-key
 *   listing when it already holds one. The call resolves to the attributed
 *   pass, or to the first pass when the attribution failed (best-effort: an
 *   unread epoch refuses nothing), and never rejects.
 */
export function useAttributedGrants(): {
  grants: ResolvedGrant[]
  attributeGrants: (options: {
    resolution: Parameters<typeof resolveGrants>[0]
    grants: ResolvedGrant[]
    storage: Session['storage']
    appKeys?: Awaited<ReturnType<Session['storage']['listAppKeys']>>
  }) => Promise<ResolvedGrant[]>
} {
  const [grants, setGrants] = useState<ResolvedGrant[]>([])
  const runRef = useRef(0)

  const attributeGrants = useCallback(
    async ({
      resolution,
      grants: firstPass,
      storage,
      appKeys
    }: {
      resolution: Parameters<typeof resolveGrants>[0]
      grants: ResolvedGrant[]
      storage: Session['storage']
      appKeys?: Awaited<ReturnType<Session['storage']['listAppKeys']>>
    }): Promise<ResolvedGrant[]> => {
      const run = ++runRef.current
      setGrants(firstPass)
      let attributed: ResolvedGrant[] | undefined
      try {
        attributed = await attributeExistingCollections({
          resolution,
          grants: firstPass,
          storage,
          appKeys
        })
      } catch (err) {
        log.warn('Could not attribute the existing collections', { err })
      }
      if (attributed && runRef.current === run) {
        setGrants(attributed)
      }
      return attributed ?? firstPass
    },
    []
  )

  return { grants, attributeGrants }
}
