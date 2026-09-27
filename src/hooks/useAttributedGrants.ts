/**
 * The consent screen's resolved grants, shared by the CHAPI get popup and the
 * interaction-URL request page: the first resolution pass shown at once, then
 * replaced by the second pass with the existing collections' attribution read
 * in (`attributeExistingCollections`). A later call supersedes an earlier
 * pass, so a superseded pass's late result is dropped rather than written
 * over a newer one.
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
 *   ResolvedGrant[], storage: Session['storage'] }) => void }}   the grants
 *   to render, and the call that shows a first pass's grants and starts the
 *   attribution pass behind them
 */
export function useAttributedGrants(): {
  grants: ResolvedGrant[]
  attributeGrants: (options: {
    resolution: Parameters<typeof resolveGrants>[0]
    grants: ResolvedGrant[]
    storage: Session['storage']
  }) => void
} {
  const [grants, setGrants] = useState<ResolvedGrant[]>([])
  const runRef = useRef(0)

  const attributeGrants = useCallback(
    ({
      resolution,
      grants: firstPass,
      storage
    }: {
      resolution: Parameters<typeof resolveGrants>[0]
      grants: ResolvedGrant[]
      storage: Session['storage']
    }) => {
      const run = ++runRef.current
      setGrants(firstPass)
      attributeExistingCollections({ resolution, grants: firstPass, storage })
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

  return { grants, attributeGrants }
}
