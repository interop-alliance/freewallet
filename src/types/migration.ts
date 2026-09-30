/**
 * The vocabulary the content-migration import methods report in, and the
 * held-content snapshot they decide against.
 *
 * A migration walk (`@interop/wallet-backup`) reads one archived Resource out
 * of a backup bundle and hands it to a host import method; the method says what
 * happened to it, and the walk tallies the report. The outcome vocabulary is
 * the package's `SinkOutcome`, under the name the store layer uses for it:
 * `accepted` (written), `skipped` (already held, or content this build does not
 * migrate), `conflicting` (that identity is held under different content, and
 * the Resource landed nowhere), `failed` (the write did not land and may be
 * retried).
 */
import type { ContactHeadPayload } from '@interop/social-core'
import type { WalletActivity } from '@/stores/storageManager'

export type { SinkOutcome as ImportOutcome } from '@interop/wallet-backup'

/**
 * What the account holds in the collections the migration writes, read once
 * per run and kept current by the import methods as they write. The "already
 * held" checks decide against it, so a run reads each collection once rather
 * than once per archived Resource, and a Resource this run wrote is held for
 * the Resources behind it.
 *
 * - `contactHeads` -- every stored contact head, keyed by its `contactId`
 *   (a legacy head with none is keyed by its resource id), in the read-side
 *   upgraded shape every listing serves.
 * - `contactRevisions` -- per `contactId`, the content identities of the
 *   revisions the account holds for it.
 * - `activities` -- per activity id, the held body (the first Resource under
 *   that id, as the history listing serves it).
 */
export interface HeldContent {
  contactHeads: Map<string, ContactHeadPayload>
  contactRevisions: Map<string, Set<string>>
  activities: Map<string, WalletActivity>
}

/**
 * What the account holds in one app collection, read once per run: each held
 * Resource's identity to its content cid. In an encrypted collection, a JSON
 * Resource's identity is its payload's own `id`, or the payload's content cid
 * when it carries none, and a bytes Resource's is its resource id, mapped to
 * `null` since its content is never read for the snapshot. A plaintext
 * Resource's identity is its resource id. The import method adds each
 * Resource it writes.
 */
export type HeldAppResources = Map<string, string | null>
