/**
 * The vocabulary the content-migration import methods report in, and the
 * held-content snapshot they decide against.
 *
 * A migration walk (`@interop/wallet-backup`) reads one archived row out of a
 * backup bundle and hands it to a host import method; the method says what
 * happened to it, and the walk tallies the report. The outcome vocabulary is
 * the package's `SinkOutcome`, under the name the store layer uses for it:
 * `accepted` (written), `skipped` (already held, or content this build does
 * not migrate), `conflicting` (that identity is held under different content,
 * and the row landed nowhere), `failed` (the write did not land and may be
 * retried).
 */
import type { ContactHeadPayload } from '@interop/social-core'
import type { WalletActivity } from '@/stores/storageManager'

export type { SinkOutcome as ImportOutcome } from '@interop/wallet-backup'

/**
 * What the account holds in the collections the migration writes, read once
 * per run and kept current by the import methods as they write. The "already
 * held" checks decide against it, so a run reads each collection once rather
 * than once per archived row, and a row this run wrote is held for the rows
 * behind it.
 *
 * - `contactHeads` -- every stored contact head, keyed by its `contactId`
 *   (a legacy head with none is keyed by its row id), in the read-side
 *   upgraded shape every listing serves.
 * - `contactRevisions` -- per `contactId`, the content identities of the
 *   revisions the account holds for it.
 * - `activities` -- per activity id, the held body (the first row under
 *   that id, as the history listing serves it).
 */
export interface HeldContent {
  contactHeads: Map<string, ContactHeadPayload>
  contactRevisions: Map<string, Set<string>>
  activities: Map<string, WalletActivity>
}
