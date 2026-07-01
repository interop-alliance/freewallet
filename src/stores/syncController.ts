/**
 * SyncController: the app-side lifecycle around background WAS replication.
 *
 * The local RxDB collections owned by the session's storage (BrowserStore) are
 * the always-on active replica; when a remote WAS Space is configured and the
 * session is not a guest, this controller starts a `replicateRxCollection`
 * state machine per synced collection against its remote counterpart via the
 * generic adapter in `src/lib/sync/`.
 *
 * Reachability is not polled: the replication attempt is the probe. RxDB's own
 * `retryTime` backoff retries a down server silently and surfaces failures on
 * `error$`; the controller's only reachability wiring is `window` `online` /
 * `offline`, firing `reSync()` on reconnect so a long-offline session recovers
 * promptly rather than waiting out the backoff. Status is driven off
 * `active$` / `error$` into the `syncStatusStore` for the UI.
 *
 * The collection set is data-driven (`SYNCED_COLLECTIONS`): all three standard
 * collections replicate through the same adapter. The encrypted ones
 * (`private-credentials`, `wallet-activity`) need nothing special here -- their
 * locally stored EDV envelopes ship verbatim; encrypt/decrypt happens at the
 * storage layer's read/write time, never in the sync path.
 */
import type { RxReplicationState } from 'rxdb/plugins/replication'
import {
  SYNCED_COLLECTIONS,
  WAS_SERVER_URL,
  WAS_SYNC_BATCH_SIZE,
  WAS_SYNC_RETRY_MS
} from '@/app.config'
import {
  createWasReplication,
  type SyncCheckpoint,
  type SyncedDoc
} from '@/lib/sync'
import { createWasSyncPort } from '@/stores/wasSyncPort'
import { useSyncStatusStore } from '@/stores/syncStatusStore'
import type { Session } from '@/types/auth'

/**
 * The subset of an RxJS `Subscription` we hold (rxjs is only a transitive dep,
 * so we type structurally rather than import it).
 */
type Unsubscribable = { unsubscribe: () => void }

interface CollectionReplication {
  state: RxReplicationState<SyncedDoc, SyncCheckpoint>
  subscriptions: Unsubscribable[]
}

/**
 * Singleton controlling replication for the current session. Constructed once
 * and shared; `start()`/`stop()` bracket a login/logout.
 */
class SyncController {
  private _replications: CollectionReplication[] = []
  private _onlineHandler?: () => void
  private _started = false

  /**
   * Starts background replication for a logged-in session. A no-op for guests,
   * or when no remote WAS replica is configured, or when already running.
   * Expects the session storage's local collections to be initialized
   * (`ensureUserCollections()` runs before login).
   *
   * @param options {object}
   * @param options.session {Session}
   * @returns {Promise<void>}
   */
  async start({ session }: { session: Session }): Promise<void> {
    if (this._started) {
      return
    }
    // Guests never sync; a missing client/space means no remote replica.
    const was = session.storage.wasClient
    const spaceId = session.storage.spaceId
    if (session.isGuest || !WAS_SERVER_URL || !was || !spaceId) {
      return
    }
    this._started = true

    const setStatus = useSyncStatusStore.getState().setStatus

    try {
      for (const { key, id } of SYNCED_COLLECTIONS) {
        setStatus(id, 'idle')
        // The local end of replication IS the page-facing active replica.
        const rxCollection = session.storage.localCollection(key)
        const wasPort = createWasSyncPort({ was, spaceId, collectionId: id })
        const state = createWasReplication({
          rxCollection,
          wasPort,
          replicationIdentifier: `was-sync:${WAS_SERVER_URL}:${spaceId}:${id}`,
          ...(WAS_SYNC_BATCH_SIZE !== undefined && {
            batchSize: WAS_SYNC_BATCH_SIZE
          }),
          ...(WAS_SYNC_RETRY_MS !== undefined && {
            retryTime: WAS_SYNC_RETRY_MS
          })
        })

        // Drive UI status off the replication streams. `active$` toggles while a
        // cycle runs; `error$` marks a failed cycle (RxDB then backs off/retries).
        const subscriptions: Unsubscribable[] = [
          state.active$.subscribe(active => {
            setStatus(id, active ? 'syncing' : 'synced')
          }),
          state.error$.subscribe(err => {
            console.error(`Sync error for "${id}":`, err)
            setStatus(id, 'error')
          })
        ]
        this._replications.push({ state, subscriptions })
      }

      // The one genuinely useful reachability signal: on reconnect, resync
      // immediately rather than waiting out RxDB's backoff tick.
      this._onlineHandler = () => {
        for (const { state } of this._replications) {
          state.reSync()
        }
      }
      window.addEventListener('online', this._onlineHandler)
    } catch (err) {
      console.error('Failed to start sync controller:', err)
      // Leave any partial state for stop() to tear down cleanly.
      await this.stop()
    }
  }

  /**
   * Stops replication and releases all resources (the underlying database is
   * owned by the session's storage, which closes it on logout). Idempotent.
   *
   * @returns {Promise<void>}
   */
  async stop(): Promise<void> {
    if (this._onlineHandler) {
      window.removeEventListener('online', this._onlineHandler)
      this._onlineHandler = undefined
    }
    for (const { state, subscriptions } of this._replications) {
      for (const subscription of subscriptions) {
        subscription.unsubscribe()
      }
      try {
        await state.cancel()
      } catch (err) {
        console.error('Error cancelling replication:', err)
      }
    }
    this._replications = []
    useSyncStatusStore.getState().reset()
    this._started = false
  }
}

export const syncController = new SyncController()
