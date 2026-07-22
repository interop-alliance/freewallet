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
 * The collection set is data-driven (`SYNCED_COLLECTIONS`, projected from the
 * standard collections): every standard collection replicates through the same
 * adapter. The encrypted ones
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
import type { SyncCheckpoint, SyncedDoc, WasSyncPort } from '@/lib/sync'
import { createWasSyncPort } from '@interop/was-client/sync'
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
  #replications: CollectionReplication[] = []
  #onlineHandler?: () => void
  #started = false
  // Serializes every lifecycle transition (start / stop / restart) onto a
  // single chain so overlapping login / logout calls can never interleave and
  // leave dangling replications or a stale `_started` flag. A start racing a
  // stop is thereby impossible: each runs to completion before the next begins.
  #queue: Promise<void> = Promise.resolve()

  /**
   * Serializes a lifecycle task after any in-flight one. Rejections are
   * swallowed on the chain (each task already handles its own errors) so a
   * single failure cannot wedge every subsequent transition; the returned
   * promise still reflects this task's own outcome for callers that await it.
   *
   * @param task {() => Promise<void>}
   * @returns {Promise<void>}
   */
  #enqueue(task: () => Promise<void>): Promise<void> {
    const next = this.#queue.then(task, task)
    this.#queue = next.catch(() => {})
    return next
  }

  /**
   * Starts background replication for a logged-in session, serialized after any
   * in-flight lifecycle transition. A no-op for guests, when no remote WAS
   * replica is configured, or when already running.
   *
   * @param options {object}
   * @param options.session {Session}
   * @returns {Promise<void>}
   */
  start({ session }: { session: Session }): Promise<void> {
    return this.#enqueue(() => this.#start({ session }))
  }

  /**
   * Stops any running replication, then starts it fresh for `session`,
   * serialized as a single atomic transition. This is the login path's entry
   * point: it guarantees a controller left running by a previous (restored or
   * other-account) session is torn down before the new one starts, closing the
   * `_started`-guard hole where a re-login would otherwise silently never
   * replicate.
   *
   * @param options {object}
   * @param options.session {Session}
   * @returns {Promise<void>}
   */
  restart({ session }: { session: Session }): Promise<void> {
    return this.#enqueue(async () => {
      await this.#stop()
      await this.#start({ session })
    })
  }

  /**
   * Stops background replication and releases all resources, serialized after
   * any in-flight lifecycle transition. Idempotent.
   *
   * @returns {Promise<void>}
   */
  stop(): Promise<void> {
    return this.#enqueue(() => this.#stop())
  }

  /**
   * Starts background replication for a logged-in session. A no-op for guests,
   * or when no remote WAS replica is configured, or when already running.
   * Expects the session storage's local collections to be initialized
   * (`ensureUserCollections()` runs before login). Runs inside the serialized
   * queue; callers use `start()` / `restart()`.
   *
   * @param options {object}
   * @param options.session {Session}
   * @returns {Promise<void>}
   */
  async #start({ session }: { session: Session }): Promise<void> {
    if (this.#started) {
      return
    }
    // Guests never sync; a missing client/space means no remote replica.
    const was = session.storage.wasClient
    const spaceId = session.storage.spaceId
    if (session.isGuest || !WAS_SERVER_URL || !was || !spaceId) {
      return
    }
    this.#started = true

    const setStatus = useSyncStatusStore.getState().setStatus

    try {
      // Dynamically imported: the replication adapter drags in RxDB's
      // replication machinery (rxdb core, rxjs, broadcast-channel), which
      // would otherwise land in the eager entry chunk via the auth store.
      const { createWasReplication } = await import('@/lib/sync')
      for (const { key, id } of SYNCED_COLLECTIONS) {
        setStatus(id, 'idle')
        // The local end of replication IS the page-facing active replica.
        const rxCollection = session.storage.localCollection(key)
        // The library port ships the opaque wire body typed as `unknown`; the
        // driver's stricter `WasSyncPort` types it as `Json`. Bridge onto the
        // stricter interface here (the body is moved verbatim either way).
        const wasPort = createWasSyncPort({
          was,
          spaceId,
          collectionId: id
        }) as unknown as WasSyncPort
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
        this.#replications.push({ state, subscriptions })
      }

      // The one genuinely useful reachability signal: on reconnect, resync
      // immediately rather than waiting out RxDB's backoff tick.
      this.#onlineHandler = () => this.reSync()
      window.addEventListener('online', this.#onlineHandler)
    } catch (err) {
      console.error('Failed to start sync controller:', err)
      // Tear down any partial state cleanly. Call the internal `#stop()`
      // directly rather than the queueing `stop()`: we already hold the queue,
      // so enqueuing here would deadlock on our own in-flight task.
      await this.#stop()
    }
  }

  /**
   * Triggers an immediate replication cycle on every running collection
   * replication, rather than waiting for RxDB's next scheduled tick.
   * Fire-and-forget: progress surfaces through the syncStatusStore as usual.
   * A no-op when replication is not running (guest, no remote, stopped).
   *
   * @returns {void}
   */
  reSync(): void {
    for (const { state } of this.#replications) {
      state.reSync()
    }
  }

  /**
   * Stops replication and releases all resources (the underlying database is
   * owned by the session's storage, which closes it on logout). Idempotent.
   * Runs inside the serialized queue; callers use `stop()` / `restart()`.
   *
   * @returns {Promise<void>}
   */
  async #stop(): Promise<void> {
    if (this.#onlineHandler) {
      window.removeEventListener('online', this.#onlineHandler)
      this.#onlineHandler = undefined
    }
    for (const { state, subscriptions } of this.#replications) {
      for (const subscription of subscriptions) {
        subscription.unsubscribe()
      }
      try {
        await state.cancel()
      } catch (err) {
        console.error('Error cancelling replication:', err)
      }
    }
    this.#replications = []
    useSyncStatusStore.getState().reset()
    this.#started = false
  }
}

export const syncController = new SyncController()
