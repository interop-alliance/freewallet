/**
 * The session binding around background WAS replication. The driver and the
 * lifecycle core live in `@interop/was-sync`; what is here is everything that
 * is this app's: which sessions replicate at all, where the core's access seam
 * comes from, and where status and diagnostics go.
 *
 * The local RxDB collections owned by the session's storage (BrowserStore) are
 * the always-on active replica. A guest, a deployment with no remote WAS Space,
 * and a replica-less session (the transient session's remote-direct storage)
 * each have nothing to replicate, so the gate below returns before the core is
 * ever constructed.
 *
 * The collection set is data-driven (`SYNCED_COLLECTIONS`, projected from the
 * standard collections): every standard collection replicates through the same
 * driver. The encrypted ones (`private-credentials`, `wallet-activity`) need
 * nothing special here -- their locally stored EDV envelopes ship verbatim;
 * encrypt and decrypt happen at the storage layer's read and write time, never
 * in the sync path.
 *
 * The core's `stop()` is terminal for an instance, so `restart()` constructs a
 * fresh core per session and this module-scope singleton is a thin shell
 * holding the current one.
 */
import type { SyncController } from '@interop/was-sync/rxdb'
import {
  SYNCED_COLLECTIONS,
  WAS_SERVER_URL,
  WAS_SYNC_BATCH_SIZE,
  WAS_SYNC_POLL_MS,
  WAS_SYNC_RETRY_MS
} from '@/app.config'
import { useSyncStatusStore } from '@/stores/syncStatusStore'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:sync:controller')

/**
 * The browser's reachability source: `navigator.onLine` for the poll tick, and
 * the `online` event for the immediate reconnect resync. An environment that
 * cannot answer reads as online, so a missing signal never stops the poll.
 *
 * @returns {{ isOnline: () => boolean, subscribe: (onOnline: () => void) => () => void }}
 */
function browserOnlineSource() {
  return {
    isOnline(): boolean {
      return typeof navigator === 'undefined' ? true : navigator.onLine
    },
    subscribe(onOnline: () => void): () => void {
      window.addEventListener('online', onOnline)
      return () => window.removeEventListener('online', onOnline)
    }
  }
}

/**
 * Singleton bracketing replication for the current session. Constructed once
 * and shared; `restart()` / `stop()` bracket a login / logout.
 */
class SessionSyncController {
  #core: SyncController | null = null
  // Serializes every lifecycle transition (restart / stop) onto a single chain
  // so overlapping login / logout calls can never interleave and leave a
  // dangling core. The core serializes its own start and stop; this chain is
  // what keeps two SESSIONS' cores from overlapping.
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
   * Stops any running replication, then starts it fresh for `session`,
   * serialized as a single atomic transition. The one entry point for
   * starting: it guarantees a core left running by a previous (restored or
   * other-account) session is torn down before the new one starts, so a
   * re-login can never silently fail to replicate.
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
   * Triggers an immediate replication cycle on every running collection
   * replication, rather than waiting for the next scheduled tick.
   * Fire-and-forget: progress surfaces through the syncStatusStore as usual. A
   * no-op when replication is not running (guest, no remote, stopped).
   *
   * @returns {void}
   */
  reSync(): void {
    this.#core?.reSync()
  }

  /**
   * Builds the core for a logged-in session and starts it. A no-op for guests,
   * when no remote WAS replica is configured, and for a replica-less session:
   * every synced-collection operation there is already served remote-direct,
   * so replication has no local end to drive. Expects the session storage's
   * local collections to be initialized (`ensureUserCollections()` runs before
   * login). Runs inside the serialized queue, always behind a stop; callers use
   * `restart()`.
   *
   * @param options {object}
   * @param options.session {Session}
   * @returns {Promise<void>}
   */
  async #start({ session }: { session: Session }): Promise<void> {
    const wasClient = session.storage.wasClient
    const spaceId = session.storage.spaceId
    if (
      session.isGuest ||
      !WAS_SERVER_URL ||
      !wasClient ||
      !spaceId ||
      !session.storage.hasLocalReplica
    ) {
      return
    }

    const setStatus = useSyncStatusStore.getState().setStatus

    try {
      // Dynamically imported: the RxDB half of the driver drags in RxDB's
      // replication machinery (rxdb core, rxjs, broadcast-channel), which
      // would otherwise land in the eager entry chunk via the auth store.
      const { createSyncController } = await import('@interop/was-sync/rxdb')
      const core = createSyncController({
        port: {
          wasClient,
          spaceId,
          serverUrl: WAS_SERVER_URL,
          collections: SYNCED_COLLECTIONS,
          // The local end of replication IS the page-facing active replica.
          rxCollection: key => session.storage.localCollection(key),
          ...(WAS_SYNC_BATCH_SIZE !== undefined && {
            batchSize: WAS_SYNC_BATCH_SIZE
          }),
          ...(WAS_SYNC_RETRY_MS !== undefined && {
            retryTime: WAS_SYNC_RETRY_MS
          })
        },
        onStatus: (_key, collectionId, status) => {
          setStatus(collectionId, status)
        },
        onlineSource: browserOnlineSource(),
        pollMs: WAS_SYNC_POLL_MS,
        // The core's log port takes `Record<string, unknown>` metadata, which
        // the namespaced logger already satisfies, so its diagnostics ride
        // the `fw:sync:controller` namespace with no adapter.
        log
      })
      this.#core = core
      await core.start()
    } catch (err) {
      // The login path fires `restart()` inside a `void` async block, where a
      // rethrow would surface as an unhandled rejection. The core has already
      // unwound its own partial bring-up and flagged each collection `error`.
      log.error('Failed to start sync controller', { err })
    }
  }

  /**
   * Stops the current core and drops it (the underlying database is owned by
   * the session's storage, which closes it on logout). Idempotent. Runs inside
   * the serialized queue; callers use `stop()` / `restart()`.
   *
   * @returns {Promise<void>}
   */
  async #stop(): Promise<void> {
    const core = this.#core
    this.#core = null
    if (core) {
      await core.stop()
    }
    useSyncStatusStore.getState().reset()
  }
}

export const syncController = new SessionSyncController()
