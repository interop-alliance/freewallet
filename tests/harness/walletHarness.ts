/**
 * The session harness: real wallet sessions, run in node as scripted actors
 * against an in-process `was-teaching-server`. Each actor is one tab. It
 * holds its own session in its own tab memory, so several can be live at
 * once against one account. The signup runs `signUpWithPassphrase`. A visit
 * runs `loginWithPassphrase` or `loginWithPasskey`, the login page's own
 * entry points, which route through `routeUnlockLogin` to the transient
 * composition (`transientSessionFromKeyringHit`) or to the remembered
 * branches. Nothing under `src/session/` and no `@interop/*` module is
 * mocked.
 *
 * Inventory: what on the credential-anchored signup path, the transient
 * login path, and the remembered login path does not load or run in
 * vitest's node environment with nothing mocked, and how each is handled.
 *
 * - `@/app.config` (`VITE_WAS_SERVER_URL`). It reads the variable once, at
 *   its first evaluation, and the server's port is known only after boot.
 *   Handled by load order, with no module stub: the harness boots the
 *   server, sets the variable with `vi.stubEnv` (vitest's
 *   `import.meta.env` reads `process.env` at access), then imports the
 *   wallet modules dynamically. It refuses to start when `@/app.config` was
 *   already evaluated under another value. One server per test file, since
 *   each file has its own module graph.
 * - KMS URL. Derived from the same variable (`<server>/kms`), served by the
 *   server's in-process `/kms` facet. Runs for real: the signup's
 *   `kms-authentication` stage mints the account's `authentication` key, and
 *   a remembered login provisions its keystore there.
 * - Service discovery (`src/lib/wasService.ts`). Runs for real against the
 *   server. The unit suite's setup-file mock of this module is not part of
 *   the harness config.
 * - The `freewallet-session` database (the client-key record probe
 *   `hasClientKeyRecord`, the client-key record, the keyring cache, the
 *   writer first-seen record, the unlock-methods cache). Its default
 *   `idb = indexedDB` throws a ReferenceError in node. Handled by the
 *   existing injection port: the entry points take `idb`, and the harness
 *   also builds the remembered persistence strategy over the same factory
 *   (`browserLocalSessionPersistence({ idb })`) and hands it in through
 *   their existing `persistence` option. Each `BrowserProfile` holds its own
 *   factory, the in-repo `IDBFactory` fake (`tests/unit/fakeSessionIdb.ts`).
 *   It models the create-nothing probe and the get, put, delete, and key
 *   scan the session database needs, which is all of what this database
 *   asks. The signup never probes. `fake-indexeddb` is not a dependency of
 *   this repo: adding it re-resolved an unrelated workspace link in the
 *   lockfile, so it was not added.
 * - The local replica (`BrowserStore`, RxDB). Runs for real, on RxDB's
 *   memory storage rather than on the IndexedDB substitute: its default
 *   Dexie storage needs a full IndexedDB, which the in-repo fake is not.
 *   Each profile holds its own memory storage (its own collection-state
 *   map, so no two profiles share a replica). It reaches the session through
 *   one seam: the browser-local persistence strategy's optional
 *   `replicaStorage` member, which `StorageManager.initStorageClients` uses
 *   when no explicit storage is given. A remembered login therefore passes
 *   `storageReady` and runs its login mender block over a real replica.
 *   `BrowserStore.userExists` enumerates the global `indexedDB`. It now
 *   answers false where there is none, and the remembered path's remote
 *   probe answers instead.
 * - Background replication (`src/stores/syncController.ts`). Not started.
 *   The controller is a process-wide singleton started only by the auth
 *   store's `login`, which the harness does not call. A remembered actor's
 *   replica neither pushes nor pulls: its own writes to the replicated
 *   collections (the Login activity, the welcome seed) stay in its replica,
 *   and its replica reads do not see another actor's writes. Account
 *   ceremonies write to the server directly and are unaffected. Every
 *   actor's logout still calls the singleton's `stop()`.
 * - `localStorage` (the descriptor and meta caches in
 *   `src/session/persistence.ts`, `src/lib/writerId.ts`,
 *   `src/lib/prefsStorage.ts`, the logger's filter read). Absent, with no
 *   substitute: every one of them is guarded for a missing `localStorage`,
 *   and the transient strategy never reaches it. On a remembered actor the
 *   consequences are that the descriptor and meta caches hold nothing (each
 *   login fetches the descriptors, and there is no offline fallback), and
 *   that `getOrCreateWriterId` mints a fresh `writerId` per call, so the
 *   writer first-seen record's id never matches a later session's and the
 *   second-session writer registration does not fire.
 * - Passkeys (`src/lib/passkey.ts`). Node has no WebAuthn. A passkey is test
 *   owned (`createTestPasskey`): a credential id and 32 PRF bytes. The login
 *   rides the existing port: `loginWithPasskey({ credential })` takes the
 *   unlock credential derived from those bytes under `PASSKEY_KDF` (HKDF,
 *   so no stretch), which skips the assertion ceremony. The Settings add
 *   ceremony (`addAccountPasskey`) called `registerPasskey` directly. It now
 *   takes an optional `register` in its place, and the test passes
 *   `testAuthenticator`, which answers with those bytes.
 * - Unlock KDF (Argon2id, 64 MiB, 3 passes, through noble). Runs for real,
 *   once per passphrase signup and once per passphrase visit. Measured at
 *   0.65 to 0.8 s per derivation in node, so 21 derivations cost about 15
 *   s, which is tolerable. Existing unit tests avoid it by mocking
 *   `deriveUnlockCredential` under `src/session/`, which this harness may
 *   not do. `loginWithPassphrase` also takes a pre-derived `credential`, an
 *   escape hatch the harness does not use for passphrases.
 * - CHAPI registration (`src/lib/registerWallet.ts`). The module loads in
 *   node, but the call throws (`window is not defined`). Not run: it is
 *   called only by the login page's mount and `completeAppLogin`.
 * - The zustand auth store (`src/stores/authStore.ts`). It loads, but its
 *   `login` and `logout` throw in node (`window is not defined`, the e2e
 *   storage seam), and it holds one session for the whole process. Not used:
 *   the entry points return the `Session`, and the actor holds it.
 * - `completeAppLogin`. Not run, since it adopts the session into the auth
 *   store. The actor runs its non-UI steps itself: it awaits
 *   `storageReady`, writes the Login activity (`recordWalletLogin`'s one
 *   write, with its handle kept so `settled()` can wait on it), and runs
 *   the recovery health check. The CHAPI registration, the toasts, and the
 *   navigation are skipped.
 * - Logout. The Logout page calls the auth store's `logout`, which throws in
 *   node and resets process-wide stores. The actor runs the teardown that
 *   `logout` delegates to, `discardSession` (`src/stores/sessionTeardown.ts`):
 *   the session's disposal signal, the sync controller stop, the storage
 *   close. The store's own resets (the setup store, the registry lookup
 *   caches, the prefs overlay) are skipped, since they would reach every
 *   live actor. A transient session's teardown sends nothing to the server.
 *   A remembered session's closes its replica and keeps its data.
 * - Logger wiring (`src/lib/log.ts`). Runs for real: its dev sinks are gated
 *   on `MODE === 'development'`, which vitest is not. The harness turns the
 *   default console sink off, sets the e2e debug filter, and adds one sink
 *   that attributes each event to its tab (`tabAttribution.ts`).
 * - E2E seams (`src/lib/e2eSeams.ts`). Guarded on a missing `window`, so all
 *   read false.
 * - Node supplies the rest as globals: `fetch`, `crypto.getRandomValues`,
 *   WebCrypto, `performance`, `AbortController`, `BroadcastChannel` (the
 *   replica's cross-tab teardown listener).
 *
 * Stubs in force: one environment variable (`VITE_WAS_SERVER_URL`). No
 * module is mocked. Production code carries three optional seams for the
 * harness, each defaulting to the app's behavior: the persistence
 * strategy's `replicaStorage` (read by `initStorageClients`), the
 * missing-`indexedDB` guard in `BrowserStore.userExists`, and the `register`
 * option of `addAccountPasskey`.
 *
 * The browser profile is owned by the test and outlives the actors that use
 * it. `wipe()` deletes what the profile stores, at any point, as clearing
 * the site's data does: the session database and the replica. One
 * difference from a browser: a live actor's open replica keeps its own
 * in-memory state rather than being force-closed. `drop()` keeps the store.
 * A later actor on the same profile and the same enrolled client opens the
 * same replica database name, and RxDB's `closeDuplicates` (which the app
 * sets) closes the dropped actor's handle, as a second tab would find the
 * first one gone.
 *
 * Isolation between two live actors. Each actor owns its `Session` and
 * everything hanging off it: the persistence strategy and its pin stores,
 * the per-visit or client key, the storage manager and its replica, the
 * disposal signal, the encounter gate, and the mend report. The
 * module-level state on these paths that is keyed by session
 * (`sessionLifecycle.ts`, `userKeyAdoption.ts`, `connectionWriters.ts`,
 * `menders/encounter.ts`, `menders/encounterSites.ts`) is a `WeakMap`, so it
 * is per actor too. Each profile owns its session database and its replica
 * storage. Shared by every actor in the process:
 *
 * - the service discovery memo (`src/lib/wasService.ts`), one per process;
 * - `@interop/logger`'s sinks and filter, and wallet-core's, pws-sync's, and
 *   wallet-request's `setLogger` wiring;
 * - the sync controller singleton (`src/stores/syncController.ts`), never
 *   started by any actor, but stopped by every actor's logout;
 * - the zustand stores (auth, setup, sync status, toast), which no actor
 *   touches;
 * - RxDB's process-wide registries: the open database names (keyed by
 *   storage name and database name, so two actors of one enrolled client
 *   share one name, which is what `closeDuplicates` acts on), and the
 *   open-collection cap of the open-source build (13 per process). A
 *   remembered session opens 7 collections, so two remembered actors can be
 *   live at once (the second stalls about 2 s on the cap) and a third is
 *   refused (`COL23`);
 * - node's `BroadcastChannel` namespace, so a replica wipe's teardown
 *   broadcast reaches every remembered actor's listener. Only a store whose
 *   replica prefix matches (the same enrolled client) closes on it;
 * - the absent `localStorage`, so no actor persists a cache or a `writerId`;
 * - pure memos with no session state: pws-client's resolved did:key cache,
 *   the webvh and resource-log `WeakMap` indexes keyed by log or document;
 * - the server, its data dir, and its request recorder and armed faults.
 */
import { vi } from 'vitest'
import type { LogEvent } from '@interop/logger'
import type { RxStorage } from 'rxdb/plugins/core'
import {
  getRxStorageMemory,
  type RxStorageMemory
} from 'rxdb/plugins/storage-memory'
import {
  openTempBackend,
  startTestServer,
  type RequestFaults,
  type RequestRecord
} from 'was-teaching-server/testing'
import { canonicalBaseServerUrl, spaceIdOfUrl } from '@interop/pws-client/paths'
import type { Session } from '@/types/auth'
import type { PasskeyRegistration } from '@/lib/passkey'
import { createFakeSessionIdb } from '../unit/fakeSessionIdb'
import { readAccountLogSizes } from '../shared/storedLogs'
import {
  inTab,
  installTabAttribution,
  type TabRecorder
} from './tabAttribution'

/**
 * The storage one browser profile holds, owned by the test so it can outlive
 * the actors that use it. A transient visit only probes it (the client-key
 * record lookup) and should write nothing to it. A remembered visit keeps
 * its client-key record and its replica here.
 *
 * - `name`: a label for messages.
 * - `idb`: the factory the session code is handed in place of `indexedDB`,
 *   holding the `freewallet-session` database.
 * - `replicaStorage`: the RxDB storage the local replica opens on.
 * - `databaseNames`: the IndexedDB databases the profile holds, read by the
 *   test.
 * - `sessionStore`: the `freewallet-session` database's records, read by
 *   the test.
 * - `replicaCollectionCount()`: how many replica collections the profile
 *   stores, across every database.
 * - `wipe()`: deletes the session database and the replica, as clearing the
 *   site's data does. Callable at any point, a live actor's ceremony
 *   included.
 */
export interface BrowserProfile {
  readonly name: string
  readonly idb: IDBFactory
  readonly replicaStorage: RxStorage<unknown, unknown>
  readonly databaseNames: ReadonlySet<string>
  readonly sessionStore: ReadonlyMap<string, unknown>
  replicaCollectionCount(): number
  wipe(): void
}

/**
 * A passkey the test owns, standing in for an authenticator: the credential
 * id the registry records and the PRF output the authenticator would
 * evaluate. The wallet derives the passkey's unlock credential from
 * `prfOutput` alone.
 */
export interface TestPasskey {
  readonly credentialId: Uint8Array
  readonly prfOutput: Uint8Array
}

/**
 * Where a visit is in its life.
 *
 * - `live`: the session is held in the actor's tab memory.
 * - `logged-out`: the session's own teardown ran.
 * - `dropped`: the tab died with no teardown (the crashed-tab case).
 */
export type ActorState = 'live' | 'logged-out' | 'dropped'

/**
 * One part of a visit's background work that failed. `source` names the
 * part: a session promise that rejected (`storageReady`, `mends`, ...), the
 * harness-held `loginActivity` write or `recoveryHealth` check that
 * rejected, or `mends <invariant>` for a mend report entry whose outcome is
 * `failed` (the report itself never rejects). `error` is the rejection
 * reason, or the mend report entry.
 */
export interface BackgroundFailure {
  source: string
  error: unknown
}

/**
 * One visit: a tab holding one live session in its own memory. Several can
 * be live at once against one account.
 */
export interface WalletActor {
  readonly name: string
  readonly profile: BrowserProfile
  readonly session: Session
  /**
   * `transient` for a session on the in-memory strategy, `remembered` for
   * one on the browser-local strategy (an enrolled client).
   */
  readonly kind: 'transient' | 'remembered'
  /**
   * The account Space id the session's account pointer names.
   */
  readonly spaceId: string
  /**
   * Every log event this tab's async chains emitted, in dispatch order.
   */
  readonly events: readonly LogEvent[]
  /**
   * When the entry call started, in epoch milliseconds (the clock a
   * `LogEvent.ts` reads).
   */
  readonly startedAt: number
  /**
   * Wall-clock milliseconds from the entry call until the session existed
   * with its storage ready: what a user waits before the dashboard.
   */
  readonly entryMs: number
  state(): ActorState
  /**
   * The server requests that arrived from the entry call until the visit
   * settled (until now, before `settled()` has returned). The server sees no
   * tab, so this is a time window: exact only while no other actor is
   * active.
   */
  serverRequests(): readonly RequestRecord[]
  /**
   * Waits for the work the visit started and did not await: the login
   * mender block (`session.mends`), the welcome-content seed, the Login
   * activity write, the recovery health check, and a remembered session's
   * writer registration. Never rejects: every part is waited out, and the
   * parts that failed come back as `failures` for the test to assert on.
   *
   * @returns {Promise<{ settledMs: number, failures: BackgroundFailure[] }>}
   *   milliseconds from the entry call until the visit went idle, and the
   *   background work that failed (empty on a clean visit)
   */
  settled(): Promise<{ settledMs: number; failures: BackgroundFailure[] }>
  /**
   * Runs work against the live session inside this tab's scope, so what it
   * logs is attributed to this tab.
   */
  run<T>(work: (session: Session) => Promise<T>): Promise<T>
  /**
   * The session's own logout: the shared teardown (`discardSession`), the
   * same one the auth store's logout and account switch run.
   */
  logout(): Promise<void>
  /**
   * The crashed-tab case: the actor stops being usable and nothing is torn
   * down or told. The profile's store is kept. Work the visit already
   * started keeps running in the process, since node cannot kill a promise
   * chain; call `settled()` first for a drop at an idle point.
   */
  drop(): void
}

/**
 * A booted server plus the wallet modules loaded against it.
 */
export interface WalletHarness {
  readonly serverUrl: string
  /**
   * The server's FileSystem data root, for the store readers in
   * `tests/shared/`.
   */
  readonly dataDir: string
  /**
   * The server's request recorder and fault seam, as `startTestServer()`
   * returns it: `refuse` (a tear before the server applies the request),
   * `dropResponse` (a tear after it applied it), `hold`, and the ordered
   * `requests` record. A fault is armed for the whole server, so it fires on
   * whichever actor's request matches first. `reset()` empties `requests`,
   * which each actor's `serverRequests()` window indexes into, so call it
   * only while no actor is live.
   */
  readonly faults: RequestFaults
  /**
   * Events emitted outside every actor's scope.
   */
  readonly unattributed: readonly LogEvent[]
  /**
   * A fresh browser profile: empty storage, a browser that has never seen
   * the account.
   */
  coldProfile(options?: { name?: string }): BrowserProfile
  /**
   * The credential-anchored passphrase signup, through
   * `signUpWithPassphrase`, entering the new account as a transient session.
   */
  signUp(options: { passphrase: string; name?: string }): Promise<WalletActor>
  /**
   * A login through the login page's entry point for the credential:
   * `loginWithPassphrase` for a passphrase, `loginWithPasskey` for a test
   * passkey. The routing decides the session kind: on a profile holding no
   * client-key record for the credential it is the transient session, and
   * on one holding a record it is the remembered session of that enrolled
   * client. `rememberBrowser: true` self-enrolls a profile holding no
   * record, and `false` demands the transient session.
   */
  logIn(
    options: (
      | { passphrase: string; passkey?: undefined }
      | { passkey: TestPasskey; passphrase?: undefined }
    ) & {
      name?: string
      profile?: BrowserProfile
      rememberBrowser?: boolean
    }
  ): Promise<WalletActor>
  /**
   * The sizes of the account log, the pointed annex generation log, and the
   * user key roster, read off the store.
   */
  readLogSizes(options: {
    spaceId: string
  }): ReturnType<typeof readAccountLogSizes>
  /**
   * Waits out every actor's own work, closes every replica still open, then
   * closes the server (which removes the data dir) and restores the logger
   * and the environment.
   */
  close(): Promise<void>
}

/**
 * The wallet modules the harness drives, imported only after the server is
 * up and `VITE_WAS_SERVER_URL` names it: `@/app.config` reads the variable
 * once, when it is first evaluated.
 */
async function loadWalletModules() {
  const config = await import('@/app.config')
  const signup = await import('@/session/signup')
  const initSession = await import('@/session/initSession')
  const keyring = await import('@/session/keyring')
  const persistence = await import('@/session/persistence')
  const teardown = await import('@/stores/sessionTeardown')
  const recovery = await import('@/session/recovery')
  return {
    WAS_BASE_SERVER_URL: config.WAS_BASE_SERVER_URL,
    PASSKEY_KDF: config.PASSKEY_KDF,
    signUpWithPassphrase: signup.signUpWithPassphrase,
    loginWithPassphrase: initSession.loginWithPassphrase,
    loginWithPasskey: initSession.loginWithPasskey,
    deriveUnlockCredential: keyring.deriveUnlockCredential,
    browserLocalSessionPersistence: persistence.browserLocalSessionPersistence,
    discardSession: teardown.discardSession,
    closeUnenteredSession: teardown.closeUnenteredSession,
    checkRecoveryHealth: recovery.checkRecoveryHealth
  }
}

type WalletModules = Awaited<ReturnType<typeof loadWalletModules>>

/**
 * Boots the teaching server in process over a temp-dir backend, points the
 * wallet's configuration at it, and loads the wallet modules. Call once per
 * test file, before anything imports a module under `src/`, and `close()`
 * in `afterAll`. Closing the server removes the data dir.
 *
 * @param [options] {object}
 * @param [options.console] {boolean}   keep `@interop/logger`'s console
 *   sink (off by default: a visit logs hundreds of lines)
 * @returns {Promise<WalletHarness>}
 */
export async function startWalletHarness({
  console: keepConsole = false
}: { console?: boolean } = {}): Promise<WalletHarness> {
  const backend = await openTempBackend({ prefix: 'was-harness-' })
  const dataDir = backend.dataDir
  const { fastify, serverUrl, faults } = await startTestServer({ backend })
  const baseServerUrl = canonicalBaseServerUrl(serverUrl)
  vi.stubEnv('VITE_WAS_SERVER_URL', serverUrl)
  const attribution = installTabAttribution({ console: keepConsole })
  let wallet: WalletModules
  try {
    wallet = await loadWalletModules()
    if (wallet.WAS_BASE_SERVER_URL !== baseServerUrl) {
      throw new Error(
        `@/app.config was evaluated before the harness booted: it names ` +
          `"${wallet.WAS_BASE_SERVER_URL}", not "${baseServerUrl}". Start the harness ` +
          'before importing any module under src/.'
      )
    }
  } catch (err) {
    attribution.uninstall()
    vi.unstubAllEnvs()
    await fastify.close()
    throw err
  }
  const actors: WalletActor[] = []

  return {
    serverUrl,
    dataDir,
    faults,
    unattributed: attribution.unattributed,
    coldProfile,
    async signUp({ passphrase, name = 'signup' }) {
      const actor = await enterTab({
        name,
        profile: coldProfile({ name }),
        wallet,
        faults,
        enter: async () => {
          const { session } = await wallet.signUpWithPassphrase({ passphrase })
          if (!session) {
            throw new Error('The signup found an existing account.')
          }
          return session
        }
      })
      actors.push(actor)
      return actor
    },
    async logIn({
      passphrase,
      passkey,
      name = 'visit',
      profile = coldProfile({ name }),
      rememberBrowser
    }) {
      const actor = await enterTab({
        name,
        profile,
        wallet,
        faults,
        enter: async () => {
          // The remembered strategy over this profile's storage. The routing
          // uses it only when it proceeds remembered; a transient login
          // builds its own in-memory family.
          const persistence = wallet.browserLocalSessionPersistence({
            idb: profile.idb,
            replicaStorage: profile.replicaStorage
          })
          const { session } = passkey
            ? await wallet.loginWithPasskey({
                credential: await wallet.deriveUnlockCredential({
                  secret: passkey.prfOutput,
                  kdf: wallet.PASSKEY_KDF
                }),
                idb: profile.idb,
                rememberBrowser,
                persistence
              })
            : await wallet.loginWithPassphrase({
                passphrase: passphrase!,
                idb: profile.idb,
                rememberBrowser,
                persistence
              })
          if (!session) {
            throw new Error(
              'The credential located no account this profile can enter.'
            )
          }
          return session
        }
      })
      actors.push(actor)
      return actor
    },
    readLogSizes: ({ spaceId }) => readAccountLogSizes({ dataDir, spaceId }),
    async close() {
      // Every actor's own work is waited out first, so none of it outlives
      // the server it talks to.
      await Promise.allSettled(actors.map(actor => actor.settled()))
      for (const actor of actors) {
        const wasLoggedOut = actor.state() === 'logged-out'
        actor.drop()
        if (!wasLoggedOut) {
          // Process cleanup, not a visit end: an open replica holds RxDB's
          // process-wide registries and a BroadcastChannel listener.
          await actor.session.storage.close().catch(() => undefined)
        }
      }
      attribution.uninstall()
      vi.unstubAllEnvs()
      await fastify.close()
    }
  }
}

/**
 * A profile with nothing stored. Its session database is the in-repo
 * `IDBFactory` fake the unit tests use, which models the create-nothing
 * probe the routing runs. Its replica storage is RxDB's memory storage with
 * a collection-state map of its own (the package default shares one map
 * across the process).
 *
 * @param [options] {object}
 * @param [options.name] {string}   a label for messages
 * @returns {BrowserProfile}
 */
function coldProfile({
  name = 'profile'
}: { name?: string } = {}): BrowserProfile {
  const { idb, databaseNames, sessionStore } = createFakeSessionIdb()
  const collectionStates: RxStorageMemory['collectionStates'] = new Map()
  // The spread keeps the package's `createStorageInstance`, which reads the
  // map off `this`, so this profile's instances land in its own map.
  const replicaStorage: RxStorageMemory = {
    ...getRxStorageMemory(),
    collectionStates
  }
  return {
    name,
    idb,
    replicaStorage: replicaStorage as RxStorage<unknown, unknown>,
    databaseNames,
    sessionStore,
    replicaCollectionCount: () => collectionStates.size,
    wipe() {
      databaseNames.clear()
      sessionStore.clear()
      collectionStates.clear()
    }
  }
}

/**
 * A fresh test passkey: a random credential id and 32 random PRF bytes.
 *
 * @returns {TestPasskey}
 */
export function createTestPasskey(): TestPasskey {
  return {
    credentialId: crypto.getRandomValues(new Uint8Array(16)),
    prfOutput: crypto.getRandomValues(new Uint8Array(32))
  }
}

/**
 * The registration ceremony `addAccountPasskey` takes in place of WebAuthn's:
 * an authenticator that answers with the test passkey's credential id and
 * PRF output, with no transports and both backup flags clear.
 *
 * @param options {object}
 * @param options.passkey {TestPasskey}
 * @returns {() => Promise<PasskeyRegistration>}
 */
export function testAuthenticator({
  passkey
}: {
  passkey: TestPasskey
}): () => Promise<PasskeyRegistration> {
  return async () => ({
    credentialId: passkey.credentialId,
    transports: [],
    prfOutput: passkey.prfOutput,
    backupEligibility: false,
    backupState: false
  })
}

/**
 * Waits for one part of a visit's background work and captures how it
 * ended: `undefined` once it resolved (or when the session carries no such
 * part), the failure once it rejected. Never rejects.
 *
 * @param options {object}
 * @param options.source {string}   the part's name in a failure
 * @param [options.work] {Promise<unknown>}   the part, when the session has
 *   it
 * @returns {Promise<BackgroundFailure | undefined>}
 */
async function captureFailure({
  source,
  work
}: {
  source: string
  work?: Promise<unknown>
}): Promise<BackgroundFailure | undefined> {
  try {
    await work
    return undefined
  } catch (err) {
    return { source, error: err }
  }
}

/**
 * Opens a tab and enters a session in it: the entry call, then the steps the
 * login page's post-login sequence (`completeAppLogin`) runs that are not
 * UI. Storage provisioning is awaited, the Login activity is recorded, and
 * the recovery health check starts. The auth store adoption, the CHAPI
 * handler registration, the toasts, and the navigation are not run.
 *
 * @param options {object}
 * @param options.name {string}
 * @param options.profile {BrowserProfile}
 * @param options.wallet {WalletModules}
 * @param options.faults {RequestFaults}   the server's request recorder
 * @param options.enter {() => Promise<Session>}   the entry call
 * @returns {Promise<WalletActor>}
 */
async function enterTab({
  name,
  profile,
  wallet,
  faults,
  enter
}: {
  name: string
  profile: BrowserProfile
  wallet: WalletModules
  faults: RequestFaults
  enter: () => Promise<Session>
}): Promise<WalletActor> {
  const recorder: TabRecorder = { name, events: [] }
  const firstRequest = faults.requests.length
  let lastRequest: number | undefined
  const startedAt = Date.now()
  const started = performance.now()
  // The session once `enter()` returns it, so a failure after that point
  // can still tear it down.
  const entry: { session?: Session } = {}
  let entered: {
    session: Session
    spaceId: string
    background: Promise<BackgroundFailure | undefined>[]
  }
  try {
    entered = await inTab({
      recorder,
      work: async () => {
        const session = await enter()
        entry.session = session
        const spaceUrl = session.profile.accountPointer?.spaceUrl
        if (!spaceUrl) {
          throw new Error('The session carries no account pointer.')
        }
        const spaceId = spaceIdOfUrl(spaceUrl)
        await session.storageReady
        return {
          session,
          spaceId,
          background: [
            // `recordWalletLogin`'s one write, with its handle kept: the app
            // voids it, and `settled()` has to wait on it.
            captureFailure({
              source: 'loginActivity',
              work: session.storage.addHistoryWalletLogin({
                user: session.user
              })
            }),
            // Fire-and-forget in the app; held here for the same reason.
            captureFailure({
              source: 'recoveryHealth',
              work: wallet.checkRecoveryHealth({ session })
            })
          ]
        }
      }
    })
  } catch (err) {
    const failed = entry.session
    if (failed) {
      // A session that failed its entry still runs its mender block, and a
      // remembered one holds its replica open. Wait that work out and close
      // the session, so none of it outlives the server `close()` shuts down.
      await Promise.allSettled([
        failed.registryReady,
        failed.mends,
        failed.welcomeSeedReady,
        failed.writerRegistration
      ])
      await inTab({
        recorder,
        work: () => wallet.closeUnenteredSession(failed)
      })
    }
    throw err
  }
  const { session, spaceId } = entered
  const entryMs = performance.now() - started
  // Each part's outcome is captured now, so a rejection is held for
  // `settled()` rather than reported as unhandled.
  const outcomes = [
    captureFailure({ source: 'storageReady', work: session.storageReady }),
    captureFailure({ source: 'registryReady', work: session.registryReady }),
    captureFailure({ source: 'mends', work: session.mends }),
    captureFailure({
      source: 'welcomeSeedReady',
      work: session.welcomeSeedReady
    }),
    captureFailure({
      source: 'writerRegistration',
      work: session.writerRegistration
    }),
    ...entered.background
  ]
  const kind =
    session.persistence.storage === 'in-memory' ? 'transient' : 'remembered'
  let state: ActorState = 'live'
  let settledMs: number | undefined
  let failures: BackgroundFailure[] = []

  function requireLive(action: string): void {
    if (state !== 'live') {
      throw new Error(`Cannot ${action}: the actor "${name}" is ${state}.`)
    }
  }

  return {
    name,
    profile,
    session,
    kind,
    spaceId,
    events: recorder.events,
    startedAt,
    entryMs,
    state: () => state,
    serverRequests: () => faults.requests.slice(firstRequest, lastRequest),
    async settled() {
      if (settledMs === undefined) {
        const rejected = await Promise.all(outcomes)
        // A rejected `mends` is already in `rejected`.
        const report = (await session.mends?.catch(() => undefined)) ?? []
        failures = [
          ...rejected.filter(failure => failure !== undefined),
          ...report
            .filter(mend => mend.outcome === 'failed')
            .map(mend => ({ source: `mends ${mend.invariant}`, error: mend }))
        ]
        settledMs = performance.now() - started
        lastRequest = faults.requests.length
      }
      return { settledMs, failures }
    },
    async run(work) {
      requireLive('run work')
      return await inTab({ recorder, work: () => work(session) })
    },
    async logout() {
      requireLive('log out')
      state = 'logged-out'
      await inTab({
        recorder,
        work: () => wallet.discardSession(session)
      })
    },
    drop() {
      if (state === 'live') {
        state = 'dropped'
      }
    }
  }
}
