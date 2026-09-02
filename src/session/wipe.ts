/**
 * The shared wipe enumeration: the ONE list of browser-local state a wallet
 * account leaves on a browser, and the one executor that deletes it. Its
 * consumers are the deletion-shaped ceremonies -- account deletion, the guest
 * wipe, the forget ceremony and its login-time detector
 * (`src/session/forget.ts`), and (when it lands) the orphan-client heal --
 * so the incomplete-enumeration bug class is a single-point fix rather than
 * a per-caller audit.
 *
 * The internal order is snapshot-first: every target is derived from the
 * live session's state (the client-key record's own identity, the account
 * pointer, the unlock-methods registry) BEFORE anything is deleted, which
 * makes the deletion order among the middle stages irrelevant. Cross-tab
 * teardown precedes the replica delete, and the replica delete verifies
 * completion rather than resolving while blocked (both inside
 * `BrowserStore.wipeStorage`).
 *
 * What no enumeration reaches, honestly: forensic recoverability of deleted
 * IndexedDB data (the plaintext `public-credentials` rows included), the
 * CHAPI popup's partitioned third-party buckets, and the mediator-origin
 * (authn.io) "a wallet handler is registered here" bit -- only clearing the
 * browser profile removes those. Global UI prefs (theme, language) are not
 * account state and stay out; the global `writerId` is cleared only when the
 * consumer asks (the forget grade), since it is browser-global rather than
 * account-scoped.
 */
import { deriveSpaceId } from '@interop/was-client/sync'
import {
  deleteAccountDidForSpace,
  deletePasskeySafetyNotice,
  deleteUnlockLocalState,
  deleteUnlockMethodsCache,
  sessionDatabaseExists
} from '@/lib/sessionKey'
import { clearWriterId } from '@/lib/writerId'
import { BrowserStore, migrationMarkerKeys } from '@/stores/browserStore'
import { deleteLocalCacheFamilies } from '@/session/persistence'
import type { UnlockMethodsRecord } from '@/session/unlockMethods'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:wipe')

/**
 * Every browser-local target the wipe deletes, derived up front. The members
 * keyed by this browser's own client did:key (`clientDid`, and the
 * `dbPrefix` / cache scopes derived from it) deliberately come from
 * `session.user.id` -- the identity the client-key record established --
 * never from the account controller, which names a different key on an
 * enrolled second client.
 */
export interface WipeTargets {
  /**
   * This browser's client did:key (`session.user.id`). Also the source of
   * the replica-database and migration-marker prefix,
   * `deriveSpaceId(clientDid)` (the `BrowserStore.initClient` derivation),
   * re-derived where needed rather than carried as a separate field.
   */
  clientDid: string
  /**
   * The account data Space id; keys the Space-to-DID mapping.
   */
  accountSpaceId?: string
  /**
   * The account's own identifiers -- the account controller did:key and the
   * account did:webvh where the pointer names one -- unioned with every
   * ENROLLED CLIENT's own did:key, as the consumer read them off the verified
   * account document (`did:key:<the signing method's multibase>`).
   *
   * The client-keyed families are enumerated under these BESIDE `clientDid`,
   * because a transient visit's `clientDid` is a per-visit annex key that
   * names none of the state an enrolled client of the same account left here:
   * its unlock-methods cache, its passkey-safety notice, its local-mode cache
   * scope, its migration markers, and -- the one that holds real credential
   * data -- its replica database, whose prefix is `deriveSpaceId(did:key)`.
   * Enumerating a superset costs a no-op delete per absent key.
   */
  accountDids: string[]
  /**
   * Every unlock method's unlock Space id -- each keys that method's local
   * state (keyring cache, client-key record): the whole registry, unioned
   * with the live session's own credential (`profile.unlockMethod` and
   * `profile.standingUnlock`), so a registry the consumer could not read
   * still leaves the login credential's own state -- this browser's client
   * seed and its cached user key -- in the enumeration.
   */
  unlockSpaceIds: string[]
  /**
   * Whether the consumer's registry read failed (as opposed to finding no
   * registry). The enumeration above then holds at minimum the session's
   * own credential, and the executor reports the narrowing as a failed
   * stage rather than letting the wipe read as clean.
   */
  registryUnread: boolean
  /**
   * The descriptor/meta localStorage cache scopes: the account Space id
   * (remote mode) and `local:<clientDid>` (local mode) -- both are covered,
   * since a browser may have run either.
   */
  cacheScopes: string[]
}

/**
 * Derives the wipe targets from a live session, before anything is deleted.
 * The unlock-methods registry and the annex Space id are supplied by the
 * caller's own discovery (the registry rides in the data Space and the
 * annex behind the account document's pointer, so reading either is the
 * consumer's ceremony-specific step); absent, the affected families are
 * narrowed, with one exception: the unlock Space of the credential the
 * session itself logged in with (`profile.unlockMethod`, and the standing
 * members' `unlockSpaceId`) is always enumerated, so a registry read lost
 * to a transient server error can never leave this browser's client-key
 * record behind a wipe reported as clean. A read that failed is passed as
 * `registryUnread` and reported by the executor.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.registry] {UnlockMethodsRecord | null}
 * @param [options.registryUnread] {boolean}   the consumer's registry read
 *   failed (default false: the registry was read, or the consumer has none)
 * @param [options.enrolledClientDids] {string[]}   every enrolled client's own
 *   did:key, from the consumer's verified account document; absent, only this
 *   session's own client and the account's identifiers are enumerated, and a
 *   sibling client's replica survives
 * @returns {WipeTargets}
 */
export function snapshotWipeTargets({
  session,
  registry,
  registryUnread = false,
  enrolledClientDids = []
}: {
  session: Session
  registry?: UnlockMethodsRecord | null
  registryUnread?: boolean
  enrolledClientDids?: string[]
}): WipeTargets {
  const clientDid = session.user.id
  const accountSpaceId = session.profile.accountPointer?.spaceId
  const { unlockMethod, standingUnlock, accountController, accountPointer } =
    session.profile
  const unlockSpaceIds = new Set<string>([
    ...(unlockMethod ? [unlockMethod.unlockSpaceId] : []),
    ...(standingUnlock ? [standingUnlock.unlockSpaceId] : []),
    ...(registry?.methods ?? []).map(entry => entry.unlockSpaceId)
  ])
  const accountDids = [
    ...new Set(
      [accountController, accountPointer?.did, ...enrolledClientDids].filter(
        (did): did is string => typeof did === 'string' && did !== clientDid
      )
    )
  ]
  return {
    clientDid,
    accountSpaceId,
    accountDids,
    unlockSpaceIds: [...unlockSpaceIds],
    registryUnread,
    cacheScopes: [
      ...(accountSpaceId ? [accountSpaceId] : []),
      ...[clientDid, ...accountDids].map(did => `local:${did}`)
    ]
  }
}

/**
 * Executes the local wipe over a snapshot: the replica databases (cross-tab
 * teardown plus verified completion), the session database's families, and
 * the per-account localStorage families. Every stage is best-effort and the
 * failures are collected, never aborting the rest -- the report's stage
 * names let a consumer decide what a failure means (account deletion treats
 * a surviving replica as fatal; everything else is hygiene residue).
 *
 * A stage that ran but could not be CONFIRMED is neither a success nor a
 * failure, and is reported separately (`unverified`): a browser without
 * `indexedDB.databases()` cannot re-probe a replica delete. The delete is
 * issued regardless -- skipping it would leave real data behind -- and the
 * consumer states the unconfirmed outcome instead of claiming a clean wipe.
 *
 * The replica stage runs twice: once through the session's own store (which
 * carries the cross-tab teardown for the database this session has open), and
 * once per enumerated client did:key by name, which is the only pass that
 * reaches a transient session's replica-less browser and a SIBLING enrolled
 * client's database. Deleting an absent database is a no-op.
 *
 * @param options {object}
 * @param options.targets {WipeTargets}
 * @param [options.storage] {{ wipeLocalStorage: () => Promise<{ verified: boolean } | void> }}
 *   the session's StorageManager; absent, the replica stage is skipped
 * @param [options.idb] {IDBFactory}   the session-database factory (the
 *   Storage Access seam: a popup-begun session supplies its unpartitioned
 *   factory here)
 * @param [options.clearWriter] {boolean}   whether to clear the global
 *   `writerId` (the forget grade; account deletion and the guest wipe leave
 *   the browser-global id in place)
 * @returns {Promise<{ failed: string[], unverified: string[] }>}
 */
export async function executeLocalWipe({
  targets,
  storage,
  idb,
  clearWriter = false
}: {
  targets: WipeTargets
  storage?: { wipeLocalStorage: () => Promise<{ verified: boolean } | void> }
  idb?: IDBFactory
  clearWriter?: boolean
}): Promise<{ failed: string[]; unverified: string[] }> {
  const failed: string[] = []
  const unverified: string[] = []
  async function stage(name: string, run: () => Promise<void> | void) {
    try {
      await run()
    } catch (err) {
      failed.push(name)
      log.warn('Local wipe stage failed', { stage: name, err })
    }
  }

  // A registry the consumer could not read is a narrowed enumeration (the
  // other unlock methods' local state may survive), reported as a failed
  // stage up front so the outcome never reads as clean.
  if (targets.registryUnread) {
    failed.push('unlock-methods-registry')
  }

  // The replica databases first (cross-tab teardown rides inside).
  //
  // Two passes, because the session's own StorageManager reaches only the
  // replica this session opened: a transient session opened none at all, and
  // no session ever opens a SIBLING enrolled client's. The second pass names
  // each enumerated client's replica by its own prefix and deletes it
  // through the same `BrowserStore.wipeStorage` path (teardown broadcast and
  // verified re-probe included), which needs no live store and no keys.
  if (storage) {
    await stage('replica', async () => {
      const result = await storage.wipeLocalStorage()
      if (result && result.verified === false) {
        unverified.push('replica')
      }
    })
  }
  if (typeof indexedDB !== 'undefined') {
    for (const did of [targets.clientDid, ...targets.accountDids]) {
      const dbPrefix = deriveSpaceId(did)
      await stage(`replica:${dbPrefix}`, async () => {
        const { verified } = await new BrowserStore({ dbPrefix }).wipeStorage()
        if (!verified) {
          unverified.push(`replica:${dbPrefix}`)
        }
      })
    }
  }

  // The session database's families -- guarded by a create-nothing probe, so
  // a wipe on a browser that never held session state does not create the
  // database it set out to remove. A failing probe proceeds anyway: deleting
  // from an existing database must not be skippable by a probe hiccup.
  const haveSessionDb = await sessionDatabaseExists({ idb }).catch(() => true)
  if (haveSessionDb) {
    for (const unlockSpaceId of targets.unlockSpaceIds) {
      await stage(`unlock-local-state:${unlockSpaceId}`, async () => {
        await deleteUnlockLocalState({ spaceId: unlockSpaceId, idb })
      })
    }
    if (targets.accountSpaceId) {
      const spaceId = targets.accountSpaceId
      await stage('space-did-mapping', async () => {
        await deleteAccountDidForSpace({ spaceId, idb })
      })
    }
    // Keyed on this browser's own client did:key AND on the account: a
    // transient visit's client did:key is a per-visit annex key, so the
    // families an enrolled client of the same account left here are named by
    // the account instead. An absent key deletes as a no-op.
    for (const controller of [targets.clientDid, ...targets.accountDids]) {
      await stage(`unlock-methods-cache:${controller}`, async () => {
        await deleteUnlockMethodsCache({ controller, idb })
      })
      await stage(`passkey-safety-notice:${controller}`, async () => {
        await deletePasskeySafetyNotice({ controller, idb })
      })
    }
  }

  // The per-account localStorage families, last (markers after state).
  for (const scope of targets.cacheScopes) {
    await stage(`cache-families:${scope}`, () => {
      deleteLocalCacheFamilies({ scope })
    })
  }
  await stage('migration-markers', () => {
    if (typeof localStorage === 'undefined') {
      return
    }
    for (const did of [targets.clientDid, ...targets.accountDids]) {
      const markers = migrationMarkerKeys(deriveSpaceId(did))
      localStorage.removeItem(markers.plaintext)
      localStorage.removeItem(markers.publicCids)
    }
  })
  if (clearWriter) {
    await stage('writer-id', () => {
      clearWriterId()
    })
  }
  return { failed, unverified }
}

/**
 * The guest-wipe consumer: a guest session's whole browser-local residue is
 * its replica databases, the migration markers, and (in principle)
 * local-mode cache families, all derived from the guest's random client
 * did:key. The guest holds no keyring and no registry, so those families
 * enumerate empty by construction.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<{ failed: string[], unverified: string[] }>}
 */
export async function wipeGuestState({
  session
}: {
  session: Session
}): Promise<{ failed: string[]; unverified: string[] }> {
  return await executeLocalWipe({
    targets: snapshotWipeTargets({ session }),
    storage: session.storage ?? undefined
  })
}
