/**
 * The shared wipe enumeration: the ONE list of durable local state a wallet
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
  deleteLogPinsForSpace,
  deletePasskeySafetyNotice,
  deleteUnlockLocalTrio,
  deleteUnlockMethodsCache,
  deleteUserKeyEpochPin,
  sessionDatabaseExists
} from '@/lib/sessionKey'
import { clearWriterId } from '@/lib/writerId'
import { migrationMarkerKeys } from '@/stores/browserStore'
import { deleteLocalCacheFamilies } from '@/session/persistence'
import type { UnlockMethodsRecord } from '@/session/unlockMethods'
import type { Session } from '@/types/auth'

/**
 * Every durable local target the wipe deletes, derived up front. The members
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
   * The account did:webvh (or did:key pre-promotion), when the session holds
   * a pointer; keys the roster-epoch pin.
   */
  accountDid?: string
  /**
   * The account data Space id; keys the chain-head pin slots and the
   * Space-to-DID mapping.
   */
  accountSpaceId?: string
  /**
   * The auxiliary annex Space id, when the consumer's discovery found
   * one; its pin slots are cleared by prefix (one per generation, with the
   * generation ids possibly no longer listable).
   */
  clientAnnexSpaceId?: string
  /**
   * Every unlock method's unlock Space id, across the whole registry -- each
   * keys a local trio (keyring cache, client-key record, freshness pin).
   */
  unlockSpaceIds: string[]
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
 * simply not enumerated -- best-effort narrowing, never a failure.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param [options.registry] {UnlockMethodsRecord | null}
 * @param [options.clientAnnexSpaceId] {string}
 * @returns {WipeTargets}
 */
export function snapshotWipeTargets({
  session,
  registry,
  clientAnnexSpaceId
}: {
  session: Session
  registry?: UnlockMethodsRecord | null
  clientAnnexSpaceId?: string
}): WipeTargets {
  const clientDid = session.user.id
  const accountSpaceId = session.profile.accountPointer?.spaceId
  return {
    clientDid,
    accountDid: session.profile.accountPointer?.did,
    accountSpaceId,
    clientAnnexSpaceId,
    unlockSpaceIds: (registry?.methods ?? []).map(entry => entry.unlockSpaceId),
    cacheScopes: [
      ...(accountSpaceId ? [accountSpaceId] : []),
      `local:${clientDid}`
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
 * @param options {object}
 * @param options.targets {WipeTargets}
 * @param [options.storage] {{ wipeLocalStorage: () => Promise<void> }}   the
 *   session's StorageManager; absent, the replica stage is skipped
 * @param [options.idb] {IDBFactory}   the session-database factory (the
 *   Storage Access seam: a popup-begun session supplies its unpartitioned
 *   factory here)
 * @param [options.clearWriter] {boolean}   whether to clear the global
 *   `writerId` (the forget grade; account deletion and the guest wipe leave
 *   the browser-global id in place)
 * @returns {Promise<{ failed: string[] }>}
 */
export async function executeLocalWipe({
  targets,
  storage,
  idb,
  clearWriter = false
}: {
  targets: WipeTargets
  storage?: { wipeLocalStorage: () => Promise<void> }
  idb?: IDBFactory
  clearWriter?: boolean
}): Promise<{ failed: string[] }> {
  const failed: string[] = []
  async function stage(name: string, run: () => Promise<void> | void) {
    try {
      await run()
    } catch (err) {
      failed.push(name)
      console.warn(`Local wipe stage "${name}" failed:`, err)
    }
  }

  // The replica databases first (cross-tab teardown rides inside).
  if (storage) {
    await stage('replica', async () => await storage.wipeLocalStorage())
  }

  // The session database's families -- guarded by a create-nothing probe, so
  // a wipe on a browser that never held session state does not create the
  // database it set out to remove. A failing probe proceeds anyway: deleting
  // from an existing database must not be skippable by a probe hiccup.
  const haveSessionDb = await sessionDatabaseExists({ idb }).catch(() => true)
  if (haveSessionDb) {
    for (const unlockSpaceId of targets.unlockSpaceIds) {
      await stage(`unlock-trio:${unlockSpaceId}`, async () => {
        await deleteUnlockLocalTrio({ spaceId: unlockSpaceId, idb })
      })
    }
    if (targets.accountDid) {
      const accountDid = targets.accountDid
      await stage('epoch-pin', async () => {
        await deleteUserKeyEpochPin({ accountDid, idb })
      })
    }
    if (targets.accountSpaceId) {
      const spaceId = targets.accountSpaceId
      await stage('account-log-pins', async () => {
        await deleteLogPinsForSpace({ spaceId, idb })
      })
      await stage('space-did-mapping', async () => {
        await deleteAccountDidForSpace({ spaceId, idb })
      })
    }
    if (targets.clientAnnexSpaceId) {
      const spaceId = targets.clientAnnexSpaceId
      await stage('clientAnnex-log-pins', async () => {
        await deleteLogPinsForSpace({ spaceId, idb })
      })
    }
    await stage('unlock-methods-cache', async () => {
      await deleteUnlockMethodsCache({ controller: targets.clientDid, idb })
    })
    await stage('passkey-safety-notice', async () => {
      await deletePasskeySafetyNotice({ controller: targets.clientDid, idb })
    })
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
    const markers = migrationMarkerKeys(deriveSpaceId(targets.clientDid))
    localStorage.removeItem(markers.plaintext)
    localStorage.removeItem(markers.publicCids)
  })
  if (clearWriter) {
    await stage('writer-id', () => {
      clearWriterId()
    })
  }
  return { failed }
}

/**
 * The guest-wipe consumer: a guest session's whole durable footprint is its
 * replica databases, the migration markers, and (in principle) local-mode
 * cache families, all derived from the guest's random client did:key. The
 * guest holds no keyring, no pins, and no registry, so those families
 * enumerate empty by construction.
 *
 * @param options {object}
 * @param options.session {Session}
 * @returns {Promise<{ failed: string[] }>}
 */
export async function wipeGuestState({
  session
}: {
  session: Session
}): Promise<{ failed: string[] }> {
  return await executeLocalWipe({
    targets: snapshotWipeTargets({ session }),
    storage: session.storage ?? undefined
  })
}
