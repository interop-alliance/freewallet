/**
 * Client revocation: disconnecting an enrolled wallet client from the
 * account -- the synchronous cascade the identity model's revocation spike
 * verified, run in the revoking client, in dependency order:
 *
 * 1. **The did:webvh document edit** (`revokeWebvhClient`): the revoked
 *    client's verification methods, update key, and both standing
 *    commitments leave in one log entry. Under the current-key-set rule this
 *    single edit is the revoked client's pull axis everywhere -- its
 *    invocations, and every delegation and app grant it signed, stop
 *    verifying the moment its verification method leaves the document. There
 *    is no per-collection revoke; apps reconnect through the ordinary App
 *    Connect flow.
 * 2. **The PUK rotation** in the `key-map/puk.json` roster, recipients
 *    resolved from the just-updated verified document (the roster delivers,
 *    never sources -- the revoked client's entry is dropped even before the
 *    retire filter).
 * 3. **The epoch cascade**: every encrypted collection re-epoch'd onto the
 *    fresh PUK in parallel, the revoked generations retired, history
 *    escrowed (`cascadeCollectionsToPuk`).
 * 4. **The recovery re-PUTs** (`remintRecoveryDelegations`): the recovery
 *    delegations the revoked client had signed are re-minted by this client
 *    and the unlock records re-PUT in the same fan-out.
 *
 * The revoking session then adopts the fresh PUK in place (it minted it),
 * and the cascade is convergent under a naive full re-run: every stage
 * detects completion from durable state alone -- the log entry is
 * idempotent, the roster no-ops once the entry is off the current epoch, and
 * a collection is stale exactly when its current epoch names a non-current
 * PUK generation -- so a mid-cascade crash strands nothing permanently (the
 * completion sweep is the standing backstop). The honest ceiling is
 * unchanged: ciphertext the revoked client already fetched stays readable to
 * it, and old epochs open to the keys it already held.
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import {
  clientSigningKeyMultibase,
  revokeWebvhClient,
  type RevokedClientKeys
} from '@interop/wallet-core/webvh'
import {
  pukVaultKeys,
  readPukRoster,
  rotatePukRoster
} from '@interop/wallet-core/keys'
import { isWebvhDid } from '@interop/wallet-core/webvh'
import { WAS_SERVER_URL } from '@/app.config'
import type { Session } from '@/types/auth'
import { savePukEpochPin } from '@/lib/sessionKey'
import { getUnlockMethods, rewrapUnlockMethodsRecord } from '@/session/unlockMethods'
import {
  remintRecoveryDelegations,
  verifyAccountLog
} from '@/session/recovery'
import {
  cascadeCollectionsToPuk,
  type PukCascadeResult
} from '@/session/pukCascade'

export type { RevokedClientKeys } from '@interop/wallet-core/webvh'

/**
 * What a completed revocation cascade reports: whether the roster actually
 * rotated on this run (a naive re-run of an already-complete revocation
 * reports `false` everywhere), the per-collection outcomes, and the recovery
 * re-mint counts.
 */
export interface RevocationOutcome {
  rotated: boolean
  collections: PukCascadeResult
  recovery: { reminted: number; skipped: number }
}

/**
 * The revocation preconditions, resolved from a live session: a configured
 * WAS server and remote store, a promoted did:webvh account pointer, and
 * this client's own key material. Mirrors the recovery-issuance gate -- an
 * enrolled wallet client holding its key material is what can revoke.
 *
 * @param session {Session}
 * @returns {object}   the resolved pieces
 */
function requireRevocationPreconditions(session: Session) {
  const remoteStore = session.storage.remoteStore
  if (!WAS_SERVER_URL || !remoteStore) {
    throw new Error('Client revocation requires a configured storage server.')
  }
  const { profile } = session
  const pointer = profile.accountPointer
  if (!pointer || !isWebvhDid(pointer.did)) {
    throw new Error(
      'Client revocation requires a promoted did:webvh account; this ' +
        'account has not finished provisioning.'
    )
  }
  if (!profile.clientWebvhKeys) {
    throw new Error(
      "Client revocation requires this client's did:webvh update keys."
    )
  }
  if (!profile.clientKeyAgreementKey) {
    throw new Error(
      "Client revocation requires this client's key-agreement key."
    )
  }
  return {
    remoteStore,
    pointer,
    clientWebvhKeys: profile.clientWebvhKeys,
    clientKeyAgreementKey: profile.clientKeyAgreementKey
  }
}

/**
 * The revoked client's roster kid: its key-agreement key's id exactly as its
 * own `agentsFromSeed` derives it (`did:key:<ed-multibase>#<x-multibase>`) --
 * the same shape the enrollment ceremony minted its wrap under.
 *
 * @param client {RevokedClientKeys}
 * @returns {string}
 */
function revokedRosterKid(client: RevokedClientKeys): string {
  return `did:key:${client.signingKeyMultibase}#${client.keyAgreementKeyMultibase}`
}

/**
 * Runs the whole revocation cascade for one enrolled wallet client. See the
 * module doc for the order and the convergence story. Throws before touching
 * anything on a malformed call (self-revocation, missing key material); once
 * the document edit lands, every later stage is best-effort-but-resumable --
 * a thrown stage leaves durable state a naive re-run (or the completion
 * sweep) converges from.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.client {RevokedClientKeys}   the revoked client's public
 *   halves (its two verification-method multibases and its active update key)
 * @param [options.label] {string}   a display label for the history record
 * @param [options.idb] {IDBFactory}
 * @returns {Promise<RevocationOutcome>}
 */
export async function revokeEnrolledClient({
  session,
  client,
  label,
  idb
}: {
  session: Session
  client: RevokedClientKeys
  label?: string
  idb?: IDBFactory
}): Promise<RevocationOutcome> {
  const { remoteStore, pointer, clientWebvhKeys, clientKeyAgreementKey } =
    requireRevocationPreconditions(session)

  // Self-revocation is refused up front (the document edit would also refuse
  // on the update key, but the UI-facing error should name the real rule).
  const { keyAgent } = session.profile
  if (
    keyAgent &&
    clientSigningKeyMultibase({ keyAgent }) === client.signingKeyMultibase
  ) {
    throw new Error(
      'This client cannot disconnect itself; use another enrolled wallet ' +
        'client (or a recovery code) instead.'
    )
  }

  // The standing recovery codes' update-key hashes, so the document edit can
  // tell the revoked client's staged commitment apart from a latent recovery
  // commitment (the one ambiguous log shape). Best-effort: an unreadable
  // registry falls back to attribution without them.
  let knownLatentHashes: string[] = []
  try {
    const record = await getUnlockMethods({ session, idb })
    knownLatentHashes = await Promise.all(
      (record?.methods ?? [])
        .filter(method => method.type === 'recovery-code')
        .map(method => deriveNextKeyHash(method.updateKeyMultibase))
    )
  } catch (err) {
    console.warn(
      'Could not read the recovery registry for the revocation edit:',
      err
    )
  }

  // 1. The document edit -- the pull axis everywhere, first.
  await revokeWebvhClient({
    idStore: remoteStore,
    updateKeys: clientWebvhKeys,
    revokedClient: client,
    knownLatentHashes
  })

  // 2. The PUK rotation, recipients resolved from the just-updated verified
  // document.
  const { doc } = await verifyAccountLog({ pointer })
  const rosterStore = remoteStore.pukRosterStore()
  await rotatePukRoster({
    store: rosterStore,
    document: doc,
    retireRecipientId: revokedRosterKid(client)
  })
  const read = await readPukRoster({
    store: rosterStore,
    puk: session.profile.puk,
    clientKeyAgreementKey
  })
  if (!read) {
    throw new Error('The account has no PUK roster; nothing to rotate.')
  }
  await savePukEpochPin({
    spaceId: pointer.spaceId,
    epochId: read.latestEpochId,
    idb
  })
  if (read.rotated) {
    await session.profile.persistClientKeys?.({ puk: read.puk })
  }

  // 3. The epoch cascade, in parallel -- run even when this call found the
  // roster already rotated (a naive re-run after a crash), because the
  // staleness rule finds exactly the stranded collections.
  const collections = await cascadeCollectionsToPuk({
    remoteStore,
    rosterDescriptor: read.descriptor,
    clientKeyAgreementKey,
    puk: read.puk
  })

  // 4. The recovery re-PUTs: delegations the revoked client signed stopped
  // chaining at step 1; re-mint them while the registry is still readable
  // under the session's current vault keys.
  const recovery = await remintRecoveryDelegations({ session, doc, idb })

  // Re-seal the unlock-methods registry to the rotated PUK, then adopt the
  // rotation in the live session (profile vault keys + storage ciphers), so
  // this session keeps operating without a re-login.
  const { keyAgreementKey, keyResolver } = session.profile
  if (read.rotated) {
    if (keyAgreementKey && keyResolver && WAS_SERVER_URL) {
      try {
        await rewrapUnlockMethodsRecord({
          storageServerUrl: WAS_SERVER_URL,
          zcapClient: session.profile.zcapClient,
          spaceId: pointer.spaceId,
          from: { keyAgreementKey, keyResolver },
          to: pukVaultKeys({ puk: read.puk })
        })
      } catch (err) {
        console.warn(
          'Could not re-wrap the unlock-methods registry to the rotated PUK:',
          err
        )
      }
    }
    const vaultKeys = pukVaultKeys({ puk: read.puk })
    session.profile.puk = read.puk
    session.profile.keyAgreementKey = vaultKeys.keyAgreementKey
    session.profile.keyResolver = vaultKeys.keyResolver
    try {
      await session.storage.adoptRotatedVaultKeys(vaultKeys)
    } catch (err) {
      console.warn(
        'Could not rebuild the storage ciphers on the rotated PUK; the next ' +
          'login adopts it instead:',
        err
      )
    }
  }

  // The audit record, written after the adoption so it lands under the fresh
  // epoch. Best-effort.
  try {
    await session.storage.addHistoryClientRevoked({
      user: session.user,
      signingKeyMultibase: client.signingKeyMultibase,
      label,
      rotated: Object.values(collections.outcomes).filter(
        outcome => outcome === 'rotated'
      ).length,
      failed: collections.failed.length
    })
  } catch (err) {
    console.warn('Could not record the client-revocation activity:', err)
  }

  return { rotated: read.rotated, collections, recovery }
}
