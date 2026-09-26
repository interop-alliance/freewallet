/**
 * The entry-first establishment of a standing credential added to a live
 * account: a passkey (the add-a-passkey ceremony) or a backup credential
 * (the backup export). Both kinds are high-entropy, so their `keyAgreement`
 * key publishes verbatim, and both are identified in the registry by their
 * unlock Space. The ceremony supplies the kind-specific parts: the secret,
 * the KDF it derives under, the entry as written, and any establishment
 * option. This module owns the order the two share -- the bare entry written
 * BEFORE the establishment, the establishment, the verify-then-act cleanup
 * behind a failure, and the completion write -- so the two ceremonies differ
 * only in what they mint and in the error they fail with.
 */
import type { UnlockKdf } from '@interop/wallet-core/keyring'
import { ladderRung } from '@interop/wallet-core/clientAnnex'
import {
  establishStandingUnlock,
  standingFieldsOfKeyringHit
} from '@/session/standingUnlock'
import {
  deleteUnlockMethod,
  fetchKeyring,
  keyAgreementPublicationOf,
  type KeyringFetchResult,
  type UnlockCredential
} from '@/session/keyring'
import {
  dropRegistryEntry,
  isLoginEntry,
  updateUnlockMethods,
  upsertUnlockMethod,
  type BackupCredentialUnlockMethod,
  type PasskeyUnlockMethod,
  type StandingUnlockFields,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import type { AccountCeremonyContext } from '@/session/accountCeremonyContext'
import { documentListsCredential } from '@/session/pendingRetirement'
import {
  isUnclaimedLadderVmRefusal,
  rotateOffUnlockCredential
} from '@/session/credentialRotation'
import { reportCeremonyTail } from '@/session/menders/ceremonyTail'
import { adoptRotatedUserKey, rotationSpaceId } from '@/session/userKeyAdoption'
import {
  invalidateVerifiedLog,
  verifiedAccountLog
} from '@/session/verifiedLog'
import type { Session } from '@/types/auth'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:settings')

/**
 * The registry entry kinds written entry-first: the high-entropy standing
 * credentials.
 */
type StandingEstablishedMethod =
  PasskeyUnlockMethod | BackupCredentialUnlockMethod

/**
 * The entry-first establishment, in the order both kinds share:
 *
 * 1. The bare entry, merged into a fresh registry read (a concurrent write
 *    must survive). A write that fails throws with no residue anywhere.
 * 2. The establishment (`establishStandingUnlock`): roster wrap, record,
 *    document entry, bridge delegation. Its failure runs the
 *    verify-then-act cleanup (`recoverFailedStandingEstablishment`); a
 *    cleanup that proves a lost-response success completes the entry and
 *    returns normally, any other rethrows the establishment's own failure.
 * 3. The completion write (`completeStandingEntry`): the same entry
 *    completed in place with the key-agreement multibase, the standing
 *    fields, and the establishment's management zcap.
 *
 * The caller wraps whatever this throws in its own ceremony's error.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext | null}
 * @param options.secret {Uint8Array}   the credential's secret (a passkey's
 *   PRF output, a backup credential's random bytes)
 * @param options.kdf {UnlockKdf}   the KDF the secret derives under
 * @param options.credential {UnlockCredential}   its derived credential
 * @param options.ladderSeed {Uint8Array}   the ceremony-minted ladder seed,
 *   minted by the caller so a failure cleanup still holds rung 0 and the
 *   attribution seed an actual retirement needs
 * @param options.entry {StandingEstablishedMethod}   the bare entry as the
 *   ceremony writes it
 * @param options.base {UnlockMethodsRecord}   the ceremony's registry base,
 *   the fallback for a fresh read that comes back empty
 * @param [options.requiredAnnexCommit] {object}   handed through to the
 *   establishment: the annex rung commit required and placed before the
 *   document entry, into the generation the caller's pre-flight resolved
 * @returns {Promise<{ record: UnlockMethodsRecord, recorded: boolean }>}
 */
export async function establishEntryFirstStandingCredential({
  session,
  context,
  secret,
  kdf,
  credential,
  ladderSeed,
  entry,
  base,
  requiredAnnexCommit
}: {
  session: Session
  context: AccountCeremonyContext | null
  secret: Uint8Array
  kdf: UnlockKdf
  credential: UnlockCredential
  ladderSeed: Uint8Array
  entry: StandingEstablishedMethod
  base: UnlockMethodsRecord
  requiredAnnexCommit?: { clientAnnexDid: string | null }
}): Promise<{ record: UnlockMethodsRecord; recorded: boolean }> {
  // 1. The bare entry-first write.
  await updateUnlockMethods({
    session,
    mutate: fresh => upsertUnlockMethod({ record: fresh ?? base, entry })
  })
  // 2. The establishment.
  let established: Awaited<ReturnType<typeof establishStandingUnlock>>
  try {
    established = await establishStandingUnlock({
      session,
      context,
      secret,
      kdf,
      lowEntropy:
        keyAgreementPublicationOf({ type: entry.type }) === 'commitment',
      email: session.user.email,
      credential,
      ladderSeed,
      ...(requiredAnnexCommit ? { requiredAnnexCommit } : {})
    })
  } catch (err) {
    log.error('Could not establish the standing credential', {
      err,
      type: entry.type
    })
    const recovered = await recoverFailedStandingEstablishment({
      session,
      context,
      secret,
      kdf,
      credential,
      ladderSeed,
      entry,
      base
    })
    if (recovered) {
      return recovered
    }
    throw err
  }
  // 3. The completion write.
  return await completeStandingEntry({
    session,
    base,
    entry: completedEntry({
      entry,
      manageCapability: established.manageCapability,
      standingFields: established.standingFields
    })
  })
}

/**
 * The bare entry completed with what the establishment (or a re-fetch of
 * its record) handed back: the standing fields and, where one came back,
 * the management zcap.
 *
 * @param options {object}
 * @param options.entry {StandingEstablishedMethod}   the bare entry
 * @param [options.manageCapability] {object}
 * @param options.standingFields {StandingUnlockFields}
 * @returns {StandingEstablishedMethod}
 */
function completedEntry<T extends StandingEstablishedMethod>({
  entry,
  manageCapability,
  standingFields
}: {
  entry: T
  manageCapability?: T['manageCapability']
  standingFields: StandingUnlockFields
}): T {
  return {
    ...entry,
    ...(manageCapability ? { manageCapability } : {}),
    ...standingFields
  }
}

/**
 * The completion write: merges the completed entry into a FRESH registry read
 * (anything written since the ceremony's own read -- another tab, another
 * client, a login-time refresh -- must survive), then clears the
 * passkey-only safety notice once the account positively has a second method
 * a login accepts. A backup credential is not one (`isLoginEntry`): an
 * export leaves a passkey-only account still one lost authenticator from
 * locked out, so the notice stands. A fresh read that comes back empty falls
 * back to the ceremony's base, so the handle the ceremony's base carries is
 * the one persisted; a fresh read carrying a different handle wins anyway
 * (the stored record is the source of truth).
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.base {UnlockMethodsRecord}   the ceremony's registry base
 * @param options.entry {StandingEstablishedMethod}   the completed entry
 * @returns {Promise<{ record: UnlockMethodsRecord, recorded: boolean }>}
 */
export async function completeStandingEntry({
  session,
  base,
  entry
}: {
  session: Session
  base: UnlockMethodsRecord
  entry: StandingEstablishedMethod
}): Promise<{ record: UnlockMethodsRecord; recorded: boolean }> {
  let record: UnlockMethodsRecord = upsertUnlockMethod({ record: base, entry })
  try {
    record =
      (await updateUnlockMethods({
        session,
        mutate: fresh => upsertUnlockMethod({ record: fresh ?? base, entry })
      })) ?? record
  } catch (err) {
    // The credential is standing and will log in; only the entry's
    // completion failed to persist. The registry still holds the bare shape
    // from the entry-first write, which the credential's next login rebuilds.
    log.error('Could not record the new standing credential in the registry', {
      err,
      type: entry.type
    })
    return { record, recorded: false }
  }
  // The account now has a second method a login accepts, so the dashboard's
  // passkey-only safety prompt is resolved. Only a completion that added a
  // login entry can have changed that count. Non-fatal.
  if (isLoginEntry(entry) && record.methods.filter(isLoginEntry).length > 1) {
    try {
      await session.persistence.passkeyNotices.delete({
        controller: session.user.id
      })
    } catch (err) {
      log.warn('Could not clear the passkey-safety notice', { err })
    }
  }
  return { record, recorded: true }
}

/**
 * The verify-then-act cleanup behind a failed standing-credential
 * establishment.
 *
 * Verify first: the record at the credential's unlock Space is re-fetched,
 * because the failure can be a lost response to the establishment's final
 * record PUT with the credential fully standing server-side -- deleting on
 * the error alone would destroy a succeeded credential. A standing record
 * is treated as SUCCESS: the entry is completed from the hit and the
 * ceremony returns normally (the non-null return).
 *
 * Otherwise, act by what was published. When nothing was (no document
 * `keyAgreement` entry, no roster wrap, and the record absent or plain),
 * the unlock Space and its local state are deleted and the bare registry
 * entry dropped: the credential then never exists -- the simplest mendable
 * state. When something WAS published (or that could not be told), the
 * cleanup is an ACTUAL retirement (`rotateOffUnlockCredential` with the
 * ceremony-minted ladder seed -- the tapped-removal pattern minus the tap,
 * since the credential's secret is in hand), never a record delete: the
 * record is the retirement's anchor. Only after the retirement do the
 * unlock Space and the bare entry go. A retirement, re-fetch, or delete
 * that itself fails leaves the bare entry and the record standing as
 * mendable residue, and the surrounding ceremony still fails.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext | null}   the ceremony
 *   context the failed establishment ran on
 * @param options.secret {Uint8Array}   the credential's secret (a passkey's
 *   PRF output, a backup credential's random bytes)
 * @param options.kdf {UnlockKdf}   the KDF the secret derives under
 * @param options.credential {UnlockCredential}   its derived credential
 * @param options.ladderSeed {Uint8Array}   the ceremony-minted ladder seed
 * @param options.entry {StandingEstablishedMethod}   the bare entry as
 *   written
 * @param options.base {UnlockMethodsRecord}   the ceremony's registry base
 * @returns {Promise<{ record: UnlockMethodsRecord, recorded: boolean } | null>}
 *   the ceremony outcome when the re-fetch proved the establishment
 *   succeeded, else null (the caller fails the ceremony)
 */
export async function recoverFailedStandingEstablishment({
  session,
  context,
  secret,
  kdf,
  credential,
  ladderSeed,
  entry,
  base
}: {
  session: Session
  context: AccountCeremonyContext | null
  secret: Uint8Array
  kdf: UnlockKdf
  credential: UnlockCredential
  ladderSeed: Uint8Array
  entry: StandingEstablishedMethod
  base: UnlockMethodsRecord
}): Promise<{ record: UnlockMethodsRecord; recorded: boolean } | null> {
  // The two reads are independent, so they go out together: the record at
  // the unlock Space, and one fresh read of the account document that
  // decides both arms below (whether the establishment's document entry
  // landed, and failing that whether it published anything at all). The
  // published read never rejects.
  const publishedRead = standingEstablishmentPublished({
    session,
    context,
    credential,
    type: entry.type
  })
  let found: KeyringFetchResult | null
  try {
    found = await fetchKeyring({
      secret,
      kdf,
      credential,
      mintManageCapability: true,
      accountLogPinStore: session.persistence.logPins
    })
  } catch (err) {
    // Cannot verify, so nothing is acted on: the bare entry and whatever the
    // establishment left stand as mendable residue.
    log.warn(
      'Could not re-fetch the standing credential unlock record after the failed establishment; leaving the residue for the standing menders',
      { err, type: entry.type }
    )
    await publishedRead
    return null
  }
  const published = await publishedRead
  if (found?.standing?.ladderSeed && published.listed) {
    // The lost-response case: the record is standing AND the document lists
    // the credential (the record is written before the entry, so a standing
    // record alone proves only the earlier stage), so the establishment
    // succeeded server-side after all. Complete the entry from the hit.
    log.warn(
      'The standing credential unlock record is standing after all; completing the registry entry',
      { type: entry.type }
    )
    return await completeStandingEntry({
      session,
      base,
      entry: completedEntry({
        entry,
        manageCapability: found.manageCapability,
        standingFields: await standingFieldsOfKeyringHit({ found })
      })
    })
  }
  try {
    if (published.anything) {
      // The retirement: document inventory out (where the entry landed), the
      // user key rotated off the roster wrap (where one landed), every
      // encrypted collection re-epoch'd. Its stages no-op over anything the
      // establishment never reached.
      const rung0 = await ladderRung({ ladderSeed, index: 0 })
      const rotation = await rotateOffUnlockCredential({
        session,
        context,
        method: {
          type: entry.type,
          keyAgreementKeyMultibase:
            credential.standing.keyAgreementKeyMultibase,
          updateKeyMultibase: rung0.keyMultibase,
          ladderSeed,
          unlockSpaceId: credential.unlock.spaceId
        },
        verb: `cleaning up a failed ${entry.type} addition`
      })
      if (rotation) {
        reportCeremonyTail({ mended: rotation.mended })
      }
      if (rotation?.rotated && rotation.userKey) {
        await adoptRotatedUserKey({
          session,
          spaceId: rotationSpaceId({ session }),
          userKey: rotation.userKey
        })
      }
    }
  } catch (err) {
    if (isUnclaimedLadderVmRefusal(err)) {
      // The gate, named rather than reported as a transport tear: the
      // retirement published nothing, and the credential keeps a ladder VM
      // that no seedless retry can claim. The residue is the same either
      // way -- the bare entry and the record stand -- but only this arm says
      // that a retry cannot mend it on its own.
      log.error(
        'Could not retire the partially established standing credential: its ladder VM could not be claimed, so the retirement refused before publishing anything',
        {
          err,
          type: entry.type,
          unclaimedLadderVmIds: (err as { unclaimedLadderVmIds?: string[] })
            .unclaimedLadderVmIds,
          retryableWithLadderSeed: (
            err as { retryableWithLadderSeed?: boolean }
          ).retryableWithLadderSeed
        }
      )
      return null
    }
    // The retirement tore: the bare entry and the record stay standing --
    // the state the standing menders already own.
    log.error(
      'Could not retire the partially established standing credential; its bare entry and record are left for the standing menders',
      { err, type: entry.type }
    )
    return null
  }
  // Nothing published (or the retirement swept it): the unlock Space, the
  // local state, and the bare entry go, so the credential never exists.
  try {
    await deleteUnlockMethod({ secret, kdf, credential })
  } catch (err) {
    log.warn('Could not delete the failed standing credential unlock Space', {
      err,
      type: entry.type
    })
    return null
  }
  // Best-effort: a leftover bare entry names a Space that no longer exists
  // and is removable from Settings.
  try {
    await dropRegistryEntry({ session, entry })
  } catch (err) {
    log.warn('Could not drop the bare registry entry after the cleanup', {
      err,
      type: entry.type
    })
  }
  return null
}

/**
 * What a torn standing-credential establishment left published server-side,
 * from ONE fresh read of the account document: `listed`, whether the
 * document carries the credential's `keyAgreement` entry (the establishment's
 * document entry landed), and `anything`, whether that entry or a wrap of the
 * credential in any user-key roster epoch stands. The roster is read only
 * when the document lists nothing. A read that fails resolves to
 * `{ listed: false, anything: true }` -- the conservative direction, since
 * the retirement it routes to no-ops over anything never published. A
 * session with no enrolled-client context resolves to neither: the
 * establishment refused before its first write there.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext | null}
 * @param options.credential {UnlockCredential}
 * @param options.type {StandingEstablishedMethod['type']}   the credential's
 *   kind, which decides the published form of its key
 * @returns {Promise<{ listed: boolean, anything: boolean }>}
 */
async function standingEstablishmentPublished({
  session,
  context,
  credential,
  type
}: {
  session: Session
  context: AccountCeremonyContext | null
  credential: UnlockCredential
  type: StandingEstablishedMethod['type']
}): Promise<{ listed: boolean; anything: boolean }> {
  if (!context) {
    return { listed: false, anything: false }
  }
  try {
    // A fresh read: the establishment primed the session's verified-log
    // memo with the PRE-entry document, so the memo can never show the
    // entry the torn run itself published.
    invalidateVerifiedLog({ profile: session.profile })
    const { doc } = await verifiedAccountLog({
      session,
      pointer: context.pointer
    })
    const listed = await documentListsCredential({
      doc,
      did: context.pointer.did,
      keyAgreementKeyMultibase: credential.standing.keyAgreementKeyMultibase,
      published: keyAgreementPublicationOf({ type })
    })
    if (listed) {
      return { listed: true, anything: true }
    }
    const roster = await context.rosterStore.read()
    const wrapped = (roster?.descriptor.epochs ?? []).some(epoch =>
      epoch.recipients.some(
        recipient => recipient.header.kid === credential.standing.recipientKid
      )
    )
    return { listed: false, anything: wrapped }
  } catch (err) {
    log.warn(
      'Could not check what a failed standing credential establishment published; cleaning by retirement',
      { err }
    )
    return { listed: false, anything: true }
  }
}
