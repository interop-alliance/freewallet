/**
 * The login-time repair for a passphrase change whose retirement failed at
 * its document edit.
 *
 * Changing a passphrase writes the registry's passphrase entry only after the
 * old credential's retirement has reported. When the retirement failed before
 * its document edit landed, the entry is written naming the NEW unlock Space
 * but the OLD credential's standing configuration -- the one state that still names
 * the credential left standing (its `keyAgreement` commitment in the account
 * document and its wrap in the user key roster). Nothing else can find it:
 * the login-time roster sweep only rotates away recipients the document does
 * not back, and this one is still backed.
 *
 * So the next login with the (new) passphrase finishes the job: an entry
 * naming a credential other than the one logging in is a pending retirement,
 * and it is retired here, after which the entry records the login
 * credential's own standing configuration. When the named credential is already out of the
 * document -- a run whose retirement landed but whose registry write did not
 * -- only the entry is rewritten; the roster and cascade residue of that run
 * is the ordinary login sweep's. Best-effort throughout -- a failure leaves
 * the same detectable state for the login after it.
 *
 * A pending-shaped entry whose login credential is itself NOT in the
 * account document gets the establish-first arm: the login credential's
 * standing configuration is established here (from the typed secret the
 * login threads in, with the ladder seed read back from the record the torn
 * change sealed), and only then does the retirement above run.
 * Establish-first is load-bearing -- retiring the old credential while the
 * new one is still plain would leave the account with no standing
 * passphrase. The state the arm mends is a passphrase change torn between
 * the new credential's standing record and its document entry: the record
 * and roster wrap stand, nothing in the document names them, and the entry
 * still names the old credential at the old unlock Space. An OLD passphrase
 * (its unlock Space delete lost) logging in after a change that completed
 * elsewhere leaves the registry and the document in exactly that shape too,
 * and so does an abandoned torn passphrase after a later change succeeded,
 * so the arm is gated on the change's establishment marker
 * (`pendingEstablishment`): the change stamps the entry with the NEW
 * credential's unlock Space and key-agreement multibase before its
 * establishment starts, and its final write drops the stamp. The arm fires
 * only when that marker names the credential logging in at its own unlock
 * Space; a completed change never leaves a marker behind, so the forbidden
 * direction -- an old passphrase establishing itself back into an account
 * it was rotated off, and retiring the current one -- cannot fire.
 *
 * The same entry point mends the other damaged shape of that entry: a BARE
 * entry, one whose identity members are absent while the login credential's
 * standing configuration stands in the account document. Nothing names the
 * credential there, so no retirement runs -- the entry is simply rebuilt
 * from the login credential's keyring hit. That is also the whole migration
 * for accounts an earlier shipped defect (FW-282) damaged this way; there is
 * no separate migration code. A bare entry carrying the establishment
 * marker for the credential logging in is the same torn change on an
 * account whose registry named no passphrase members: the login credential
 * is established first, then the entry is rebuilt from that establishment.
 * An entry naming ANOTHER credential while carrying no ladder rung is left
 * alone: it is not this login credential's to rebuild, and the retirement
 * has no rung to attribute the named credential's ladder by.
 *
 * A passkey login mends the same bare shape through
 * {@link rebuildBarePasskeyEntry}, which rebuilds its own entry alone.
 */
import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import { unlockKeyVmId } from '@interop/wallet-core/unlock'
import { KEYRING_KDF } from '@interop/wallet-core/keyring'
import type { Session } from '@/types/auth'
import { documentListsVmId } from '@/session/keyring'
import type { KeyringFetchResult, UnlockCredential } from '@/session/keyring'
import {
  accountCeremonyContext,
  type AccountCeremonyContext
} from '@/session/accountCeremonyContext'
import {
  isUnclaimedLadderVmRefusal,
  rotateOffUnlockCredential
} from '@/session/credentialRotation'
import { reportCeremonyTail } from '@/session/menders/ceremonyTail'
import { adoptRotatedUserKey } from '@/session/userKeyAdoption'
import {
  establishStandingUnlock,
  standingFieldsOfKeyringHit
} from '@/session/standingUnlock'
import { verifiedAccountLog } from '@/session/verifiedLog'
import {
  adoptPassphraseRebind,
  getUnlockMethods,
  updateUnlockMethods,
  upsertPassphraseUnlockMethod,
  upsertPasskeyUnlockMethod,
  type PasskeyUnlockMethod,
  type PassphraseUnlockMethod,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'
import { createLogger } from '@/lib/log'

const log = createLogger('fw:session:retirement')

/**
 * Finishes a pending passphrase retirement, if this login's registry shows
 * one, and rebuilds a bare passphrase entry when the login credential is
 * document-standing. A no-op on every healthy account (one registry read),
 * and on every login that is not a passphrase login or cannot act as an
 * enrolled client.
 *
 * @param options {object}
 * @param options.session {Session}   the live session of the passphrase
 *   logging in
 * @param options.found {KeyringFetchResult}   that credential's keyring hit
 * @param [options.credential] {object}   the login credential the typed
 *   passphrase derives -- the secret and, when the login already ran the
 *   KDF, the derived bundle. Only the establish-first arm consumes it;
 *   absent, that arm skips and every other shape mends as before
 * @param [options.readRegistry] {Function}   the registry read. A login
 *   block hands its shared read here, so the passes beside this one ride the
 *   same fetch; omitted, the registry is read directly
 * @returns {Promise<'noop' | 'repaired'>}   `repaired` when the pass wrote
 *   the registry (a rebuild, a retirement, or both); `noop` when it read and
 *   left everything as it stands
 */
export async function repairTornPassphraseRetirement({
  session,
  found,
  credential,
  readRegistry
}: {
  session: Session
  found: KeyringFetchResult
  credential?: { secret?: string | Uint8Array; derived?: UnlockCredential }
  readRegistry?: () => Promise<UnlockMethodsRecord | null>
}): Promise<'noop' | 'repaired'> {
  if (session.profile.unlockMethod?.type !== 'passphrase') {
    return 'noop'
  }
  const context = await accountCeremonyContext({ session })
  const standingClient = found.standingClient
  if (!context || !standingClient) {
    return 'noop'
  }
  const registry = await (readRegistry
    ? readRegistry()
    : getUnlockMethods({ session }))
  if (!registry) {
    // No registry at all is the backfill's business, not a repair's: it
    // creates the record, and the login after that finds an entry here.
    return 'noop'
  }
  const entry = registry.methods.find(
    (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
  )
  const mine = standingClient.keyAgreementKeyMultibase
  if (
    !entry?.keyAgreementKeyMultibase ||
    (entry.keyAgreementKeyMultibase === mine && !entry.updateKeyMultibase)
  ) {
    // A bare entry -- and an absent ENTRY, which the upsert below creates
    // (an absent REGISTRY returned above), so the two states mend the same
    // way. An entry naming this login's own credential but carrying no rung
    // is the same damage in a narrower form, and is rebuilt here too.
    // Nothing names another credential in either case, so nothing is
    // retired.
    return await rebuildBareEntry({
      session,
      found,
      context,
      registry,
      entry,
      mine,
      ...(credential ? { credential } : {})
    })
  }
  if (entry.keyAgreementKeyMultibase === mine) {
    return 'noop'
  }
  if (!entry.updateKeyMultibase) {
    // An entry naming ANOTHER credential with no recorded rung. The
    // retirement attributes the credential's ladder by that rung, so this
    // repair cannot run it -- and rebuilding the entry from the login
    // credential would silently un-name a credential that may still stand.
    log.warn(
      "The registry's passphrase entry names another credential but records no update key; the repair cannot attribute it, so the entry is left as it stands"
    )
    return 'noop'
  }
  // The direction guard. An entry naming another credential is a pending
  // retirement only when the credential logging in is itself standing in the
  // account document. The other reading of the same registry state is an OLD
  // passphrase whose unlock Space delete failed, logging in after a change
  // that completed elsewhere: retiring the entry's credential there would
  // strip the account's CURRENT passphrase.
  let { doc } = await verifiedAccountLog({
    profile: session.profile,
    pointer: context.pointer
  })
  let established:
    Awaited<ReturnType<typeof establishStandingUnlock>> | undefined
  if (
    !(await documentListsCredential({
      doc,
      did: context.pointer.did,
      keyAgreementKeyMultibase: mine
    }))
  ) {
    // The establish-first arm: a passphrase change torn between the new
    // credential's standing record and its document entry, so the entry
    // still names the old credential while the login credential is not in
    // the document. The marker gate is what keeps the forbidden direction
    // impossible: an OLD passphrase logging in after a completed change, or
    // an abandoned torn passphrase after a later successful change, finds
    // the same registry and document state but no marker naming it, so it
    // can never establish itself back into an account it was rotated off.
    if (!establishmentMarkerNamesLogin({ entry, found, mine }) || !credential) {
      return 'noop'
    }
    // The marker-armed state holds the old credential standing by
    // construction (the change tears before its retirement). A marker over
    // an entry whose own credential has since left the document (a torn
    // registry write of a later ceremony that retired it) is stale, and
    // establishing the marked credential would reinstate an abandoned
    // passphrase over the account's current one.
    if (
      !(await documentListsCredential({
        doc,
        did: context.pointer.did,
        keyAgreementKeyMultibase: entry.keyAgreementKeyMultibase
      }))
    ) {
      log.warn(
        "The registry's establishment marker names the credential logging in, but the entry's own credential is no longer in the document; the marker is stale and the arm does not fire"
      )
      return 'noop'
    }
    // Establish-first is load-bearing: retiring the old credential while
    // the login credential is still plain would leave the account with no
    // standing passphrase.
    established = await establishLoginCredential({
      session,
      context,
      credential
    })
    if (!established) {
      return 'noop'
    }
    // The establishment extended the account log (and dropped the verified
    // memo), so the still-standing check below reads the post-edit document.
    ;({ doc } = await verifiedAccountLog({
      profile: session.profile,
      pointer: context.pointer
    }))
  }
  // Whether the named credential's document inventory is still standing. Gone
  // means the retirement's document edit landed after all and only the
  // registry write was lost: the roster and cascade residue of such a run is
  // the ordinary login sweep's business, and re-running the retirement here
  // would only swap the annex generation on every login (the repair holds
  // no retired ladder seed, so its annex stage cannot strike).
  const stillStanding = await documentListsCredential({
    doc,
    did: context.pointer.did,
    keyAgreementKeyMultibase: entry.keyAgreementKeyMultibase
  })
  log.warn('Finishing a passphrase change that was torn at its retirement', {
    stillStanding
  })
  if (stillStanding) {
    // The entry's own ladder seed is unknown here (only its holder derives
    // it), so the annex stage signs with this login credential's seed,
    // already on the profile as the surviving one.
    let outcome
    try {
      outcome = await rotateOffUnlockCredential({
        session,
        context,
        method: entry,
        verb: 'finishing a passphrase change'
      })
    } catch (err) {
      if (!isUnclaimedLadderVmRefusal(err)) {
        throw err
      }
      // The retirement gate. This repair holds no retired ladder seed, so it
      // can never claim the named credential's ladder VM, and the retirement
      // refused before publishing anything. Logged and skipped: the entry
      // stays pending for a run that holds the seed, and this login -- which
      // is unattended, on the registry chain -- carries on. Rewriting the
      // entry here would un-name a credential that is still standing.
      log.warn(
        "A pending passphrase retirement was refused: the named credential's ladder VM could not be claimed, so the entry stays pending",
        {
          err,
          unclaimedLadderVmIds: (err as { unclaimedLadderVmIds?: string[] })
            .unclaimedLadderVmIds,
          retryableWithLadderSeed: (
            err as { retryableWithLadderSeed?: boolean }
          ).retryableWithLadderSeed
        }
      )
      return 'noop'
    }
    // The retirement's ceremony-tail entry, reported from the ceremony's own
    // call site: it carries no registration, so no login chain's runner ever
    // sees it.
    if (outcome) {
      reportCeremonyTail({ mended: outcome.mended })
    }
    if (outcome?.rotated && outcome.userKey) {
      // Already adopted in band by the retirement's roster tail, so this
      // returns on its id guard; it retries the registry re-seal only when
      // that in-band step failed and left the session on the pre-rotation
      // keys.
      await adoptRotatedUserKey({
        session,
        spaceId:
          session.profile.accountPointer?.spaceId ?? session.storage.spaceId!,
        userKey: outcome.userKey
      })
    }
  }
  // The entry now records the login credential's own standing configuration
  // -- straight off the establishment when the arm above ran (the keyring
  // hit predates its re-bind), else rebuilt from the hit. The write's base
  // is the wrapper's own fresh read, because the retirement re-sealed the
  // registry to the rotated user key (in band, or on the retry above).
  const standing = established
    ? established.standingFields
    : await standingFieldsOfKeyringHit({ found })
  await updateUnlockMethods({
    session,
    mutate: current => {
      if (!current) {
        return null
      }
      return upsertPassphraseUnlockMethod({
        record: current,
        unlockSpaceId: established?.unlockSpaceId ?? found.unlockSpaceId,
        // The entry's unlock Space is unchanged, so this is not a repoint: a
        // login whose management-zcap mint returned nothing must not clear
        // the one the entry already carries.
        manageCapability:
          established?.manageCapability ??
          found.manageCapability ??
          entry.manageCapability,
        standing
      })
    }
  })
  return 'repaired'
}

/**
 * Whether a passphrase entry's establishment marker names the credential
 * logging in, at its own unlock Space: the one state in which a login
 * credential absent from the account document is a torn passphrase change's
 * new credential rather than a retired one.
 *
 * @param options {object}
 * @param [options.entry] {PassphraseUnlockMethod}
 * @param options.found {KeyringFetchResult}   the login credential's hit
 * @param options.mine {string}   the login credential's key-agreement
 *   multibase
 * @returns {boolean}
 */
function establishmentMarkerNamesLogin({
  entry,
  found,
  mine
}: {
  entry?: PassphraseUnlockMethod
  found: KeyringFetchResult
  mine: string
}): boolean {
  const marker = entry?.pendingEstablishment
  return (
    marker !== undefined &&
    marker.keyAgreementKeyMultibase === mine &&
    marker.unlockSpaceId === found.unlockSpaceId
  )
}

/**
 * Finishes the login credential's standing establishment from the record
 * the torn change sealed (`establishStandingUnlock` reads the ladder seed
 * back from it, so the document entry names the rung the record holds),
 * then swaps the live profile onto the re-bound record, as the change
 * ceremony does on its own establishment. Best-effort: a failure is logged
 * and yields nothing, leaving the same state for the next passphrase login.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.context {AccountCeremonyContext}
 * @param options.credential {object}   the typed login secret and, when the
 *   login already ran the KDF, its derived bundle
 * @returns {Promise<object | undefined>}   the establishment's outcome, or
 *   `undefined` when it failed
 */
async function establishLoginCredential({
  session,
  context,
  credential
}: {
  session: Session
  context: AccountCeremonyContext
  credential: { secret?: string | Uint8Array; derived?: UnlockCredential }
}): Promise<Awaited<ReturnType<typeof establishStandingUnlock>> | undefined> {
  log.warn(
    'Finishing a passphrase change torn before its document entry: establishing the login credential from its sealed record'
  )
  let established: Awaited<ReturnType<typeof establishStandingUnlock>>
  try {
    established = await establishStandingUnlock({
      session,
      context,
      secret: credential.secret ?? '',
      kdf: KEYRING_KDF,
      lowEntropy: true,
      email: session.user.email,
      ...(credential.derived ? { credential: credential.derived } : {})
    })
  } catch (err) {
    log.warn(
      'Could not establish the login credential as standing; the torn change is left for the next passphrase login',
      { err }
    )
    return undefined
  }
  // The standing re-bind superseded this login's record: swap the live
  // profile's persist closure, unlock method, and annex-writing seed onto
  // it.
  adoptPassphraseRebind({
    session,
    unlockSpaceId: established.unlockSpaceId,
    manageCapability: established.manageCapability,
    ...(established.persistClientKeys
      ? { persistClientKeys: established.persistClientKeys }
      : {})
  })
  session.profile.ladderSeed = established.ladderSeed
  return established
}

/**
 * Rebuilds a bare (or absent) passphrase entry from the login credential's
 * keyring hit, once the account document shows that credential standing. A
 * credential the document does not list has nothing to record -- a bare
 * entry on a never-established credential is honest -- so that case writes
 * nothing, with one exception: a bare entry whose establishment marker
 * names the credential logging in is a passphrase change torn before its
 * document entry on an account whose registry named no passphrase members,
 * and the credential is established first (from its sealed record), then
 * recorded. The caller's registry read decided the rebuild; the write
 * itself runs over the compare-and-swap wrapper's own fresh read, with that
 * read as the fallback base on a true absent.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.found {KeyringFetchResult}   the login credential's hit
 * @param options.context {AccountCeremonyContext}
 * @param options.registry {UnlockMethodsRecord}   the registry as read
 * @param [options.entry] {PassphraseUnlockMethod}   the bare entry, if any
 * @param options.mine {string}   the login credential's key-agreement
 *   multibase
 * @param [options.credential] {object}   the typed login secret, which the
 *   marker-gated establishment consumes
 * @returns {Promise<'noop' | 'repaired'>}
 */
async function rebuildBareEntry({
  session,
  found,
  context,
  registry,
  entry,
  mine,
  credential
}: {
  session: Session
  found: KeyringFetchResult
  context: AccountCeremonyContext
  registry: UnlockMethodsRecord
  entry?: PassphraseUnlockMethod
  mine: string
  credential?: { secret?: string | Uint8Array; derived?: UnlockCredential }
}): Promise<'noop' | 'repaired'> {
  const { doc } = await verifiedAccountLog({
    profile: session.profile,
    pointer: context.pointer
  })
  let established:
    Awaited<ReturnType<typeof establishStandingUnlock>> | undefined
  if (
    !(await documentListsCredential({
      doc,
      did: context.pointer.did,
      keyAgreementKeyMultibase: mine
    }))
  ) {
    if (!establishmentMarkerNamesLogin({ entry, found, mine }) || !credential) {
      return 'noop'
    }
    established = await establishLoginCredential({
      session,
      context,
      credential
    })
    if (!established) {
      return 'noop'
    }
  }
  log.warn(
    established
      ? 'Recording the passphrase just established over its bare registry entry'
      : "The registry's passphrase entry is bare; rebuilding it from the credential logging in"
  )
  const standing = established
    ? established.standingFields
    : await standingFieldsOfKeyringHit({ found })
  await updateUnlockMethods({
    session,
    mutate: current =>
      upsertPassphraseUnlockMethod({
        record: current ?? registry,
        unlockSpaceId: established?.unlockSpaceId ?? found.unlockSpaceId,
        manageCapability:
          established?.manageCapability ??
          found.manageCapability ??
          entry?.manageCapability,
        standing
      })
  })
  return 'repaired'
}

/**
 * Rebuilds a BARE passkey registry entry -- one carrying no identity members
 * -- from the passkey logging in, once the account document publishes that
 * credential's `keyAgreement` key. The passkey twin of the bare-entry rebuild
 * above, and what keeps a passkey account's registry naming every standing
 * credential the account document publishes.
 *
 * A passkey's PRF-derived key is high entropy, so the document publishes it
 * VERBATIM rather than as a commitment; that is the form checked here.
 *
 * Only a bare-but-PRESENT entry is rebuilt. Creating an absent one would need
 * members no keyring hit carries -- the WebAuthn `credentialId` the entry is
 * matched on, the label, the transports and backup flags captured at
 * registration -- so an absent entry is left to the add-a-passkey ceremony's
 * own registry write.
 *
 * @param options {object}
 * @param options.session {Session}   the live session of the passkey logging
 *   in
 * @param options.found {KeyringFetchResult}   that credential's keyring hit
 * @param [options.readRegistry] {Function}   the registry read. A login
 *   block hands its shared read here, so the passes beside this one ride the
 *   same fetch; omitted, the registry is read directly
 * @returns {Promise<'noop' | 'repaired'>}   `repaired` when a bare entry was
 *   rebuilt, `noop` when there was nothing bare to rebuild
 */
export async function rebuildBarePasskeyEntry({
  session,
  found,
  readRegistry
}: {
  session: Session
  found: KeyringFetchResult
  readRegistry?: () => Promise<UnlockMethodsRecord | null>
}): Promise<'noop' | 'repaired'> {
  if (session.profile.unlockMethod?.type !== 'passkey') {
    return 'noop'
  }
  const context = await accountCeremonyContext({ session })
  const standingClient = found.standingClient
  if (!context || !standingClient) {
    return 'noop'
  }
  const registry = await (readRegistry
    ? readRegistry()
    : getUnlockMethods({ session }))
  if (!registry) {
    return 'noop'
  }
  const entry = registry.methods.find(
    (method): method is PasskeyUnlockMethod =>
      method.type === 'passkey' && method.unlockSpaceId === found.unlockSpaceId
  )
  if (!entry || entry.keyAgreementKeyMultibase) {
    return 'noop'
  }
  const { doc } = await verifiedAccountLog({
    profile: session.profile,
    pointer: context.pointer
  })
  if (
    !(await documentListsCredential({
      doc,
      did: context.pointer.did,
      keyAgreementKeyMultibase: standingClient.keyAgreementKeyMultibase,
      published: 'verbatim'
    }))
  ) {
    return 'noop'
  }
  log.warn(
    "The registry's entry for the passkey logging in is bare; rebuilding it from that credential"
  )
  const rebuilt = {
    ...entry,
    ...(await standingFieldsOfKeyringHit({ found }))
  }
  await updateUnlockMethods({
    session,
    mutate: current =>
      upsertPasskeyUnlockMethod({
        record: current ?? registry,
        entry: rebuilt
      })
  })
  return 'repaired'
}

/**
 * Whether the account document still carries one credential's `keyAgreement`
 * entry, by the verification-method id its published form implies: the
 * commitment id a passphrase publishes under (the default), or the verbatim
 * id a high-entropy credential -- a passkey PRF output -- publishes under.
 *
 * @param options {object}
 * @param options.doc {object}   the verified account document
 * @param options.did {string}   the account's did:webvh
 * @param options.keyAgreementKeyMultibase {string}
 * @param [options.published] {'commitment' | 'verbatim'}   how the
 *   credential publishes its key; default `'commitment'`
 * @returns {Promise<boolean>}
 */
export async function documentListsCredential({
  doc,
  did,
  keyAgreementKeyMultibase,
  published = 'commitment'
}: {
  doc: object
  did: string
  keyAgreementKeyMultibase: string
  published?: 'commitment' | 'verbatim'
}): Promise<boolean> {
  const vmId = unlockKeyVmId({
    did,
    keyAgreement:
      published === 'verbatim'
        ? { publicKeyMultibase: keyAgreementKeyMultibase }
        : {
            commitment: await keyAgreementCommitment({
              keyAgreementKeyMultibase
            })
          }
  })
  return documentListsVmId({ doc, vmId })
}
