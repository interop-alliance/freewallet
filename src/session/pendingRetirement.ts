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
 * The same entry point mends the other damaged shape of that entry: a BARE
 * entry, one whose identity members are absent while the login credential's
 * standing configuration stands in the account document. Nothing names the
 * credential there, so no retirement runs -- the entry is simply rebuilt
 * from the login credential's keyring hit. That is also the whole migration
 * for accounts an earlier shipped defect (FW-282) damaged this way; there is
 * no separate migration code. An entry naming ANOTHER credential while
 * carrying no ladder rung is left alone: it is not this login credential's
 * to rebuild, and the retirement has no rung to attribute the named
 * credential's ladder by.
 *
 * A passkey login mends the same bare shape through
 * {@link rebuildBarePasskeyEntry}, which rebuilds its own entry alone.
 */
import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import { unlockKeyVmId } from '@interop/wallet-core/unlock'
import type { Session } from '@/types/auth'
import type { KeyringFetchResult } from '@/session/keyring'
import {
  enrolledClientContext,
  type EnrolledClientContext
} from '@/session/enrolledContext'
import { rotateOffUnlockCredential } from '@/session/credentialRotation'
import { adoptRotatedUserKey } from '@/session/userKeyAdoption'
import { standingFieldsOfKeyringHit } from '@/session/standingUnlock'
import { verifiedAccountLog } from '@/session/verifiedLog'
import {
  getUnlockMethods,
  putUnlockMethods,
  upsertPassphraseUnlockMethod,
  upsertPasskeyUnlockMethod,
  type PasskeyUnlockMethod,
  type PassphraseUnlockMethod,
  type UnlockMethodsRecord
} from '@/session/unlockMethods'

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
 * @returns {Promise<void>}
 */
export async function repairTornPassphraseRetirement({
  session,
  found
}: {
  session: Session
  found: KeyringFetchResult
}): Promise<void> {
  if (session.profile.unlockMethod?.type !== 'passphrase') {
    return
  }
  const context = enrolledClientContext({ session })
  const standingClient = found.standingClient
  if (!context || !standingClient) {
    return
  }
  const registry = await getUnlockMethods({ session })
  if (!registry) {
    // No registry at all is the backfill's business, not a repair's: it
    // creates the record, and the login after that finds an entry here.
    return
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
    await rebuildBareEntry({ session, found, context, registry, entry, mine })
    return
  }
  if (entry.keyAgreementKeyMultibase === mine) {
    return
  }
  if (!entry.updateKeyMultibase) {
    // An entry naming ANOTHER credential with no recorded rung. The
    // retirement attributes the credential's ladder by that rung, so this
    // repair cannot run it -- and rebuilding the entry from the login
    // credential would silently un-name a credential that may still stand.
    console.warn(
      "The registry's passphrase entry names another credential but " +
        'records no update key; the repair cannot attribute it, so the ' +
        'entry is left as it stands.'
    )
    return
  }
  // The direction guard. An entry naming another credential is a pending
  // retirement only when the credential logging in is itself standing in the
  // account document. The other reading of the same registry state is an OLD
  // passphrase whose unlock Space delete failed, logging in after a change
  // that completed elsewhere: retiring the entry's credential there would
  // strip the account's CURRENT passphrase.
  const { doc } = await verifiedAccountLog({
    profile: session.profile,
    pointer: context.pointer
  })
  if (
    !(await documentListsCredential({
      doc,
      did: context.pointer.did,
      keyAgreementKeyMultibase: mine
    }))
  ) {
    return
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
  console.warn(
    'Finishing a passphrase change that was torn at its retirement; ' +
      (stillStanding
        ? 'retiring the credential the registry still names.'
        : 'the credential is already out of the document, recording this ' +
          "credential's standing configuration.")
  )
  if (stillStanding) {
    // The entry's own ladder seed is unknown here (only its holder derives
    // it), so the annex stage signs with this login credential's seed,
    // already on the profile as the surviving one.
    const outcome = await rotateOffUnlockCredential({
      session,
      method: entry,
      verb: 'finishing a passphrase change'
    })
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
  // The entry now records the login credential's own standing configuration.
  // The registry is re-read because the retirement re-sealed it to the
  // rotated user key (in band, or on the retry above).
  const current = await getUnlockMethods({ session })
  if (!current) {
    return
  }
  await putUnlockMethods({
    session,
    record: upsertPassphraseUnlockMethod({
      record: current,
      unlockSpaceId: found.unlockSpaceId,
      // The entry's unlock Space is unchanged, so this is not a repoint: a
      // login whose management-zcap mint returned nothing must not clear the
      // one the entry already carries.
      manageCapability: found.manageCapability ?? entry.manageCapability,
      standing: await standingFieldsOfKeyringHit({ found })
    })
  })
}

/**
 * Rebuilds a bare (or absent) passphrase entry from the login credential's
 * keyring hit, once the account document shows that credential standing. A
 * credential the document does not list has nothing to record -- a bare
 * entry on a never-established credential is honest -- so that case writes
 * nothing. The registry read by the caller is the write's base: no rotation
 * ran, so nothing can have re-sealed it in between.
 *
 * @param options {object}
 * @param options.session {Session}
 * @param options.found {KeyringFetchResult}   the login credential's hit
 * @param options.context {EnrolledClientContext}
 * @param options.registry {UnlockMethodsRecord}   the registry as read
 * @param [options.entry] {PassphraseUnlockMethod}   the bare entry, if any
 * @param options.mine {string}   the login credential's key-agreement
 *   multibase
 * @returns {Promise<void>}
 */
async function rebuildBareEntry({
  session,
  found,
  context,
  registry,
  entry,
  mine
}: {
  session: Session
  found: KeyringFetchResult
  context: EnrolledClientContext
  registry: UnlockMethodsRecord
  entry?: PassphraseUnlockMethod
  mine: string
}): Promise<void> {
  const { doc } = await verifiedAccountLog({
    profile: session.profile,
    pointer: context.pointer
  })
  if (
    !(await documentListsCredential({
      doc,
      did: context.pointer.did,
      keyAgreementKeyMultibase: mine
    }))
  ) {
    return
  }
  console.warn(
    "The registry's passphrase entry is bare; rebuilding it from the " +
      'credential logging in.'
  )
  await putUnlockMethods({
    session,
    record: upsertPassphraseUnlockMethod({
      record: registry,
      unlockSpaceId: found.unlockSpaceId,
      manageCapability: found.manageCapability ?? entry?.manageCapability,
      standing: await standingFieldsOfKeyringHit({ found })
    })
  })
}

/**
 * Rebuilds a BARE passkey registry entry -- one carrying no identity members
 * -- from the passkey logging in, once the account document publishes that
 * credential's `keyAgreement` key. The passkey twin of the bare-entry rebuild
 * above, and the reason a passkey account is not left with an entry the
 * last-client transition refuses over
 * (`assertRegistryCoversStandingCredentials`) and no login can mend.
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
 * @returns {Promise<void>}
 */
export async function rebuildBarePasskeyEntry({
  session,
  found
}: {
  session: Session
  found: KeyringFetchResult
}): Promise<void> {
  if (session.profile.unlockMethod?.type !== 'passkey') {
    return
  }
  const context = enrolledClientContext({ session })
  const standingClient = found.standingClient
  if (!context || !standingClient) {
    return
  }
  const registry = await getUnlockMethods({ session })
  if (!registry) {
    return
  }
  const entry = registry.methods.find(
    (method): method is PasskeyUnlockMethod =>
      method.type === 'passkey' && method.unlockSpaceId === found.unlockSpaceId
  )
  if (!entry || entry.keyAgreementKeyMultibase) {
    return
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
    return
  }
  console.warn(
    "The registry's entry for the passkey logging in is bare; rebuilding " +
      'it from that credential.'
  )
  await putUnlockMethods({
    session,
    record: upsertPasskeyUnlockMethod({
      record: registry,
      entry: {
        ...entry,
        ...(await standingFieldsOfKeyringHit({ found }))
      }
    })
  })
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
  return documentListsVm({ doc, vmId })
}

/**
 * Whether the account document lists a verification method by id, over both
 * the `verificationMethod` set (where wallet-core's own inventory edit looks)
 * and the `keyAgreement` relation, whose members may be ids or embedded
 * methods.
 *
 * @param options {object}
 * @param options.doc {object}   the verified account document
 * @param options.vmId {string}
 * @returns {boolean}
 */
function documentListsVm({
  doc,
  vmId
}: {
  doc: object
  vmId: string
}): boolean {
  const { verificationMethod = [], keyAgreement = [] } = doc as {
    verificationMethod?: { id?: string }[]
    keyAgreement?: (string | { id?: string })[]
  }
  return (
    verificationMethod.some(method => method?.id === vmId) ||
    keyAgreement.some(member =>
      typeof member === 'string' ? member === vmId : member?.id === vmId
    )
  )
}
