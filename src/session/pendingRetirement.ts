/**
 * The login-time completer for a passphrase change whose retirement failed at
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
 */
import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import { unlockKeyVmId } from '@interop/wallet-core/unlock'
import type { Session } from '@/types/auth'
import type { KeyringFetchResult } from '@/session/keyring'
import { enrolledClientContext } from '@/session/enrolledContext'
import { rotateOffUnlockCredential } from '@/session/credentialRotation'
import { adoptRotatedUserKey } from '@/session/userKeyAdoption'
import { standingFieldsOfKeyringHit } from '@/session/standingUnlock'
import { verifiedAccountLog } from '@/session/verifiedLog'
import {
  getUnlockMethods,
  putUnlockMethods,
  upsertPassphraseUnlockMethod,
  type PassphraseUnlockMethod
} from '@/session/unlockMethods'

/**
 * Finishes a pending passphrase retirement, if this login's registry shows
 * one. A no-op on every healthy account (one registry read), and on every
 * login that is not a passphrase login or cannot act as an enrolled client.
 *
 * @param options {object}
 * @param options.session {Session}   the live session of the passphrase
 *   logging in
 * @param options.found {KeyringFetchResult}   that credential's keyring hit
 * @returns {Promise<void>}
 */
export async function finishPendingPassphraseRetirement({
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
  const entry = registry?.methods.find(
    (method): method is PassphraseUnlockMethod => method.type === 'passphrase'
  )
  if (!entry?.keyAgreementKeyMultibase || !entry.updateKeyMultibase) {
    return
  }
  const mine = standingClient.keyAgreementKeyMultibase
  if (entry.keyAgreementKeyMultibase === mine) {
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
  // would only swap the annex generation on every login (the completer holds
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
      await adoptRotatedUserKey({
        session,
        spaceId:
          session.profile.accountPointer?.spaceId ?? session.storage.spaceId!,
        userKey: outcome.userKey
      })
    }
  }
  // The entry now records the login credential's own standing configuration. The registry is
  // re-read because the adoption above re-sealed it to the rotated user key.
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
 * Whether the account document still carries one credential's `keyAgreement`
 * entry, by the commitment verification-method id a passphrase publishes
 * under.
 *
 * @param options {object}
 * @param options.doc {object}   the verified account document
 * @param options.did {string}   the account's did:webvh
 * @param options.keyAgreementKeyMultibase {string}
 * @returns {Promise<boolean>}
 */
async function documentListsCredential({
  doc,
  did,
  keyAgreementKeyMultibase
}: {
  doc: object
  did: string
  keyAgreementKeyMultibase: string
}): Promise<boolean> {
  const vmId = unlockKeyVmId({
    did,
    keyAgreement: {
      commitment: await keyAgreementCommitment({ keyAgreementKeyMultibase })
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
