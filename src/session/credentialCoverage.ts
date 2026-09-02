/**
 * Two read-only detectors over the standing unlock credentials an account
 * document publishes, and the unlock-methods registry that is supposed to
 * name them all:
 *
 * - a PENDING-shaped passphrase entry -- one whose unlock record is sealed to
 *   a credential other than the one the entry's identity members name, the
 *   residue of a passphrase change torn before its retirement landed;
 * - an UNRECORDED standing credential -- a `keyAgreement` entry in the
 *   document carrying no enrolled-client controller marker that no registry
 *   entry records, in either published form.
 *
 * Both name an unlock Space a registry-driven walk cannot reach. Two
 * ceremonies read them and grade them differently: the last-client transition
 * REFUSES on either (a bridge delegation its removal entry would rot with no
 * replacement), while the account-deletion walk REPORTS each as a residue and
 * continues, since the account Space's own deletion is what mends them -- that
 * credential's next login meets a dead account log and is offered the removal.
 *
 * The detectors therefore return findings; each caller decides what a finding
 * means.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { getUnlockKeyringWithCapability } from '@interop/wallet-core/keyring'
import {
  unlockKeyVmId,
  unlockRecordSealedTo
} from '@interop/wallet-core/unlock'
import {
  clientKeyAgreementController,
  keyAgreementCommitment,
  relationIds,
  resolvedKeyAgreementMethods
} from '@interop/wallet-core/webvh'
import { WAS_SERVER_URL } from '@/app.config'
import type {
  PassphraseUnlockMethod,
  UnlockMethod
} from '@/session/unlockMethods'

/**
 * The verification-method ids of the standing credentials' `keyAgreement`
 * entries in a verified account document: every resolved key-agreement
 * method whose `controller` is not an enrolled client's marker (the did:key
 * of a signing key the document lists under `capabilityInvocation`). A
 * method carrying no id of its own is named by the id its published key
 * material implies, the form {@link unlockKeyVmId} builds.
 *
 * @param options {object}
 * @param options.doc {object}   the verified account document
 * @param options.did {string}   the account's did:webvh
 * @returns {string[]}
 */
export function credentialKeyAgreementVmIds({
  doc,
  did
}: {
  doc: object
  did: string
}): string[] {
  const invocation = (
    doc as { capabilityInvocation?: Array<string | { id?: string }> }
  ).capabilityInvocation
  const markers = new Set(
    relationIds(invocation).map(id =>
      clientKeyAgreementController({
        signingKeyMultibase: id.slice(id.lastIndexOf('#') + 1)
      })
    )
  )
  const vmIds: string[] = []
  for (const method of resolvedKeyAgreementMethods({ doc })) {
    if (method.controller && markers.has(method.controller)) {
      continue
    }
    const fragment = method.publicKeyMultibase ?? method.publicKeyCommitment
    const vmId =
      method.id ??
      (fragment
        ? unlockKeyVmId({
            did,
            keyAgreement: method.publicKeyMultibase
              ? { publicKeyMultibase: method.publicKeyMultibase }
              : { commitment: method.publicKeyCommitment! }
          })
        : undefined)
    if (vmId) {
      vmIds.push(vmId)
    }
  }
  return [...new Set(vmIds)]
}

/**
 * The registry's passphrase entries whose unlock record is sealed to a
 * credential OTHER than the one the entry's identity members name.
 *
 * The record IS the detector, deliberately, rather than a session-derived
 * comparison: that comparison needs a direction guard (an entry naming
 * another credential is also what an OLD passphrase sees, logging in after a
 * change that completed elsewhere, on a perfectly healthy account), and the
 * record settles the question outright for a passkey login too.
 *
 * An entry carrying no management zcap or no unlock key-agreement multibase
 * is unsettleable either way and is skipped: it is a bare entry, not a
 * pending one. A record that cannot be read, parsed, or read for its
 * recipients THROWS, since neither caller may run over an entry it could not
 * settle.
 *
 * @param options {object}
 * @param options.registry {{ methods?: unknown[] } | null}
 * @param options.host {string}   the storage host to read the records from
 * @param options.readerFor {Function}   the entry's record reader: the signing
 *   client and the capability its record GET rides (the stored management zcap
 *   on a remembered session, a GET-only child of it on a transient one).
 *   Returning `undefined` skips the entry as unsettleable
 * @returns {Promise<PassphraseUnlockMethod[]>}   the pending-shaped entries
 */
export async function findPendingPassphraseEntries({
  registry,
  host,
  readerFor
}: {
  registry: { methods?: unknown[] } | null
  host: string
  readerFor: (
    entry: PassphraseUnlockMethod
  ) => Promise<{ zcapClient: ZcapClient; capability: IZcap } | undefined>
}): Promise<PassphraseUnlockMethod[]> {
  const entries = (
    (registry?.methods ?? []) as PassphraseUnlockMethod[]
  ).filter(method => method.type === 'passphrase')
  const pending: PassphraseUnlockMethod[] = []
  for (const entry of entries) {
    if (!entry.manageCapability || !entry.unlockKeyAgreementKeyMultibase) {
      continue
    }
    const reader = await readerFor(entry)
    if (!reader) {
      continue
    }
    let sealedToEntry: boolean
    try {
      const record = await getUnlockKeyringWithCapability({
        storageServerUrl: WAS_SERVER_URL ?? host,
        zcapClient: reader.zcapClient,
        spaceId: entry.unlockSpaceId,
        capability: reader.capability
      })
      // Inside the same try: a malformed frame or a degenerate descriptor is
      // a record the caller could not settle, not a pending entry and not a
      // generic failure.
      sealedToEntry = unlockRecordSealedTo({
        record,
        keyAgreementKeyMultibase: entry.unlockKeyAgreementKeyMultibase
      })
    } catch (err) {
      throw new Error(
        'Could not read the sign-in record the unlock-methods registry ' +
          'names; try again.',
        { cause: err }
      )
    }
    if (!sealedToEntry) {
      pending.push(entry)
    }
  }
  return pending
}

/**
 * The standing credentials the account document publishes that no registry
 * entry records: every credential `keyAgreement` verification-method id
 * (see {@link credentialKeyAgreementVmIds}) not covered by a registry entry's
 * recorded key-agreement multibase, compared in BOTH published forms -- the
 * verbatim id a passkey or recovery code publishes under, and the commitment
 * id a passphrase publishes under.
 *
 * A registry that read as absent covers nothing, so every credential entry
 * the document publishes comes back unrecorded.
 *
 * @param options {object}
 * @param options.doc {object}   the verified account document
 * @param options.did {string}   the account's did:webvh
 * @param options.registry {{ methods?: unknown[] } | null}
 * @returns {Promise<string[]>}   the unrecorded verification-method ids
 */
export async function findUnrecordedCredentials({
  doc,
  did,
  registry
}: {
  doc: object
  did: string
  registry: { methods?: unknown[] } | null
}): Promise<string[]> {
  const credentialVmIds = credentialKeyAgreementVmIds({ doc, did })
  if (credentialVmIds.length === 0) {
    return []
  }
  const covered = new Set<string>()
  const multibases = ((registry?.methods ?? []) as UnlockMethod[]).flatMap(
    method =>
      typeof method?.keyAgreementKeyMultibase === 'string'
        ? [method.keyAgreementKeyMultibase]
        : []
  )
  for (const keyAgreementKeyMultibase of multibases) {
    covered.add(
      unlockKeyVmId({
        did,
        keyAgreement: { publicKeyMultibase: keyAgreementKeyMultibase }
      })
    )
    covered.add(
      unlockKeyVmId({
        did,
        keyAgreement: {
          commitment: await keyAgreementCommitment({ keyAgreementKeyMultibase })
        }
      })
    )
  }
  return credentialVmIds.filter(vmId => !covered.has(vmId))
}
