/**
 * The invariant auditor's key-holder port, built from a live harness actor:
 * the checks only a party holding the user key or the acting unlock
 * credential can run, over the actor's own session.
 *
 * Each check runs the code the registered mender or detector runs wherever
 * one exists, so the audit and the mender share the predicate by
 * construction: the registry read (`getUnlockMethods`, whose stale-seal
 * refusal is the re-seal repair's detector), the verified account log
 * (`refreshVerifiedAccountLog`), the declarations' own `holdsWhen` detectors
 * on `MENDER_INVARIANTS` (`findPendingPassphraseEntries`,
 * `documentListsCredential`, `checkRecoveryHealth`),
 * `findUnrecordedCredentials`, and the writer sweep
 * (`sweepConnectionWriters`), run over a store whose write is a no-op.
 *
 * The acting credential's unlock record is encrypted to that credential
 * alone, so the two rows about its account pointer need the credential
 * itself: a test that hands in the passphrase or passkey it logged in with
 * gets them checked off the served record (`fetchTransientKeyring`, which
 * writes nothing), and one that does not gets them skipped. The standing
 * delegations are read off the served record too when it is available, and
 * off the session's standing members otherwise.
 *
 * An unlock Space names no account, and a retired credential leaves the
 * registry, so `no-unlock-space-outlives-its-credential` needs the caller to
 * say which unlock Spaces the account's retired credentials had. A test that
 * hands them in (an empty list when it retired none) gets the row checked,
 * and one that does not gets it skipped.
 *
 * Every read runs through `actor.run`, so what it logs is attributed to the
 * actor's tab. The modules under `src/` are imported inside the builder, after
 * the harness has booted.
 */
import type { InvariantId } from '@interop/wallet-core/menders'
import type { StandingCredentialEntry } from '@/session/unlockMethods'
import type { TestPasskey, WalletActor, WalletHarness } from './walletHarness'
import {
  auditInvariants,
  holds,
  undetermined,
  violated,
  type InvariantAudit,
  type InvariantCheck,
  type InvariantCheckOutcome,
  type InvariantKeyHolder
} from '../shared/invariantAudit'

/**
 * The wallet modules the port reads through, loaded after the harness boot.
 *
 * @returns {Promise<object>}
 */
async function loadPortModules() {
  const config = await import('@/app.config')
  const keyringKdf = await import('@interop/wallet-core/keyring')
  const keys = await import('@interop/wallet-core/keys')
  const webvh = await import('@interop/wallet-core/webvh')
  const clientAnnex = await import('@interop/wallet-core/clientAnnex')
  const connections = await import('@interop/wallet-core/connections')
  const resourceLog = await import('@interop/vh-resource-log')
  const unlockMethods = await import('@/session/unlockMethods')
  const verifiedLog = await import('@/session/verifiedLog')
  const credentialCoverage = await import('@/session/credentialCoverage')
  const keyring = await import('@/session/keyring')
  const ceremonyContext = await import('@/session/accountCeremonyContext')
  const menders = await import('@/session/menders')
  const zcap = await import('@/lib/zcap')
  return {
    PASSKEY_KDF: config.PASSKEY_KDF,
    KEYRING_KDF: keyringKdf.KEYRING_KDF,
    rosterWrapsRecipient: keys.rosterWrapsRecipient,
    attributeLadderRung: webvh.attributeLadderRung,
    credentialKeyAgreementMethods: webvh.credentialKeyAgreementMethods,
    MULTIKEY_COMMITMENT_VM_TYPE: webvh.MULTIKEY_COMMITMENT_VM_TYPE,
    standingZcapStale: webvh.standingZcapStale,
    zcapExpiring: webvh.zcapExpiring,
    delegatedClientsDelegationSpaceId:
      clientAnnex.delegatedClientsDelegationSpaceId,
    readConnections: connections.readConnections,
    sweepConnectionWriters: connections.sweepConnectionWriters,
    memoryResourceLogPinStore: resourceLog.memoryResourceLogPinStore,
    getUnlockMethods: unlockMethods.getUnlockMethods,
    isStandingCredentialEntry: unlockMethods.isStandingCredentialEntry,
    standingUnlockFields: unlockMethods.standingUnlockFields,
    unlockEntryReaderFor: unlockMethods.unlockEntryReaderFor,
    UnlockRegistryStaleSealError: unlockMethods.UnlockRegistryStaleSealError,
    refreshVerifiedAccountLog: verifiedLog.refreshVerifiedAccountLog,
    findUnrecordedCredentials: credentialCoverage.findUnrecordedCredentials,
    deriveUnlockCredential: keyring.deriveUnlockCredential,
    fetchTransientKeyring: keyring.fetchTransientKeyring,
    keyAgreementPublicationOf: keyring.keyAgreementPublicationOf,
    accountCeremonyContext: ceremonyContext.accountCeremonyContext,
    menderRegistry: menders.freewalletMenderRegistry,
    zcapExpires: zcap.zcapExpires
  }
}

type PortModules = Awaited<ReturnType<typeof loadPortModules>>

/**
 * The unlock credential a check needs to read the acting credential's own
 * unlock record.
 */
type UnlockCredential = Awaited<
  ReturnType<PortModules['deriveUnlockCredential']>
>

/**
 * The unlock credentials `auditActor` has derived, keyed by the secret's
 * text. The KDF is Argon2id, so a test auditing the same login several
 * times derives once.
 */
const derivedCredentials = new Map<string, Promise<UnlockCredential>>()

/**
 * A promise-returning function run at most once, its result shared.
 *
 * @param work {() => Promise<T>}
 * @returns {() => Promise<T>}
 */
function once<T>(work: () => Promise<T>): () => Promise<T> {
  let pending: Promise<T> | undefined
  return () => (pending ??= work())
}

/**
 * A declaration's own detector (`holdsWhen`) as a check outcome.
 *
 * @param options {object}
 * @param options.modules {PortModules}
 * @param options.id {InvariantId}
 * @param options.deps {unknown}   the detector's parameter object
 * @param [options.evidence] {unknown}   what to report when it says
 *   violated
 * @returns {Promise<InvariantCheckOutcome>}
 */
async function declaredDetector({
  modules,
  id,
  deps,
  evidence
}: {
  modules: PortModules
  id: InvariantId
  deps: unknown
  evidence?: unknown
}): Promise<InvariantCheckOutcome> {
  const declaration = modules.menderRegistry.byId(id)
  const detector = declaration?.holdsWhen as
    | ((deps: unknown) => Promise<'holds' | 'violated' | 'undetermined'>)
    | undefined
  if (detector === undefined) {
    throw new Error(`The declaration for ${id} carries no holdsWhen detector.`)
  }
  const verdict = await detector.call(declaration, deps)
  if (verdict === 'holds') {
    return holds()
  }
  if (verdict === 'violated') {
    return violated(evidence ?? { detector: `${id} holdsWhen` })
  }
  return undetermined(`The declared detector for ${id} could not settle it.`)
}

/**
 * Builds the key-holder port over a live actor.
 *
 * @param options {object}
 * @param options.actor {WalletActor}   a live actor on the audited account
 * @param [options.credential] {UnlockCredential}   the actor's acting
 *   unlock credential, derived; without it the rows about the served unlock
 *   record are skipped
 * @param [options.retiredUnlockSpaceIds] {string[]}   the unlock Space ids
 *   of every credential the account has retired, as the caller knows them,
 *   or an empty list when it retired none; without it
 *   `no-unlock-space-outlives-its-credential` is skipped
 * @returns {Promise<InvariantKeyHolder>}
 */
export async function actorKeyHolder({
  actor,
  credential,
  retiredUnlockSpaceIds
}: {
  actor: WalletActor
  credential?: UnlockCredential
  retiredUnlockSpaceIds?: string[]
}): Promise<InvariantKeyHolder> {
  const modules = await loadPortModules()
  const { profile } = actor.session
  const standing = profile.standingUnlock
  const unlockMethod = profile.unlockMethod
  const did = profile.accountPointer?.did

  const readRegistry = once(() =>
    actor.run(session => modules.getUnlockMethods({ session }))
  )
  const readVerified = once(() =>
    actor.run(session => modules.refreshVerifiedAccountLog({ session }))
  )
  const readServedRecord = once(async () =>
    credential === undefined
      ? undefined
      : await actor.run(() =>
          modules.fetchTransientKeyring({
            credential,
            accountLogPinStore: modules.memoryResourceLogPinStore()
          })
        )
  )

  /**
   * The acting credential's registry entry, matched on its unlock Space.
   *
   * @returns {Promise<object | undefined>}
   */
  async function actingEntry() {
    const registry = await readRegistry()
    return registry?.methods.find(
      method =>
        modules.isStandingCredentialEntry(method) &&
        method.unlockSpaceId === standing?.unlockSpaceId
    ) as StandingCredentialEntry | undefined
  }

  /**
   * The acting credential's bridge and sibling delegations: off the served
   * unlock record when the credential was handed in, else the session's
   * standing members.
   *
   * @returns {Promise<object | undefined>}
   */
  async function standingDelegations() {
    const served = await readServedRecord()
    return served?.standing ?? standing
  }

  /**
   * Whether the verified document lists the acting credential, by the
   * detector `documentListsCredential` the declaration carries.
   *
   * @returns {Promise<InvariantCheckOutcome>}
   */
  async function actingCredentialListed(): Promise<InvariantCheckOutcome> {
    if (!standing || !unlockMethod || did === undefined) {
      return undetermined('The session holds no standing credential.')
    }
    const { doc } = await readVerified()
    return await declaredDetector({
      modules,
      id: 'document-lists-the-acting-credential',
      deps: {
        doc,
        did,
        keyAgreementKeyMultibase:
          standing.standingClient.keyAgreementKeyMultibase,
        published: modules.keyAgreementPublicationOf({
          type: unlockMethod.type
        })
      },
      evidence: { unlockSpaceId: standing.unlockSpaceId }
    })
  }

  /**
   * `unlock-record-points-at-the-account-did` and
   * `account-pointer-names-the-account-did`, over the acting credential's
   * served unlock record.
   */
  const recordPointer: InvariantCheck = async ({ account }) => {
    if (credential === undefined) {
      return undetermined(
        'No unlock credential was handed to the key holder, and the unlock record opens under it alone.'
      )
    }
    const served = await readServedRecord()
    if (!served) {
      return violated({ unlockRecord: 'absent' })
    }
    return served.pointer?.did === account.did
      ? holds()
      : violated({ pointer: served.pointer?.did, did: account.did })
  }

  const checks: Partial<Record<InvariantId, InvariantCheck>> = {
    // The registry read's stale-seal refusal is the re-seal repair's
    // detector.
    'unlock-registry-opens-under-the-current-user-key': async () => {
      try {
        return (await readRegistry()) === null
          ? undetermined('The account has no registry.')
          : holds()
      } catch (err) {
        if (err instanceof modules.UnlockRegistryStaleSealError) {
          return violated({ registry: 'stale seal' })
        }
        throw err
      }
    },
    // The declaration's detector, over the reader a ceremony of this
    // session's kind would use.
    'registry-passphrase-entry-names-the-standing-credential': async () => {
      const registry = await readRegistry()
      // The detector reads each entry's unlock record, so it runs in the tab.
      return await actor.run(async session => {
        const context = await modules.accountCeremonyContext({ session })
        return await declaredDetector({
          modules,
          id: 'registry-passphrase-entry-names-the-standing-credential',
          deps: {
            registry,
            readerFor: modules.unlockEntryReaderFor({
              session,
              ...(context?.kind === 'ladder'
                ? { signer: context.ladderDeleter }
                : {})
            })
          }
        })
      })
    },
    'passkey-entry-carries-its-standing-configuration': async () => {
      const registry = await readRegistry()
      const bare = (registry?.methods ?? [])
        .filter(
          method =>
            method.type === 'passkey' && !method.keyAgreementKeyMultibase
        )
        .map(method => method.unlockSpaceId)
      return bare.length === 0 ? holds() : violated({ bare })
    },
    // A passphrase stands when the document publishes a commitment-form
    // credential entry; the acting passphrase's entry must name its unlock
    // Space and carry its management zcap.
    'registry-lists-the-passphrase-method': async () => {
      if (did === undefined) {
        return undetermined('No account DID.')
      }
      const registry = await readRegistry()
      const { doc } = await readVerified()
      const passphraseStands = modules
        .credentialKeyAgreementMethods({ doc, did })
        .some(method => method.type === modules.MULTIKEY_COMMITMENT_VM_TYPE)
      const entry = registry?.methods.find(
        method => method.type === 'passphrase'
      )
      if (passphraseStands && entry === undefined) {
        return violated({ passphraseEntry: 'absent' })
      }
      if (unlockMethod?.type === 'passphrase' && entry !== undefined) {
        if (entry.unlockSpaceId !== unlockMethod.unlockSpaceId) {
          return violated({
            entryUnlockSpaceId: entry.unlockSpaceId,
            actingUnlockSpaceId: unlockMethod.unlockSpaceId
          })
        }
        if (!entry.manageCapability) {
          return violated({ manageCapability: 'absent' })
        }
      }
      return holds()
    },
    // `standingZcapStale`, the rule the standing-delegation refresh
    // re-mints on.
    'standing-delegations-verify-under-the-current-document': async () => {
      const delegations = await standingDelegations()
      if (!delegations) {
        return undetermined('The session holds no standing credential.')
      }
      const { doc } = await readVerified()
      const stale = [
        ['delegation', delegations.delegation],
        ['delegatedClients', delegations.delegatedClients]
      ]
        .filter(
          (
            pair
          ): pair is [string, NonNullable<typeof delegations.delegation>] =>
            pair[1] !== undefined
        )
        .filter(([, zcap]) => modules.standingZcapStale({ zcap, doc }))
        .map(([name]) => name)
      return stale.length === 0 ? holds() : violated({ stale })
    },
    // `attributeLadderRung`, the attribution `refreshCommittedLadderRung`
    // records from.
    'registry-records-the-committed-ladder-rung': async () => {
      const ladderSeed =
        (await readServedRecord())?.standing?.ladderSeed ?? profile.ladderSeed
      if (ladderSeed === undefined) {
        return undetermined('The session holds no ladder seed.')
      }
      const verified = await readVerified()
      const { rung, state } = await modules.attributeLadderRung({
        ladderSeed,
        published: verified
      })
      if (state !== 'committed') {
        return holds()
      }
      const entry = await actingEntry()
      return entry?.updateKeyMultibase === rung.keyMultibase
        ? holds()
        : violated({
            recorded: entry?.updateKeyMultibase,
            committed: rung.keyMultibase
          })
    },
    'unlock-record-points-at-the-account-did': recordPointer,
    'account-pointer-names-the-account-did': recordPointer,
    // The key-holder half: `rosterWrapsRecipient` over the acting
    // credential's roster kid.
    'roster-and-collection-epochs-exist': async ({ account }) => {
      if (!standing || account.roster === undefined) {
        return undetermined('No standing credential, or no roster to open.')
      }
      const recipientId = standing.standingClient.recipientKid
      return modules.rosterWrapsRecipient({
        descriptor: account.roster as Parameters<
          PortModules['rosterWrapsRecipient']
        >[0]['descriptor'],
        recipientId
      })
        ? holds()
        : violated({ unwrapped: recipientId })
    },
    // Once the document lists the acting credential, its registry entry
    // must record its delegations.
    'registry-records-the-establishing-credential': async () => {
      const listed = await actingCredentialListed()
      if (listed.outcome !== 'holds') {
        return listed.outcome === 'violated' ? holds() : listed
      }
      const entry = await actingEntry()
      if (entry === undefined) {
        return violated({ missing: ['entry'] })
      }
      // The fields a recorded delegation writes, as the ceremonies write
      // them (`standingUnlockFields`), each expected present on the entry.
      const delegations = await standingDelegations()
      const missing = Object.keys(
        modules.standingUnlockFields({
          delegation: delegations?.delegation,
          delegatedClients: delegations?.delegatedClients
        })
      ).filter(field => !(entry as unknown as Record<string, unknown>)[field])
      return missing.length === 0 ? holds() : violated({ missing })
    },
    // The key-holder half: `delegatedClientsDelegationSpaceId`, the
    // Space the sibling delegation aims at.
    'annex-generation-is-reachable': async ({ account }) => {
      const delegations = await standingDelegations()
      if (!delegations || account.pointedAnnex === undefined) {
        return undetermined('No standing credential, or no pointed generation.')
      }
      const target =
        delegations.delegatedClients === undefined
          ? undefined
          : modules.delegatedClientsDelegationSpaceId({
              delegation: delegations.delegatedClients
            })
      return target === account.pointedAnnex.annexSpaceId
        ? holds()
        : violated({
            siblingTarget: target ?? 'absent',
            pointedSpace: account.pointedAnnex.annexSpaceId
          })
    },
    // The refresh's own staleness test: an absent zcap, or one
    // `zcapExpiring` flags.
    'acting-credential-manage-zcap-is-current': async () => {
      const entry = await actingEntry()
      if (entry === undefined) {
        return undetermined(
          'The registry holds no entry for the acting credential (registry-records-the-establishing-credential).'
        )
      }
      const expires = modules.zcapExpires(entry.manageCapability)
      return entry.manageCapability && !modules.zcapExpiring({ expires })
        ? holds()
        : violated({
            manageCapability: entry.manageCapability ? expires : 'absent'
          })
    },
    // The declaration's detector.
    'document-lists-the-acting-credential': async () =>
      await actingCredentialListed(),
    // `findUnrecordedCredentials`, the detector the deletion walk and
    // the last-client transition read.
    'every-document-key-agreement-entry-has-a-locatable-credential':
      async () => {
        if (did === undefined) {
          return undetermined('No account DID.')
        }
        const unrecorded = await modules.findUnrecordedCredentials({
          doc: (await readVerified()).doc,
          did,
          registry: await readRegistry()
        })
        return unrecorded.length === 0 ? holds() : violated({ unrecorded })
      },
    // The declaration's detector (`checkRecoveryHealth`).
    'saved-recovery-codes-locate-their-account': async () =>
      await actor.run(session =>
        declaredDetector({
          modules,
          id: 'saved-recovery-codes-locate-their-account',
          deps: { session }
        })
      ),
    // The store lists every unlock Space by its type, of every account, and
    // nothing in one names its account. The compared set is scoped to this
    // account by the caller's own knowledge: the unlock Spaces of the
    // credentials it retired. Such a Space violates the row when the store
    // still holds it and no live registry entry names it. One the registry
    // still names is a credential not yet retired, which is another row's.
    'no-unlock-space-outlives-its-credential': async ({ account }) => {
      if (retiredUnlockSpaceIds === undefined) {
        return undetermined(
          "No retired credential's unlock Space was named to the key holder, and an unlock Space carries no plaintext link to its account."
        )
      }
      const registry = await readRegistry()
      const live = new Set(
        (registry?.methods ?? []).map(method => method.unlockSpaceId)
      )
      const stored = new Set(account.unlockSpaceIds)
      const outlived = retiredUnlockSpaceIds.filter(
        unlockSpaceId => stored.has(unlockSpaceId) && !live.has(unlockSpaceId)
      )
      return outlived.length === 0 ? holds() : violated({ outlived })
    },
    // `sweepConnectionWriters`, the sweep the encounter registration runs,
    // over the listing the page reads (without the page's hold, so no real
    // sweep starts) and a store whose write is a no-op. A writer the dry
    // sweep would mark inactive or drop is the violation.
    'no-registered-writer-outlives-its-expiry': async ({ now }) => {
      const listing = await actor.run(async session => {
        const { store, hmacKey } = await session.storage.connectionsDirectory()
        return await modules.readConnections({ store, hmacKey })
      })
      if (listing === null) {
        return undetermined('The connections directory could not be listed.')
      }
      const store = {
        put: async () => ({})
      } as unknown as Parameters<
        PortModules['sweepConnectionWriters']
      >[0]['store']
      const swept = await modules.sweepConnectionWriters({
        store,
        listing,
        now: new Date(now)
      })
      const where = (writerId: string) => ({
        writerId,
        resourceId: listing.entries.find(item =>
          item.entry.writers.some(writer => writer.writerId === writerId)
        )?.resourceId
      })
      if (swept.markedInactive.length > 0 || swept.dropped.length > 0) {
        return violated({
          markedInactive: swept.markedInactive.map(where),
          dropped: swept.dropped.map(where)
        })
      }
      const unopened = [...listing.unreadable, ...listing.unparseable]
      return unopened.length === 0
        ? holds()
        : undetermined(
            `The writers of ${unopened.length} connections entries could not be read.`
          )
    }
  }
  return { name: actor.name, checks }
}

/**
 * Audits the account an actor is on, with the actor as the key holder.
 *
 * @param options {object}
 * @param options.harness {WalletHarness}
 * @param options.actor {WalletActor}   a live actor
 * @param [options.passphrase] {string}   the passphrase the actor logged in
 *   with, so the served unlock record can be read
 * @param [options.passkey] {TestPasskey}   the passkey the actor logged in
 *   with, likewise
 * @param [options.retiredUnlockSpaceIds] {string[]}   the unlock Space ids
 *   of the credentials the account has retired, or an empty list when it
 *   retired none (see `actorKeyHolder`)
 * @returns {Promise<InvariantAudit>}
 */
export async function auditActor({
  harness,
  actor,
  passphrase,
  passkey,
  retiredUnlockSpaceIds
}: {
  harness: WalletHarness
  actor: WalletActor
  passphrase?: string
  passkey?: TestPasskey
  retiredUnlockSpaceIds?: string[]
}): Promise<InvariantAudit> {
  const { deriveUnlockCredential, KEYRING_KDF, PASSKEY_KDF } =
    await loadPortModules()
  const secret = passphrase ?? passkey?.prfOutput
  let credential: UnlockCredential | undefined
  if (secret !== undefined) {
    const key =
      typeof secret === 'string'
        ? `passphrase:${secret}`
        : `passkey:${Buffer.from(secret).toString('base64')}`
    let derived = derivedCredentials.get(key)
    if (derived === undefined) {
      derived = deriveUnlockCredential({
        secret,
        kdf: typeof secret === 'string' ? KEYRING_KDF : PASSKEY_KDF
      })
      derivedCredentials.set(key, derived)
    }
    credential = await derived
  }
  return await auditInvariants({
    dataDir: harness.dataDir,
    spaceId: actor.spaceId,
    keyHolder: await actorKeyHolder({
      actor,
      credential,
      retiredUnlockSpaceIds
    })
  })
}
