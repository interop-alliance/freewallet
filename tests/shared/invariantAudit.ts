/**
 * The invariant auditor: evaluates the mender registry's invariants for one
 * account from outside any session, and reports which stand violated, with
 * the evidence for each, and which were not checked, with the reason.
 *
 * The census (`invariantCensus.ts`) says where each invariant can be checked
 * from. Every `stored` row is checked here, off the teaching server's
 * FileSystem backend under its data root, through the readers in
 * `storedLogs.ts` and `storeOracle.ts`. Every `key-holder` row, and the
 * key-holder half of a `stored` row, is checked through an injected
 * `InvariantKeyHolder` port when one is given. With none, a `key-holder` row
 * is skipped with a reason and a `stored` row stands on its stored half.
 * `browser-local` and `unchecked` rows are skipped with the census's reason.
 *
 * Where wallet-core or `@interop/vh-resource-log` exports the predicate a
 * registered mender decides on, the check calls it, so the auditor and the
 * mender cannot disagree about what holds. Each check's header names the one
 * it shares. The reads are unverified: the store is the oracle, and the
 * session under test is what verifies the logs.
 *
 * A check that cannot settle (it threw, or the state it reads is missing for
 * a reason another row covers) reports the row as skipped rather than
 * violated. The exception is a row whose missing state IS the violation.
 *
 * The auditor reports and nothing else: it writes nothing, mends nothing, and
 * is registered on no chain. This module imports nothing under `src/`, so the
 * Playwright process can load it beside `expectNoFailedMenders`.
 */
import { relationIds, vmFragmentOf } from '@interop/vh-resource-log'
import type { InvariantId } from '@interop/wallet-core/menders'
import {
  CLIENT_ANNEX_SPACE_TYPE,
  clientAnnexGcDue,
  delegatedClientsPointer,
  delegatedClientsPointerHistory,
  delegatedClientsSpaceHistory,
  embeddedGenerationDelegation,
  GENERATION_ID_PREFIX,
  generationQuiet
} from '@interop/wallet-core/clientAnnex'
import {
  currentEpochOf,
  enrolledClientRosterRecipients,
  userKeyRosterRecipientResolver
} from '@interop/wallet-core/keys'
import {
  encryptedWalletCollectionIds,
  WALLET_SPACE_PROVISION_ROSTER
} from '@interop/wallet-core/space/collections'
import {
  accountLogDids,
  commitmentMatchesKey,
  credentialKeyAgreementMethods,
  ensureDidWebProjection,
  MULTIKEY_COMMITMENT_VM_TYPE,
  standingZcapStale
} from '@interop/wallet-core/webvh'
import type { CollectionEncryption } from '@interop/was-client'
import { epochKeyIdFor } from '@interop/was-client/edv/cipher'
import { INVARIANT_CENSUS, type InvariantCensusRow } from './invariantCensus'
import {
  listStoredCollectionIds,
  listStoredKeystores,
  listStoredSpaceIds,
  readStoredKeystoreConfig,
  readStoredSpaceMeta,
  spaceExistsInStore
} from './storeOracle'
import {
  accountLogRemovalIndex,
  accountLogVersionsOf,
  annexLocationOf,
  readCollectionDescriptor,
  readCollectionLogHeadAnchor,
  readRosterLogHeadAnchor,
  readStoredLog,
  readStoredResource,
  readUserKeyRosterDescriptor
} from './storedLogs'

/**
 * The account log as the GC predicates read it.
 */
type AccountLog = Parameters<typeof clientAnnexGcDue>[0]['log']

/**
 * A document as the annex readers read it.
 */
type AnnexDocument = Parameters<typeof delegatedClientsPointer>[0]['doc']

/**
 * What one check found.
 *
 * - `holds`: the predicate is true.
 * - `violated`: it is false, and `evidence` says why.
 * - `undetermined`: the check could not settle it, and `reason` says why.
 */
export type InvariantCheckOutcome =
  | { outcome: 'holds' }
  | { outcome: 'violated'; evidence: unknown }
  | { outcome: 'undetermined'; reason: string }

/**
 * The account as the store holds it, read once per audit and handed to every
 * check: whether the Space stands, the account log with its versions, its
 * head document, and the DID it resolves to, the user key roster's head
 * descriptor, the Space's live collections with each governed one's head
 * descriptor, and the annex generation the head points at with its log.
 */
export interface StoredAccount {
  readonly dataDir: string
  readonly spaceId: string
  readonly stored: boolean
  readonly did: string | undefined
  readonly log: AccountLog
  readonly versionIds: string[]
  readonly removalIndex: number
  readonly doc: (AnnexDocument & Record<string, unknown>) | undefined
  readonly roster: CollectionEncryption | undefined
  readonly collectionIds: string[]
  readonly governed: Array<{
    collectionId: string
    descriptor: CollectionEncryption
  }>
  readonly pointer: string | undefined
  readonly pointedAnnex:
    { annexSpaceId: string; generationId: string } | undefined
  readonly pointedLog: AccountLog
}

/**
 * One check over a stored account.
 */
export type InvariantCheck = (options: {
  account: StoredAccount
  now: number
}) => Promise<InvariantCheckOutcome>

/**
 * The key-holder port: a party holding the user key or the acting unlock
 * credential, offering a check for each row it can settle. The auditor runs
 * a `key-holder` row's check, and a `stored` row's key-holder half, through
 * it.
 */
export interface InvariantKeyHolder {
  readonly name: string
  readonly checks: Partial<Record<InvariantId, InvariantCheck>>
}

/**
 * What one audit found: the violated invariants with their evidence, the
 * ones checked and holding, and the ones not checked with the reason.
 */
export interface InvariantAudit {
  readonly spaceId: string
  readonly violated: Array<{ id: InvariantId; evidence: unknown }>
  readonly held: InvariantId[]
  readonly skipped: Array<{ id: InvariantId; reason: string }>
}

/**
 * The predicate holds.
 *
 * @returns {InvariantCheckOutcome}
 */
export function holds(): InvariantCheckOutcome {
  return { outcome: 'holds' }
}

/**
 * The predicate is false.
 *
 * @param evidence {unknown}   what the check saw
 * @returns {InvariantCheckOutcome}
 */
export function violated(evidence: unknown): InvariantCheckOutcome {
  return { outcome: 'violated', evidence }
}

/**
 * The check could not settle the predicate.
 *
 * @param reason {string}
 * @returns {InvariantCheckOutcome}
 */
export function undetermined(reason: string): InvariantCheckOutcome {
  return { outcome: 'undetermined', reason }
}

/**
 * Settles a check over the account document, or reports it undetermined
 * when the account log is absent.
 *
 * @param options {object}
 * @param options.account {StoredAccount}
 * @param options.check {Function}   the check, given the DID and document
 * @returns {Promise<InvariantCheckOutcome>}
 */
async function withDocument({
  account,
  check
}: {
  account: StoredAccount
  check: (options: {
    did: string
    doc: AnnexDocument & Record<string, unknown>
  }) => Promise<InvariantCheckOutcome>
}): Promise<InvariantCheckOutcome> {
  if (account.did === undefined || account.doc === undefined) {
    return undetermined('The account log is absent from the store.')
  }
  return await check({ did: account.did, doc: account.doc })
}

/**
 * The recipient kids of a descriptor's current epoch, resolved through
 * `currentEpochOf` (which every reader resolves through), or undefined when
 * the descriptor names no current epoch in its own list.
 *
 * @param options {object}
 * @param options.descriptor {CollectionEncryption}
 * @param options.label {string}   names the descriptor in the refusal
 * @returns {Set<string> | undefined}
 */
function currentEpochKids({
  descriptor,
  label
}: {
  descriptor: CollectionEncryption
  label: string
}): Set<string> | undefined {
  try {
    return new Set(
      currentEpochOf({ descriptor, label }).recipients.map(
        recipient => recipient.header.kid
      )
    )
  } catch {
    return undefined
  }
}

/**
 * The stored log of one annex generation, oldest first.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.annexSpaceId {string}
 * @param options.generationId {string}
 * @returns {Promise<AccountLog>}
 */
async function readGenerationLog({
  dataDir,
  annexSpaceId,
  generationId
}: {
  dataDir: string
  annexSpaceId: string
  generationId: string
}): Promise<AccountLog> {
  return (await readStoredLog({
    dataDir,
    spaceId: annexSpaceId,
    collectionId: generationId,
    resourceId: 'did.jsonl'
  })) as unknown as AccountLog
}

/**
 * The stored-state checks, one per `stored` census row.
 */
const STORED_CHECKS: Partial<Record<InvariantId, InvariantCheck>> = {
  /**
   * The retire direction is the converger's own: a current-epoch
   * recipient `userKeyRosterRecipientResolver` cannot back is one the
   * document stopped keying. The escrow direction is the converger's
   * `enrolledClientRosterRecipients`. A standing credential the document
   * keys must also hold a wrap, matched on its published form (a verbatim
   * key, or a commitment through `commitmentMatchesKey`).
   */
  'roster-wraps-exactly-the-document-key-set': async ({ account }) =>
    await withDocument({
      account,
      check: async ({ did, doc }) => {
        if (account.roster === undefined) {
          return undetermined(
            'The account holds no roster (roster-and-collection-epochs-exist).'
          )
        }
        const document = doc as Parameters<
          typeof userKeyRosterRecipientResolver
        >[0]['document']
        const recipients = currentEpochOf({
          descriptor: account.roster,
          label: 'The user key roster'
        }).recipients
        const resolve = userKeyRosterRecipientResolver({ document })
        const kids = recipients.map(recipient => recipient.header.kid)
        const unbacked: string[] = []
        for (const kid of kids) {
          if ((await resolve(kid)) === null) {
            unbacked.push(kid)
          }
        }
        const unwrappedClients = enrolledClientRosterRecipients({ document })
          .map(recipient => recipient.id)
          .filter(kid => !kids.includes(kid))
        const wrappedKeys = kids
          .map(kid => vmFragmentOf(kid))
          .filter((key): key is string => key !== undefined)
        const unwrappedCredentials = credentialKeyAgreementMethods({
          doc: document,
          did
        })
          .filter(method =>
            method.type === MULTIKEY_COMMITMENT_VM_TYPE
              ? !wrappedKeys.some(keyAgreementKeyMultibase =>
                  commitmentMatchesKey({
                    commitment: method.publicKeyCommitment ?? '',
                    keyAgreementKeyMultibase
                  })
                )
              : !wrappedKeys.includes(method.publicKeyMultibase ?? '')
          )
          .map(method => method.id)
        if (
          unbacked.length === 0 &&
          unwrappedClients.length === 0 &&
          unwrappedCredentials.length === 0
        ) {
          return holds()
        }
        return violated({ unbacked, unwrappedClients, unwrappedCredentials })
      }
    }),

  /**
   * Sealed means the head's controller version is at or past the
   * latest `assertionMethod` removal, the index `latestAssertionRemovalIndex`
   * computes for the sealing sweep.
   */
  'governed-log-heads-anchor-past-the-membership-change': async ({ account }) =>
    await withDocument({
      account,
      check: async () => {
        const unsealed: Array<{ collectionId: string; anchorIndex: number }> =
          []
        for (const { collectionId } of account.governed) {
          const anchor = await readCollectionLogHeadAnchor({
            dataDir: account.dataDir,
            spaceId: account.spaceId,
            collectionId,
            accountVersionIds: account.versionIds
          })
          if (
            anchor !== undefined &&
            anchor.anchorIndex < account.removalIndex
          ) {
            unsealed.push({ collectionId, anchorIndex: anchor.anchorIndex })
          }
        }
        return unsealed.length === 0
          ? holds()
          : violated({ removalIndex: account.removalIndex, unsealed })
      }
    }),

  /**
   * The cascade's no-op condition
   * (`rotateCollectionEpochsToUserKey`): the current epoch names the
   * current user key generation and no superseded one, and every epoch
   * carries the current generation's escrow. The kids are
   * `epochKeyIdFor`'s, as the cascade builds them.
   */
  'collection-epochs-name-the-current-user-key': async ({ account }) => {
    const currentGeneration = account.roster?.currentEpoch
    if (currentGeneration === undefined) {
      return undetermined(
        'The account holds no roster to name the current user key.'
      )
    }
    const userKeyKid = epochKeyIdFor(currentGeneration)
    const staleKids = (account.roster?.epochs ?? [])
      .map(epoch => epoch.id)
      .filter(id => id !== currentGeneration)
      .map(id => epochKeyIdFor(id))
    const stale: Array<{ collectionId: string; problem: string }> = []
    // A descriptor with no resolvable current epoch is
    // `roster-and-collection-epochs-exist`'s violation, not this row's.
    const unresolved: string[] = []
    for (const { collectionId, descriptor } of account.governed) {
      const currentKids = currentEpochKids({
        descriptor,
        label: 'The collection descriptor'
      })
      if (currentKids === undefined) {
        unresolved.push(collectionId)
        continue
      }
      if (!currentKids.has(userKeyKid)) {
        stale.push({ collectionId, problem: 'current epoch misses the key' })
      } else if (staleKids.some(kid => currentKids.has(kid))) {
        stale.push({ collectionId, problem: 'current epoch names a stale key' })
      } else if (
        !(descriptor.epochs ?? []).every(epoch =>
          epoch.recipients.some(
            recipient => recipient.header.kid === userKeyKid
          )
        )
      ) {
        stale.push({ collectionId, problem: 'an epoch misses the escrow' })
      }
    }
    if (stale.length > 0) {
      return violated({ currentGeneration, stale })
    }
    return unresolved.length === 0
      ? holds()
      : undetermined(
          `No current epoch resolves on ${unresolved.join(', ')}; ` +
            'roster-and-collection-epochs-exist owns that state.'
        )
  },

  /**
   * The Space metadata object's controller against the account DID.
   */
  'space-controller-is-the-account-did': async ({ account }) =>
    await withDocument({
      account,
      check: async ({ did }) => {
        const meta = await readStoredSpaceMeta({
          dataDir: account.dataDir,
          spaceId: account.spaceId
        })
        return meta?.controller === did
          ? holds()
          : violated({ controller: meta?.controller, did })
      }
    }),

  /**
   * The stored half: the roster stands with a current epoch in its
   * own list (`currentEpochOf`, which every reader resolves through), and
   * every encrypted standard collection the Space stores carries a
   * descriptor log with one. A collection the Space does not store at all is
   * `standard-collections-are-provisioned`'s.
   */
  'roster-and-collection-epochs-exist': async ({ account }) => {
    const missing: string[] = []
    if (account.roster === undefined) {
      missing.push('key-map/user-key.jsonl')
    } else if (
      currentEpochKids({
        descriptor: account.roster,
        label: 'The user key roster'
      }) === undefined
    ) {
      missing.push('key-map/user-key.jsonl current epoch')
    }
    for (const collectionId of encryptedWalletCollectionIds()) {
      if (!account.collectionIds.includes(collectionId)) {
        continue
      }
      const descriptor = account.governed.find(
        governed => governed.collectionId === collectionId
      )?.descriptor
      if (
        descriptor === undefined ||
        currentEpochKids({
          descriptor,
          label: 'The collection descriptor'
        }) === undefined
      ) {
        missing.push(`${collectionId} epoch`)
      }
    }
    return missing.length === 0 ? holds() : violated({ missing })
  },

  /**
   * The stored half: the document's `#DelegatedClients` pointer
   * (`delegatedClientsPointer`) names a generation in an auxiliary Space the
   * store holds, and the generation's log is published.
   */
  'annex-generation-is-reachable': async ({ account }) =>
    await withDocument({
      account,
      check: async () => {
        const { pointer, pointedAnnex } = account
        if (pointer === undefined) {
          return violated({ pointer: 'absent' })
        }
        if (pointedAnnex === undefined) {
          return violated({ pointer, malformed: true })
        }
        if (
          !(await spaceExistsInStore({
            dataDir: account.dataDir,
            spaceId: pointedAnnex.annexSpaceId
          }))
        ) {
          return violated({ pointer, auxiliarySpace: 'not stored' })
        }
        return account.pointedLog.length > 0
          ? holds()
          : violated({ pointer, generationLog: 'absent' })
      }
    }),

  /**
   * The staleness rule is `standingZcapStale` over the pointed
   * generation's embedded delegation (`embeddedGenerationDelegation`), the
   * one `ensureGenerationDelegationCurrent` renews on.
   */
  'generation-delegation-is-current': async ({ account, now }) =>
    await withDocument({
      account,
      check: async ({ doc }) => {
        if (account.pointer === undefined) {
          return violated({ pointer: 'absent' })
        }
        if (account.pointedAnnex === undefined) {
          return violated({ pointer: account.pointer, malformed: true })
        }
        const head = account.pointedLog[account.pointedLog.length - 1]
        if (head === undefined) {
          return violated({ generationLog: 'absent' })
        }
        const delegation = embeddedGenerationDelegation({
          doc: head.state as AnnexDocument
        })
        if (delegation === undefined) {
          return violated({ delegation: 'absent' })
        }
        return standingZcapStale({
          zcap: delegation,
          doc: doc as NonNullable<
            Parameters<typeof standingZcapStale>[0]['doc']
          >,
          now
        })
          ? violated({
              delegationId: (delegation as { id?: string }).id,
              expires: (delegation as { expires?: string }).expires
            })
          : holds()
      }
    }),

  /**
   * The comparison is `ensureDidWebProjection`'s own, run over a store
   * whose write is a no-op: any outcome but `current` is the mismatch.
   */
  'did-web-projection-matches-the-log': async ({ account }) =>
    await withDocument({
      account,
      check: async ({ did, doc }) => {
        const text = await readStoredResource({
          dataDir: account.dataDir,
          spaceId: account.spaceId,
          collectionId: 'id',
          resourceId: 'did.json'
        })
        const store = {
          getIdResourceRaw: async () =>
            text === undefined ? undefined : { text },
          putIdResource: async () => {}
        } as unknown as Parameters<typeof ensureDidWebProjection>[0]['store']
        const { outcome } = await ensureDidWebProjection({
          store,
          did,
          doc: doc as Parameters<typeof ensureDidWebProjection>[0]['doc']
        })
        return outcome === 'current'
          ? holds()
          : violated({ projection: text === undefined ? 'absent' : 'differs' })
      }
    }),

  /**
   * The annex GC's own rules: the swap is due when
   * `clientAnnexGcDue` says so and the pointed generation is
   * `generationQuiet`, a pointed generation with no log is the `repaired`
   * swap's state, and an unpointed `gen-` collection is collectable when it
   * holds no log, when the log ever pointed at its published DID
   * (`delegatedClientsPointerHistory`, as the GC compares them), or when
   * it is quiet. Like the GC's fan-out, the walk lists the pointed auxiliary
   * Space alone.
   */
  'no-annex-generation-outlives-its-pointer': async ({ account, now }) =>
    await withDocument({
      account,
      check: async () => {
        if (account.pointedAnnex === undefined) {
          return holds()
        }
        const { annexSpaceId, generationId } = account.pointedAnnex
        if (account.pointedLog.length === 0) {
          return violated({ pointedGeneration: generationId, log: 'absent' })
        }
        if (
          clientAnnexGcDue({ log: account.log, now }) &&
          generationQuiet({ log: account.pointedLog, now })
        ) {
          return violated({ pointedGeneration: generationId, swap: 'due' })
        }
        const everPointed = new Set(
          delegatedClientsPointerHistory({ log: account.log })
        )
        const collectable: string[] = []
        for (const candidate of await listStoredCollectionIds({
          dataDir: account.dataDir,
          spaceId: annexSpaceId
        })) {
          if (
            !candidate.startsWith(GENERATION_ID_PREFIX) ||
            candidate === generationId
          ) {
            continue
          }
          const log = await readGenerationLog({
            dataDir: account.dataDir,
            annexSpaceId,
            generationId: candidate
          })
          const publishedDid = (
            log[log.length - 1]?.state as { id?: string } | undefined
          )?.id
          if (
            log.length === 0 ||
            (publishedDid !== undefined && everPointed.has(publishedDid)) ||
            generationQuiet({ log, now })
          ) {
            collectable.push(candidate)
          }
        }
        return collectable.length === 0
          ? holds()
          : violated({ annexSpaceId, collectable })
      }
    }),

  /**
   * `key-map/keys.json` names the account's KMS key, whose id names
   * its keystore; the keystore's stored configuration names its controller.
   */
  'keystore-controller-is-the-account-did': async ({ account }) =>
    await withDocument({
      account,
      check: async ({ did }) => {
        const keys = await readStoredResource({
          dataDir: account.dataDir,
          spaceId: account.spaceId,
          collectionId: 'key-map',
          resourceId: 'keys.json'
        })
        const kmsKeyId = (
          keys === undefined
            ? undefined
            : (JSON.parse(keys) as { authentication?: { kmsKeyId?: string } })
        )?.authentication?.kmsKeyId
        const keystoreId =
          kmsKeyId === undefined
            ? undefined
            : /\/keystores\/([^/]+)\//.exec(kmsKeyId)?.[1]
        if (keystoreId === undefined) {
          return undetermined(
            'key-map/keys.json records no KMS key, so no keystore is named.'
          )
        }
        const config = await readStoredKeystoreConfig({
          dataDir: account.dataDir,
          keystoreId
        })
        return config?.controller === did
          ? holds()
          : violated({ keystoreId, controller: config?.controller ?? null })
      }
    }),

  /**
   * Any member of the head document's `authentication` relation counts.
   */
  'account-document-publishes-an-authentication-key': async ({ account }) =>
    await withDocument({
      account,
      check: async ({ doc }) =>
        relationIds(
          doc.authentication as Array<string | { id?: string }> | undefined
        ).length > 0
          ? holds()
          : violated({ authentication: doc.authentication ?? 'absent' })
    }),

  /**
   * While the account Space stands the predicate holds; once it is
   * gone, a keystore whose controller is the account's did:webvh (which
   * embeds the Space id) has outlived it. A keystore whose controller was
   * never promoted off the ladder's bare did:key names no Space, so this
   * check cannot see it once `key-map/keys.json` is gone with the Space.
   */
  'no-keystore-outlives-its-account': async ({ account }) => {
    if (account.stored) {
      return holds()
    }
    const suffix = `:space:${account.spaceId}:id`
    const orphans = (await listStoredKeystores({ dataDir: account.dataDir }))
      .filter(
        keystore =>
          keystore.controller?.startsWith('did:webvh:') &&
          keystore.controller.endsWith(suffix)
      )
      .map(keystore => keystore.keystoreId)
    return orphans.length === 0 ? holds() : violated({ keystores: orphans })
  },

  /**
   * The roster is wallet-core's `WALLET_SPACE_PROVISION_ROSTER`, the
   * one `ensureUserCollections` provisions from; an `edv` collection's
   * descriptor is its governing log.
   */
  'standard-collections-are-provisioned': async ({ account }) => {
    const missing: string[] = []
    for (const spec of WALLET_SPACE_PROVISION_ROSTER) {
      if (!account.collectionIds.includes(spec.collectionId)) {
        missing.push(spec.collectionId)
      } else if (
        spec.encryption === 'edv' &&
        !account.governed.some(
          governed => governed.collectionId === spec.collectionId
        )
      ) {
        missing.push(`${spec.collectionId} descriptor`)
      }
    }
    return missing.length === 0 ? holds() : violated({ missing })
  },

  /**
   * An auxiliary Space of the annex type
   * (`CLIENT_ANNEX_SPACE_TYPE`) attributable to the account must be one a
   * pointer entry named (`delegatedClientsSpaceHistory`). Attributable means
   * controlled by the account DID, or by the bare did:key of a ladder VM
   * the account log has ever published (`accountLogDids`). A
   * ladder-signed mint creates the Space under that did:key and flips it to
   * the account DID afterwards, so a tear before the flip leaves the did:key
   * standing.
   * A Space minted under a ladder VM the log never published (a recovery
   * spend torn before its add entry) cannot be attributed from stored state.
   */
  'no-auxiliary-space-stands-unnamed': async ({ account }) =>
    await withDocument({
      account,
      check: async ({ did }) => {
        const named = new Set(
          delegatedClientsSpaceHistory({ log: account.log }).map(
            space => space.spaceId
          )
        )
        const controllers = new Set([
          did,
          ...accountLogDids({ log: account.log }).ladderDids
        ])
        const unnamed: string[] = []
        for (const spaceId of await listStoredSpaceIds({
          dataDir: account.dataDir
        })) {
          if (named.has(spaceId)) {
            continue
          }
          const meta = await readStoredSpaceMeta({
            dataDir: account.dataDir,
            spaceId
          })
          if (
            meta?.controller !== undefined &&
            controllers.has(meta.controller) &&
            CLIENT_ANNEX_SPACE_TYPE.every(type => meta.type?.includes(type))
          ) {
            unnamed.push(spaceId)
          }
        }
        return unnamed.length === 0 ? holds() : violated({ unnamed })
      }
    }),

  /**
   * The sealing rule of `governed-log-heads-anchor-past-the-membership-change`,
   * over the roster log.
   */
  'roster-log-head-anchors-past-the-membership-change': async ({ account }) =>
    await withDocument({
      account,
      check: async () => {
        const anchor = await readRosterLogHeadAnchor({
          dataDir: account.dataDir,
          spaceId: account.spaceId,
          accountVersionIds: account.versionIds
        })
        if (anchor === undefined) {
          return undetermined(
            'The account holds no roster (roster-and-collection-epochs-exist).'
          )
        }
        return anchor.anchorIndex >= account.removalIndex
          ? holds()
          : violated({
              removalIndex: account.removalIndex,
              anchorIndex: anchor.anchorIndex
            })
      }
    })
}

/**
 * The `stored` census rows the auditor has a check for. A unit test holds
 * this equal to the census's `stored` rows.
 */
export const STORED_CHECK_IDS = Object.keys(STORED_CHECKS) as InvariantId[]

/**
 * Reads the account as the store holds it, every file once.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.spaceId {string}
 * @returns {Promise<StoredAccount>}
 */
async function readStoredAccount({
  dataDir,
  spaceId
}: {
  dataDir: string
  spaceId: string
}): Promise<StoredAccount> {
  const stored = await spaceExistsInStore({ dataDir, spaceId })
  const log = await readStoredLog({
    dataDir,
    spaceId,
    collectionId: 'id',
    resourceId: 'did.jsonl'
  })
  const versions = accountLogVersionsOf({ log })
  const doc = log[log.length - 1]?.state as
    (AnnexDocument & Record<string, unknown>) | undefined
  const pointer =
    doc === undefined ? undefined : delegatedClientsPointer({ doc })
  // A pointer that is not an annex DID names no generation.
  let pointedAnnex: StoredAccount['pointedAnnex']
  try {
    pointedAnnex =
      pointer === undefined ? undefined : annexLocationOf({ pointer })
  } catch {
    pointedAnnex = undefined
  }
  const collectionIds = await listStoredCollectionIds({ dataDir, spaceId })
  const governed: StoredAccount['governed'] = []
  for (const collectionId of collectionIds) {
    const descriptor = await readCollectionDescriptor({
      dataDir,
      spaceId,
      collectionId
    })
    if (descriptor !== undefined) {
      governed.push({ collectionId, descriptor })
    }
  }
  return {
    dataDir,
    spaceId,
    stored,
    did: typeof doc?.id === 'string' ? doc.id : undefined,
    log: log as unknown as AccountLog,
    versionIds: versions.map(version => version.versionId),
    removalIndex: await accountLogRemovalIndex({ versions }),
    doc,
    roster: await readUserKeyRosterDescriptor({ dataDir, spaceId }),
    collectionIds,
    governed,
    pointer,
    pointedAnnex,
    pointedLog:
      pointedAnnex === undefined
        ? []
        : await readGenerationLog({ dataDir, ...pointedAnnex })
  }
}

/**
 * Runs one check, turning a throw into an undetermined outcome.
 *
 * @param options {object}
 * @param options.check {InvariantCheck}
 * @param options.account {StoredAccount}
 * @param options.now {number}
 * @returns {Promise<InvariantCheckOutcome>}
 */
async function settle({
  check,
  account,
  now
}: {
  check: InvariantCheck
  account: StoredAccount
  now: number
}): Promise<InvariantCheckOutcome> {
  try {
    return await check({ account, now })
  } catch (err) {
    return undetermined(
      `The check threw: ${(err as Error)?.message ?? String(err)}`
    )
  }
}

/**
 * Audits one account against every declared invariant.
 *
 * @param options {object}
 * @param options.dataDir {string}   the server's data root
 * @param options.spaceId {string}   the account Space id
 * @param [options.keyHolder] {InvariantKeyHolder}   a party holding the
 *   user key or the acting unlock credential; without one, every
 *   `key-holder` row is skipped and a `stored` row with a key-holder half is
 *   settled on its stored half alone
 * @param [options.now] {number}   epoch milliseconds, the clock the expiry
 *   and cadence checks read
 * @returns {Promise<InvariantAudit>}
 */
export async function auditInvariants({
  dataDir,
  spaceId,
  keyHolder,
  now = Date.now()
}: {
  dataDir: string
  spaceId: string
  keyHolder?: InvariantKeyHolder
  now?: number
}): Promise<InvariantAudit> {
  const audit: InvariantAudit = {
    spaceId,
    violated: [],
    held: [],
    skipped: []
  }
  const account = await readStoredAccount({ dataDir, spaceId })
  for (const [id, row] of Object.entries(INVARIANT_CENSUS) as Array<
    [InvariantId, InvariantCensusRow]
  >) {
    if (row.kind === 'browser-local' || row.kind === 'unchecked') {
      audit.skipped.push({ id, reason: `${row.kind}: ${row.reason}` })
      continue
    }
    // Once the account Space is gone only the rows about what outlives it
    // can still be asked.
    if (!account.stored && id !== 'no-keystore-outlives-its-account') {
      audit.skipped.push({ id, reason: 'The account Space is not stored.' })
      continue
    }
    const outcomes: InvariantCheckOutcome[] = []
    if (row.kind === 'stored') {
      const check = STORED_CHECKS[id]
      outcomes.push(
        check === undefined
          ? undetermined('No stored check is built for this row.')
          : await settle({ check, account, now })
      )
    }
    if (row.kind === 'key-holder' || row.keyHolderHalf !== undefined) {
      // Without a key holder a `stored` row stands on its stored half alone.
      // A key holder that offers no check for the half leaves the row
      // unsettled, so a port missing a half cannot pass as a full check.
      const check = keyHolder?.checks[id]
      if (check !== undefined) {
        outcomes.push(await settle({ check, account, now }))
      } else if (keyHolder !== undefined) {
        outcomes.push(
          undetermined(
            `The key holder "${keyHolder.name}" has no check for this row.`
          )
        )
      } else if (row.kind === 'key-holder') {
        outcomes.push(undetermined(`No key holder was given: ${row.reason}`))
      }
    }
    const evidence = outcomes.flatMap(outcome =>
      outcome.outcome === 'violated' ? [outcome.evidence] : []
    )
    const reasons = outcomes.flatMap(outcome =>
      outcome.outcome === 'undetermined' ? [outcome.reason] : []
    )
    if (evidence.length > 0) {
      audit.violated.push({
        id,
        evidence: evidence.length === 1 ? evidence[0] : evidence
      })
    } else if (reasons.length > 0) {
      audit.skipped.push({ id, reason: reasons.join(' ') })
    } else {
      audit.held.push(id)
    }
  }
  return audit
}

/**
 * Serializes evidence for a failure message, with sets as arrays.
 *
 * @param value {unknown}
 * @returns {string}
 */
function describeEvidence(value: unknown): string {
  return JSON.stringify(value, (_key, member: unknown) =>
    member instanceof Set ? [...member] : member
  )
}

/**
 * Asserts an audit's violated set is exactly the allowlist: every violated
 * invariant is allowed, and every allowed one is violated. A mender that
 * fixes its own invariant while breaking another fails it, and so does an
 * expected violation that is absent (an allowed row the audit skipped
 * included). Throws a plain `Error`, so it works under either test runner.
 * The message lists each violated id with its evidence and each skipped id
 * with its reason.
 *
 * @param options {object}
 * @param options.audit {InvariantAudit}
 * @param [options.allow] {InvariantId[]}   the ids the scenario expects to
 *   stand violated
 * @returns {void}
 */
export function expectInvariantsHold({
  audit,
  allow = []
}: {
  audit: InvariantAudit
  allow?: InvariantId[]
}): void {
  const violatedIds = new Set(audit.violated.map(entry => entry.id))
  const allowed = new Set(allow)
  const unexpected = [...violatedIds].filter(id => !allowed.has(id))
  const absent = [...allowed].filter(id => !violatedIds.has(id))
  if (unexpected.length === 0 && absent.length === 0) {
    return
  }
  const lines = [
    `The invariant audit of Space ${audit.spaceId} does not match its allowlist.`,
    ...(unexpected.length > 0
      ? [`Violated and not allowed: ${unexpected.join(', ')}`]
      : []),
    ...(absent.length > 0
      ? [`Allowed but not violated: ${absent.join(', ')}`]
      : []),
    'Violated:',
    ...audit.violated.map(
      entry => `  - ${entry.id}: ${describeEvidence(entry.evidence)}`
    ),
    'Skipped:',
    ...audit.skipped.map(entry => `  - ${entry.id}: ${entry.reason}`)
  ]
  throw new Error(lines.join('\n'))
}
