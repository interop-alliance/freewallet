// @vitest-environment node
/**
 * Unit tests for the transient login (`src/session/transientLogin.ts`): the
 * post-KDF login routing (`routeUnlockLogin`) and the public-terminal
 * composition (`transientSessionFromKeyringHit`). The wallet-core annex
 * and roster boundaries are mocked at the module seam so the composition's
 * wiring -- what enrolls with which key, what reads under which capability,
 * what refuses with which typed reason before anything is written -- runs
 * deterministically; the per-visit key mint (`agentsFromSeed`) runs for real.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'
import { WasError } from '@interop/was-client'

const state = vi.hoisted(() => ({
  wasUrl: 'https://was.example.test' as string | undefined
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return state.wasUrl
  }
}))

vi.mock('@/lib/sessionKey', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/sessionKey')>()),
  hasClientKeyRecord: vi.fn()
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  verifyAccountLog: vi.fn(),
  delegatedWebvhLogStore: vi.fn(),
  webvhZcapClient: vi.fn()
}))

vi.mock('@interop/wallet-core/clientAnnex', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@interop/wallet-core/clientAnnex')
  >()),
  enrollTransientClient: vi.fn(),
  ensureCredentialClientAnnexGeneration: vi.fn(),
  embeddedGenerationDelegation: vi.fn(),
  delegatedClientsPointer: vi.fn(),
  delegatedClientsDelegationSpaceId: vi.fn()
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  userKeyRosterDescriptorStore: vi.fn(),
  readUserKeyRoster: vi.fn(),
  userKeyRosterLogSigner: vi.fn(() => ({ isRosterSigner: true })),
  ensureUserKeyRoster: vi.fn(),
  ensureWalletSpaceEpochs: vi.fn(async () => ({ outcomes: {}, failed: [] }))
}))

vi.mock('@/session/initSession', () => ({
  initSessionFromSeed: vi.fn()
}))

vi.mock('@/session/credentialAnchoredGenesis', () => ({
  mendCredentialAnchoredAccount: vi.fn(async () => ({ reenter: false })),
  passphraseRegistryUpsertHook: vi.fn(() => vi.fn())
}))

vi.mock('@/session/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/keyring')>()),
  fetchTransientKeyring: vi.fn()
}))

import {
  delegatedWebvhLogStore,
  verifyAccountLog,
  webvhZcapClient
} from '@interop/wallet-core/webvh'
import {
  delegatedClientsDelegationSpaceId,
  delegatedClientsPointer,
  embeddedGenerationDelegation,
  enrollTransientClient,
  ensureCredentialClientAnnexGeneration
} from '@interop/wallet-core/clientAnnex'
import {
  readUserKeyRoster,
  userKeyRosterDescriptorStore
} from '@interop/wallet-core/keys'
import { hasClientKeyRecord } from '@/lib/sessionKey'
import {
  mendCredentialAnchoredAccount,
  passphraseRegistryUpsertHook
} from '@/session/credentialAnchoredGenesis'
import { fetchTransientKeyring } from '@/session/keyring'
import { initSessionFromSeed } from '@/session/initSession'
import type { TransientKeyringFetchResult } from '@/session/keyring'
import { transientSessionStores } from '@/session/persistence'
import {
  AlreadyRememberedError,
  routeUnlockLogin,
  TransientLoginUnavailableError,
  type TransientLoginUnavailableReason,
  transientSessionFromKeyringHit
} from '@/session/transientLogin'

// Type-level guarantee that the plain-record state is not a typed refusal:
// this line fails to compile if 'no-standing' rejoins the reason union.
const noStandingIsNotAReason: 'no-standing' extends TransientLoginUnavailableReason
  ? never
  : true = true
void noStandingIsNotAReason

const KDF = { algorithm: 'PBKDF2', iterations: 1, version: 1 } as never
const CREDENTIAL = {
  unlock: { spaceId: 'unlock-space-1' },
  standing: {}
} as never

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}
const CLIENT_ANNEX_DID =
  'did:webvh:QmClientAnnexScid:was.example.test:space:clientAnnex-space-1:gen-Ux3v0kQf9aPmB2hZ'
const GENERATION_DELEGATION = { id: 'urn:zcap:generation' }
const SIBLING_DELEGATION = { id: 'urn:zcap:sibling' }

const RECORD_BRIDGE = { id: 'urn:zcap:bridge' }

const FRESH_SIBLING = { id: 'urn:zcap:sibling-fresh' }
const FRESH_BRIDGE = { id: 'urn:zcap:bridge-fresh' }
const FRESH_DELEGATION = { id: 'urn:zcap:generation-fresh' }

/**
 * A no-op ensure outcome (the healthy account's pure report), with the
 * mended members overridable per test.
 */
function ensureOutcome(
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  return {
    clientAnnexDid: CLIENT_ANNEX_DID,
    generationDelegation: GENERATION_DELEGATION,
    delegatedClients: SIBLING_DELEGATION,
    delegation: RECORD_BRIDGE,
    generationMinted: false,
    spaceMinted: false,
    delegationRenewed: false,
    siblingReminted: false,
    bridgeReminted: false,
    ...overrides
  }
}

/**
 * Wallet-core's typed refusal, matched by name the way the composition
 * matches it.
 *
 * @param reason {string}
 * @returns {Error}
 */
function unavailable(reason: string): Error {
  const err = new Error(`unavailable (${reason})`)
  err.name = 'ClientAnnexGenerationUnavailableError'
  ;(err as Error & { reason: string }).reason = reason
  return err
}

/**
 * A transient keyring hit in the standing layout, overridable per test.
 */
function makeFound(
  overrides: Partial<TransientKeyringFetchResult> = {}
): TransientKeyringFetchResult {
  return {
    controller: 'did:key:z6MkController',
    pointer: POINTER,
    email: 'record@example.test',
    createdAt: new Date().toISOString(),
    unlockSpaceId: 'unlock-space-1',
    standing: {
      delegation: RECORD_BRIDGE,
      delegatedClients: SIBLING_DELEGATION,
      ladderSeed: new Uint8Array(32).fill(7)
    },
    standingClient: {
      clientDid: 'did:key:z6MkStandingClient',
      agents: {
        zcapClient: { isCredentialZcapClient: true },
        keyAgreementKey: { id: 'did:key:z6MkStandingClient#z6LSkak' }
      }
    },
    rebindStandingRecord: vi.fn(async () => undefined),
    ...overrides
  } as unknown as TransientKeyringFetchResult
}

/**
 * Installs the happy-path mocks: a verified account log whose document
 * points at an annex generation, an enrollment handing back the
 * generation document, an embedded delegation, and a roster read that
 * unwraps the user key.
 */
function primeHappyPath() {
  vi.mocked(verifyAccountLog).mockResolvedValue({
    doc: { id: POINTER.did },
    log: [{ entry: 1 }],
    updateKeys: [],
    nextKeyHashes: []
  } as never)
  vi.mocked(ensureCredentialClientAnnexGeneration).mockResolvedValue(
    ensureOutcome() as never
  )
  vi.mocked(delegatedClientsPointer).mockReturnValue(CLIENT_ANNEX_DID)
  vi.mocked(delegatedClientsDelegationSpaceId).mockReturnValue(
    'clientAnnex-space-1'
  )
  vi.mocked(delegatedWebvhLogStore).mockReturnValue({
    getIdResourceRaw: vi.fn(async () => ({ text: 'log', etag: '"1"' })),
    putIdResource: vi.fn(async () => undefined)
  } as never)
  vi.mocked(enrollTransientClient).mockResolvedValue({
    clientAnnexDid: CLIENT_ANNEX_DID,
    doc: { id: CLIENT_ANNEX_DID },
    log: [{ entry: 1 }]
  } as never)
  vi.mocked(embeddedGenerationDelegation).mockReturnValue(
    GENERATION_DELEGATION as never
  )
  vi.mocked(webvhZcapClient).mockReturnValue({
    isClientAnnexZcapClient: true
  } as never)
  vi.mocked(userKeyRosterDescriptorStore).mockReturnValue({
    isRosterStore: true
  } as never)
  vi.mocked(readUserKeyRoster).mockResolvedValue({
    descriptor: { epochs: [{ id: 'did:key:z6LSepoch1' }] },
    userKey: { id: 'did:key:z6LSepoch1', secret: new Uint8Array(32) },
    rotated: true,
    latestEpochId: 'did:key:z6LSepoch1'
  } as never)
  vi.mocked(initSessionFromSeed).mockResolvedValue({
    session: { profile: {} },
    userExists: true
  } as never)
}

beforeEach(() => {
  state.wasUrl = 'https://was.example.test'
  vi.mocked(hasClientKeyRecord).mockResolvedValue(false)
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('routeUnlockLogin -- the post-KDF login-route decision', () => {
  it('defaults to transient on a non-remembered browser', async () => {
    const routed = await routeUnlockLogin({ kdf: KDF, credential: CREDENTIAL })
    expect(routed.login).toBe('transient')
    if (routed.login === 'transient') {
      expect(routed.credential).toBe(CREDENTIAL)
      expect(routed.persistence.storage).toBe('in-memory')
    }
    expect(hasClientKeyRecord).toHaveBeenCalledWith({
      spaceId: 'unlock-space-1',
      idb: undefined
    })
  })

  it('routes remembered when this credential is remembered here (the ratchet)', async () => {
    vi.mocked(hasClientKeyRecord).mockResolvedValue(true)
    const routed = await routeUnlockLogin({ kdf: KDF, credential: CREDENTIAL })
    expect(routed.login).toBe('remembered')
  })

  it('refuses rememberBrowser: false on a remembered browser', async () => {
    vi.mocked(hasClientKeyRecord).mockResolvedValue(true)
    await expect(
      routeUnlockLogin({
        kdf: KDF,
        credential: CREDENTIAL,
        rememberBrowser: false
      })
    ).rejects.toBeInstanceOf(AlreadyRememberedError)
  })

  it('routes remembered on rememberBrowser: true without probing', async () => {
    const routed = await routeUnlockLogin({
      kdf: KDF,
      credential: CREDENTIAL,
      rememberBrowser: true
    })
    expect(routed.login).toBe('remembered')
    expect(hasClientKeyRecord).not.toHaveBeenCalled()
  })

  it('routes remembered with no WAS server, refusing an explicit transient ask', async () => {
    state.wasUrl = undefined
    const routed = await routeUnlockLogin({ kdf: KDF, credential: CREDENTIAL })
    expect(routed.login).toBe('remembered')
    expect(hasClientKeyRecord).not.toHaveBeenCalled()
    await expect(
      routeUnlockLogin({
        kdf: KDF,
        credential: CREDENTIAL,
        rememberBrowser: false
      })
    ).rejects.toMatchObject({
      name: 'TransientLoginUnavailableError',
      reason: 'no-was-server'
    })
  })

  // The CHAPI popup (FW-203) runs this same table with the Storage Access
  // handle as `idb`, so the two engine cases fall out of the record probe
  // rather than out of a popup arm: a granted handle probes the first-party
  // record, a denied one probes the partitioned bucket and finds none.
  it('routes a popup remembered when the unpartitioned handle finds the record', async () => {
    const unpartitioned = {} as IDBFactory
    vi.mocked(hasClientKeyRecord).mockResolvedValue(true)
    const routed = await routeUnlockLogin({
      kdf: KDF,
      credential: CREDENTIAL,
      idb: unpartitioned
    })
    expect(routed.login).toBe('remembered')
    expect(hasClientKeyRecord).toHaveBeenCalledWith({
      spaceId: 'unlock-space-1',
      idb: unpartitioned
    })
  })

  it('routes a popup transient when Storage Access is denied (decisions/0009)', async () => {
    // A denied grant resolves no handle, so the probe runs against the
    // partitioned bucket, where no client-key record can exist.
    const routed = await routeUnlockLogin({ kdf: KDF, credential: CREDENTIAL })
    expect(routed.login).toBe('transient')
    expect(hasClientKeyRecord).toHaveBeenCalledWith({
      spaceId: 'unlock-space-1',
      idb: undefined
    })
  })
})

describe('transientSessionFromKeyringHit -- typed refusals', () => {
  /**
   * Runs the composition against the current mocks and returns the caught
   * refusal.
   */
  async function refusalFor(
    found: TransientKeyringFetchResult,
    extra: { credential?: unknown } = {}
  ) {
    try {
      await transientSessionFromKeyringHit({
        found,
        type: 'passphrase',
        persistence: transientSessionStores(),
        ...(extra.credential !== undefined
          ? { credential: extra.credential as never }
          : {})
      })
    } catch (err) {
      return err
    }
    throw new Error('expected a refusal')
  }

  it('treats a record without standing authority as an invariant bug', async () => {
    // A standing record is the only record a WAS signup produces, so a
    // plain pointer record here is a producer bug, not a typed refusal:
    // a plain Error, deliberately outside the reason union.
    const err = await refusalFor(makeFound({ standing: undefined }))
    expect(err).not.toBeInstanceOf(TransientLoginUnavailableError)
    expect((err as Error).name).toBe('Error')
    expect((err as Error).message).toMatch(/Invariant violated/)
    expect((err as Error).message).toMatch(/no standing authority/)
  })

  it('refuses a record without the sibling when the ladder cannot mend', async () => {
    // The one state the mend cannot reach: the account document anchors no
    // ladder VM of this credential's (an account with enrolled
    // clients), so nothing ladder-signed verifies and the record's own
    // sibling was all the visit could use.
    primeHappyPath()
    const refusal = unavailable('ladder-vm-not-anchored')
    vi.mocked(ensureCredentialClientAnnexGeneration).mockRejectedValue(refusal)
    const found = makeFound()
    delete (found.standing as { delegatedClients?: unknown }).delegatedClients
    const err = await refusalFor(found)
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-delegated-clients'
    )
    expect((err as Error).cause).toBe(refusal)
  })

  it('proceeds on the record sibling when the ladder is not anchored', async () => {
    // The same refusal on an account that is nonetheless reachable: the
    // pointed generation is live and its delegation embedded, which is
    // exactly today's path.
    primeHappyPath()
    vi.mocked(ensureCredentialClientAnnexGeneration).mockRejectedValue(
      unavailable('ladder-vm-not-anchored')
    )
    const { session } = await transientSessionFromKeyringHit({
      found: makeFound(),
      type: 'passphrase',
      persistence: transientSessionStores()
    })
    expect(session).toBeTruthy()
    expect(enrollTransientClient).toHaveBeenCalled()
  })

  it('rethrows a mend failure that is not the typed refusal', async () => {
    primeHappyPath()
    const boom = new Error('the annex Space PUT failed')
    vi.mocked(ensureCredentialClientAnnexGeneration).mockRejectedValue(boom)
    expect(await refusalFor(makeFound())).toBe(boom)
  })

  it('refuses an unpromoted account pointer', async () => {
    const err = await refusalFor(
      makeFound({ pointer: { ...POINTER, did: 'did:key:z6MkNotWebvh' } })
    )
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'unpromoted-account'
    )
  })

  it('refuses when the account document carries no annex pointer', async () => {
    primeHappyPath()
    vi.mocked(ensureCredentialClientAnnexGeneration).mockRejectedValue(
      unavailable('update-key-not-attributable')
    )
    vi.mocked(delegatedClientsPointer).mockReturnValue(undefined)
    const err = await refusalFor(makeFound())
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-clientAnnex-generation'
    )
    expect(enrollTransientClient).not.toHaveBeenCalled()
  })

  it('refuses a collected generation from the store wrapper, pre-write', async () => {
    primeHappyPath()
    vi.mocked(ensureCredentialClientAnnexGeneration).mockRejectedValue(
      unavailable('ladder-vm-not-anchored')
    )
    vi.mocked(delegatedWebvhLogStore).mockReturnValue({
      getIdResourceRaw: vi.fn(async () => undefined),
      putIdResource: vi.fn(async () => undefined)
    } as never)
    // Drive the wrapper the way the enrollment's first read would.
    vi.mocked(enrollTransientClient).mockImplementation(
      async ({ storeForGenerationId }) => {
        await storeForGenerationId('gen-Ux3v0kQf9aPmB2hZ').getIdResourceRaw({
          resourceId: 'did.jsonl'
        })
        throw new Error('unreachable')
      }
    )
    const err = await refusalFor(makeFound())
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-clientAnnex-generation'
    )
  })

  it('refuses instead of minting a generation delegation', async () => {
    primeHappyPath()
    vi.mocked(ensureCredentialClientAnnexGeneration).mockRejectedValue(
      unavailable('ladder-vm-not-anchored')
    )
    vi.mocked(enrollTransientClient).mockImplementation(
      async ({ mintGenerationDelegation }) => {
        await mintGenerationDelegation!({ clientAnnexDid: CLIENT_ANNEX_DID })
        throw new Error('unreachable')
      }
    )
    const err = await refusalFor(makeFound())
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-generation-delegation'
    )
  })

  it('refuses a generation document with no embedded delegation', async () => {
    primeHappyPath()
    vi.mocked(ensureCredentialClientAnnexGeneration).mockRejectedValue(
      unavailable('ladder-vm-not-anchored')
    )
    vi.mocked(embeddedGenerationDelegation).mockReturnValue(undefined)
    const err = await refusalFor(makeFound())
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-generation-delegation'
    )
    expect(readUserKeyRoster).not.toHaveBeenCalled()
  })

  it('refuses when even the tear heal leaves no user key roster', async () => {
    primeHappyPath()
    vi.mocked(readUserKeyRoster).mockResolvedValue(null as never)
    vi.mocked(mendCredentialAnchoredAccount).mockResolvedValue({
      reenter: false,
      rosterEpochs: { converged: true, outcome: 'delivered' }
    } as never)
    const err = await refusalFor(makeFound(), { credential: CREDENTIAL })
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-user-key-roster'
    )
    // The mend ran before the refusal: it is the promoted-account-with-no-
    // roster arm, and only its own empty re-read refuses.
    expect(mendCredentialAnchoredAccount).toHaveBeenCalled()
    expect(initSessionFromSeed).not.toHaveBeenCalled()
  })

  it('refuses with no credential in hand when the roster is absent', async () => {
    primeHappyPath()
    vi.mocked(readUserKeyRoster).mockResolvedValue(null as never)
    const err = await refusalFor(makeFound())
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-user-key-roster'
    )
    // No mend without the credential: the arm cannot re-bind or hook.
    expect(mendCredentialAnchoredAccount).not.toHaveBeenCalled()
  })

  it("maps the mend's no-wrap outcome onto its own refusal", async () => {
    primeHappyPath()
    const noWrap = new Error('no wrap for this credential')
    vi.mocked(readUserKeyRoster).mockResolvedValue(null as never)
    vi.mocked(mendCredentialAnchoredAccount).mockResolvedValue({
      reenter: false,
      rosterEpochs: { converged: false, outcome: 'no-wrap', error: noWrap }
    } as never)
    const err = await refusalFor(makeFound(), { credential: CREDENTIAL })
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-user-key-wrap'
    )
    expect((err as Error).cause).toBe(noWrap)
  })

  it('refuses no-user-key-wrap when the roster read itself throws the unwrap', async () => {
    // The read returns null only for an ABSENT roster; a roster with no wrap
    // for this credential throws. The refusal is the composition's own, so
    // the raw error never reaches the login page's enrollment card, and no
    // mend arm is asked to fix a state it cannot fix.
    primeHappyPath()
    const unwrap = Object.assign(new Error('no wrap for this recipient'), {
      name: 'UserKeyRosterUnwrapError'
    })
    vi.mocked(readUserKeyRoster).mockRejectedValue(unwrap as never)
    const err = await refusalFor(makeFound(), { credential: CREDENTIAL })
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'no-user-key-wrap'
    )
    expect((err as Error).cause).toBe(unwrap)
    expect(mendCredentialAnchoredAccount).not.toHaveBeenCalled()
  })

  it("maps the mend's mint-refused outcome onto its own refusal", async () => {
    // The mint preconditions refused (a held roster-epoch pin, or foreign
    // key-agreement entries): a retry re-runs the same refusal, so it is not
    // folded into the retryable absent-roster copy.
    primeHappyPath()
    const refused = new Error('the mint preconditions refused')
    vi.mocked(readUserKeyRoster).mockResolvedValue(null as never)
    vi.mocked(mendCredentialAnchoredAccount).mockResolvedValue({
      reenter: false,
      rosterEpochs: {
        converged: false,
        outcome: 'mint-refused',
        error: refused
      }
    } as never)
    const err = await refusalFor(makeFound(), { credential: CREDENTIAL })
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'roster-mint-refused'
    )
    expect((err as Error).cause).toBe(refused)
  })

  it('rethrows a network failure unchanged (flap, not lapse)', async () => {
    primeHappyPath()
    const offline = new TypeError('Failed to fetch')
    vi.mocked(verifyAccountLog).mockRejectedValue(offline)
    const err = await refusalFor(makeFound())
    expect(err).toBe(offline)
  })
})

describe('transientSessionFromKeyringHit -- the composition wiring', () => {
  it('enrolls, reads the standing wrap under the delegation, and assembles', async () => {
    primeHappyPath()
    const persistence = transientSessionStores()
    const found = makeFound()

    const { session, userExists } = await transientSessionFromKeyringHit({
      found,
      type: 'passphrase',
      email: 'typed@example.test',
      persistence
    })

    // The enrollment: the credential's ladder seed, a real per-visit key
    // multibase, the visit's in-memory pins, and the sibling-delegated store.
    const enrollCall = vi.mocked(enrollTransientClient).mock.calls[0]![0]
    expect(enrollCall.ladderSeed).toBe(found.standing!.ladderSeed)
    expect(enrollCall.transientKeyMultibase).toMatch(/^z6Mk/)
    expect(enrollCall.pinStore).toBe(persistence.logPins)
    enrollCall.storeForGenerationId('gen-Ux3v0kQf9aPmB2hZ')
    expect(delegatedWebvhLogStore).toHaveBeenCalledWith({
      host: POINTER.host,
      spaceId: 'clientAnnex-space-1',
      collectionId: 'gen-Ux3v0kQf9aPmB2hZ',
      delegation: SIBLING_DELEGATION,
      zcapClient: found.standingClient.agents.zcapClient
    })

    // The account log was verified under the same in-memory pins.
    expect(verifyAccountLog).toHaveBeenCalledWith({
      did: POINTER.did,
      spaceId: POINTER.spaceId,
      host: POINTER.host,
      pinStore: persistence.logPins
    })

    // The roster read: annex spelling under the generation delegation,
    // unwrapped with the credential's own key-agreement key. No escrow: the
    // roster store is read-only here.
    expect(webvhZcapClient).toHaveBeenCalledWith({
      keyAgent: expect.anything(),
      did: CLIENT_ANNEX_DID
    })
    expect(userKeyRosterDescriptorStore).toHaveBeenCalledWith(
      expect.objectContaining({
        storageServerUrl: POINTER.host,
        spaceId: POINTER.spaceId,
        pinStore: persistence.logPins,
        capability: GENERATION_DELEGATION
      })
    )
    expect(readUserKeyRoster).toHaveBeenCalledWith({
      store: expect.objectContaining({ isRosterStore: true }),
      clientKeyAgreementKey: found.standingClient.agents.keyAgreementKey
    })

    // The session assembly: the transient strategy composed over the
    // routed stores carries the annex identity (the storage tier declared
    // once), the record's email defers to the typed one, and the stamps
    // the remembered tail applies follow.
    expect(initSessionFromSeed).toHaveBeenCalledWith(
      expect.objectContaining({
        accountPointer: POINTER,
        email: 'typed@example.test',
        persistence: expect.objectContaining({
          storage: persistence.storage,
          logPins: persistence.logPins,
          clientAnnex: {
            clientAnnexDid: CLIENT_ANNEX_DID,
            invocationCapability: GENERATION_DELEGATION
          }
        })
      })
    )
    // The composed handle preserves the routed stores (same writer id, same
    // pin maps under the copied methods).
    const passedPersistence =
      vi.mocked(initSessionFromSeed).mock.calls[0]![0].persistence!
    expect(passedPersistence.getWriterId()).toBe(persistence.getWriterId())
    expect(session.profile.accountController).toBe(found.controller)
    expect(session.profile.unlockMethod).toEqual({
      type: 'passphrase',
      unlockSpaceId: 'unlock-space-1'
    })
    // The standing members ride the profile: what the grant path's
    // ladder-signed renewal stage signs and invokes with.
    expect(session.profile.ladderSeed).toBe(found.standing!.ladderSeed)
    expect(session.profile.standingUnlock).toEqual({
      delegation: found.standing!.delegation,
      delegatedClients: SIBLING_DELEGATION,
      standingClient: found.standingClient,
      unlockSpaceId: 'unlock-space-1',
      rebindRecord: found.rebindStandingRecord
    })
    expect(userExists).toBe(true)

    // The visit's epoch pin advanced in memory only.
    await expect(
      persistence.epochPins.load({ accountDid: POINTER.did })
    ).resolves.toBe('did:key:z6LSepoch1')
  })

  it('falls back to the record email when none is typed', async () => {
    primeHappyPath()
    await transientSessionFromKeyringHit({
      found: makeFound(),
      type: 'passkey',
      persistence: transientSessionStores()
    })
    expect(initSessionFromSeed).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'record@example.test' })
    )
  })
})

describe('transientSessionFromKeyringHit -- the client-annex generation-readiness stage', () => {
  /**
   * Runs the composition against the current mocks and returns the ensure's
   * one call arguments beside the session.
   */
  async function runComposition(found = makeFound()) {
    const persistence = transientSessionStores()
    const { session } = await transientSessionFromKeyringHit({
      found,
      type: 'passphrase',
      persistence
    })
    return {
      session,
      persistence,
      found,
      ensureCall: vi.mocked(ensureCredentialClientAnnexGeneration).mock
        .calls[0]![0]
    }
  }

  it('runs the ensure on every visit, with the credential members', async () => {
    primeHappyPath()
    const { ensureCall, persistence, found } = await runComposition()
    expect(ensureCall.wasServerUrl).toBe(POINTER.host)
    expect(ensureCall.spaceId).toBe(POINTER.spaceId)
    expect(ensureCall.ladderSeed).toBe(found.standing!.ladderSeed)
    expect(ensureCall.delegatedClients).toBe(SIBLING_DELEGATION)
    expect(ensureCall.pinStore).toBe(persistence.logPins)
    expect(ensureCall.standingClient).toEqual({
      did: found.standingClient.clientDid,
      zcapClient: found.standingClient.agents.zcapClient
    })
    const verifiedView =
      await vi.mocked(verifyAccountLog).mock.results[0]!.value
    expect(ensureCall.account).toEqual({
      did: POINTER.did,
      doc: verifiedView.doc,
      log: verifiedView.log
    })
    // A healthy account is a pure no-op report: nothing is re-verified.
    expect(vi.mocked(verifyAccountLog).mock.calls).toHaveLength(1)
  })

  it('re-seals a freshly minted sibling through the record re-bind', async () => {
    primeHappyPath()
    const found = makeFound()
    delete (found.standing as { delegatedClients?: unknown }).delegatedClients
    vi.mocked(ensureCredentialClientAnnexGeneration).mockImplementation(
      async ({ onRebindRecord }) => {
        await onRebindRecord({
          delegation: RECORD_BRIDGE as never,
          delegatedClients: FRESH_SIBLING as never
        })
        return ensureOutcome({
          delegatedClients: FRESH_SIBLING,
          siblingReminted: true
        }) as never
      }
    )
    const { ensureCall } = await runComposition(found)
    expect(ensureCall.delegatedClients).toBeUndefined()
    expect(found.rebindStandingRecord).toHaveBeenCalledWith({
      delegation: found.standing!.delegation,
      delegatedClients: FRESH_SIBLING
    })
    // The enrollment rides the sibling the mend handed back, not the
    // record's (absent) one.
    vi.mocked(enrollTransientClient).mock.calls[0]![0].storeForGenerationId(
      'gen-Ux3v0kQf9aPmB2hZ'
    )
    expect(delegatedWebvhLogStore).toHaveBeenCalledWith(
      expect.objectContaining({ delegation: FRESH_SIBLING })
    )
  })

  it('re-verifies the account log when the mend moved the pointer', async () => {
    primeHappyPath()
    const minted =
      'did:webvh:QmClientAnnexScid:was.example.test:space:clientAnnex-space-2:gen-Fr3sh0kQf9aPmB2h'
    vi.mocked(ensureCredentialClientAnnexGeneration).mockResolvedValue(
      ensureOutcome({
        clientAnnexDid: minted,
        generationMinted: true,
        spaceMinted: true,
        generationDelegation: FRESH_DELEGATION
      }) as never
    )
    await runComposition()
    expect(vi.mocked(verifyAccountLog).mock.calls).toHaveLength(2)
    // The enrollment addresses the freshly minted generation's Space.
    const enrollCall = vi.mocked(enrollTransientClient).mock.calls[0]![0]
    enrollCall.storeForGenerationId('gen-Fr3sh0kQf9aPmB2h')
    expect(delegatedWebvhLogStore).toHaveBeenCalledWith(
      expect.objectContaining({ spaceId: 'clientAnnex-space-2' })
    )
  })

  it('adopts a re-minted generation in an existing Space', async () => {
    primeHappyPath()
    vi.mocked(ensureCredentialClientAnnexGeneration).mockResolvedValue(
      ensureOutcome({ generationMinted: true }) as never
    )
    await runComposition()
    expect(vi.mocked(verifyAccountLog).mock.calls).toHaveLength(2)
    expect(enrollTransientClient).toHaveBeenCalled()
  })

  it('carries a renewed generation delegation into the session', async () => {
    primeHappyPath()
    vi.mocked(ensureCredentialClientAnnexGeneration).mockResolvedValue(
      ensureOutcome({
        delegationRenewed: true,
        generationDelegation: FRESH_DELEGATION
      }) as never
    )
    // The annex document the enrollment hands back carries the renewed
    // delegation; the outcome's is the fallback when it does not.
    vi.mocked(embeddedGenerationDelegation).mockReturnValue(undefined)
    await runComposition()
    expect(initSessionFromSeed).toHaveBeenCalledWith(
      expect.objectContaining({
        persistence: expect.objectContaining({
          clientAnnex: {
            clientAnnexDid: CLIENT_ANNEX_DID,
            invocationCapability: FRESH_DELEGATION
          }
        })
      })
    )
  })

  it("rides the readiness stage's verified generation head, once", async () => {
    // The healthy no-op reports the head it stood on: the enrollment's first
    // attempt builds on it instead of resolving the same log a second time.
    primeHappyPath()
    const generationLog = { did: CLIENT_ANNEX_DID, log: [{ entry: 1 }] }
    vi.mocked(ensureCredentialClientAnnexGeneration).mockResolvedValue(
      ensureOutcome({ generationLog }) as never
    )
    await runComposition()
    const enrollCall = vi.mocked(enrollTransientClient).mock.calls[0]![0]
    expect(enrollCall.published).toBe(generationLog)
  })

  it('threads no head when the readiness stage published one', async () => {
    // A mint or a renewal leaves no compare-and-swap-capable post-publish
    // head, so the outcome carries none and the enrollment reads for itself.
    primeHappyPath()
    vi.mocked(ensureCredentialClientAnnexGeneration).mockResolvedValue(
      ensureOutcome({ generationMinted: true }) as never
    )
    await runComposition()
    const enrollCall = vi.mocked(enrollTransientClient).mock.calls[0]![0]
    expect(enrollCall.published).toBeUndefined()
  })

  it('threads no head on the record-sibling fallback arm', async () => {
    primeHappyPath()
    vi.mocked(ensureCredentialClientAnnexGeneration).mockRejectedValue(
      unavailable('ladder-vm-not-anchored')
    )
    await runComposition()
    const enrollCall = vi.mocked(enrollTransientClient).mock.calls[0]![0]
    expect(enrollCall.published).toBeUndefined()
  })

  it('hands the ensure the record bridge and a log-store factory', async () => {
    primeHappyPath()
    const { ensureCall, found } = await runComposition()
    expect(ensureCall.delegation).toBe(found.standing!.delegation)
    expect(typeof ensureCall.idStoreFor).toBe('function')
    // The factory builds the account-log store over whichever bridge it is
    // handed, not over the one the record happened to carry.
    const store = ensureCall.idStoreFor({ delegation: FRESH_BRIDGE as never })
    expect(typeof store.getIdResourceRaw).toBe('function')
    expect(typeof store.putIdResource).toBe('function')
  })

  it('re-seals a renewed bridge and carries it into the session', async () => {
    primeHappyPath()
    const found = makeFound()
    vi.mocked(ensureCredentialClientAnnexGeneration).mockImplementation(
      async ({ onRebindRecord }) => {
        await onRebindRecord({
          delegation: FRESH_BRIDGE as never,
          delegatedClients: SIBLING_DELEGATION as never
        })
        return ensureOutcome({
          delegation: FRESH_BRIDGE,
          bridgeReminted: true
        }) as never
      }
    )
    const { session } = await runComposition(found)
    expect(found.rebindStandingRecord).toHaveBeenCalledWith({
      delegation: FRESH_BRIDGE,
      delegatedClients: SIBLING_DELEGATION
    })
    // The session stamps the bridge the outcome reports usable, so a
    // mid-session stage writes the log through the renewed one.
    expect(session.profile.standingUnlock!.delegation).toBe(FRESH_BRIDGE)
  })

  it('warns and proceeds when a bridge-only re-seal failed', async () => {
    primeHappyPath()
    const resealError = new Error('the unlock Space PUT failed')
    vi.mocked(ensureCredentialClientAnnexGeneration).mockResolvedValue(
      ensureOutcome({
        delegation: FRESH_BRIDGE,
        bridgeReminted: true,
        bridgeResealError: resealError
      }) as never
    )
    const capture = captureSink()
    const removeSink = addSink(capture.sink)

    const { session } = await runComposition()

    // The visit needs nothing from the re-seal, so the login still assembles
    // and stamps the fresh bridge the ensure reports usable.
    expect(session.profile.standingUnlock!.delegation).toBe(FRESH_BRIDGE)
    expect(capture.events).toContainEqual(
      expect.objectContaining({
        ns: 'fw:session:transient',
        level: 'warn',
        msg: expect.stringContaining('re-seal the renewed bridge delegation')
      })
    )
    removeSink()
  })
})

describe('transientSessionFromKeyringHit -- the shared mend ceremony', () => {
  it('mends a promoted account with no roster through the roster arm, under the delegated authority', async () => {
    primeHappyPath()
    const persistence = transientSessionStores()
    const found = makeFound()
    // The first read finds nothing (the signup died before epoch[0]); the
    // re-read after the mend delivers the fresh key.
    vi.mocked(readUserKeyRoster)
      .mockResolvedValueOnce(null as never)
      .mockResolvedValue({
        descriptor: { epochs: [{ id: 'did:key:z6LSfresh' }] },
        userKey: { id: 'did:key:z6LSfresh', secret: new Uint8Array(32) },
        rotated: false,
        latestEpochId: 'did:key:z6LSfresh'
      } as never)
    vi.mocked(mendCredentialAnchoredAccount).mockResolvedValue({
      reenter: false,
      rosterEpochs: { converged: true, outcome: 'delivered' }
    } as never)
    const registryHook = vi.fn()
    vi.mocked(passphraseRegistryUpsertHook).mockReturnValue(
      registryHook as never
    )

    const { session } = await transientSessionFromKeyringHit({
      found,
      type: 'passphrase',
      persistence,
      credential: CREDENTIAL
    })

    // The mend rode the visit's live authority: the invocation triple
    // under the generation delegation, a ladder-signed roster store (the
    // last store built carries the delegation), the record's registry
    // context, and the passphrase registry hook bound to the same
    // delegation.
    const mendCall = vi.mocked(mendCredentialAnchoredAccount).mock.calls[0]![0]
    expect(mendCall.invocation!.capability).toBe(GENERATION_DELEGATION)
    expect(mendCall.rosterStore).toBeTruthy()
    expect(mendCall.registry).toEqual(
      expect.objectContaining({
        unlockSpaceId: found.unlockSpaceId,
        delegation: found.standing!.delegation,
        delegatedClients: SIBLING_DELEGATION
      })
    )
    expect(mendCall.beforePromotion).toBe(registryHook)
    expect(passphraseRegistryUpsertHook).toHaveBeenCalledWith({
      spaceId: POINTER.spaceId,
      capability: GENERATION_DELEGATION
    })
    const healStoreCall = vi
      .mocked(userKeyRosterDescriptorStore)
      .mock.calls.at(-1)![0]
    expect(healStoreCall.capability).toBe(GENERATION_DELEGATION)
    // The composition re-read the roster after the arm delivered.
    expect(vi.mocked(readUserKeyRoster).mock.calls.length).toBeGreaterThan(1)
    expect(session).toBeTruthy()
  })

  it("completes a torn promotion through the mend's delegated-read trigger, then reads on", async () => {
    primeHappyPath()
    const persistence = transientSessionStores()
    const found = makeFound()
    const torn = new Error('delegated read refused')
    vi.mocked(readUserKeyRoster)
      .mockRejectedValueOnce(torn as never)
      .mockResolvedValue({
        descriptor: { epochs: [{ id: 'did:key:z6LSepoch1' }] },
        userKey: { id: 'did:key:z6LSepoch1', secret: new Uint8Array(32) },
        rotated: true,
        latestEpochId: 'did:key:z6LSepoch1'
      } as never)
    vi.mocked(mendCredentialAnchoredAccount).mockImplementation(
      async options => {
        // The promotion arm's contract: mend, then retry the caller's read.
        await options.delegatedRead!.retry()
        return {
          reenter: false,
          promotion: { converged: true, outcome: 'retried' }
        } as never
      }
    )

    const { session } = await transientSessionFromKeyringHit({
      found,
      type: 'passphrase',
      persistence,
      credential: CREDENTIAL
    })

    const mendCall = vi.mocked(mendCredentialAnchoredAccount).mock.calls[0]![0]
    expect(mendCall.delegatedRead!.error).toBe(torn)
    expect(session).toBeTruthy()
  })

  it('rethrows the original roster error unchanged when the promotion arm does not converge', async () => {
    primeHappyPath()
    const found = makeFound()
    const torn = new TypeError('Failed to fetch')
    vi.mocked(readUserKeyRoster).mockRejectedValue(torn as never)
    vi.mocked(mendCredentialAnchoredAccount).mockImplementation(
      async options => {
        // Wallet-core's contract: a promotion or retry that still fails
        // rethrows the caller's original error unchanged.
        throw options.delegatedRead!.error
      }
    )
    const err = await transientSessionFromKeyringHit({
      found,
      type: 'passphrase',
      persistence: transientSessionStores(),
      credential: CREDENTIAL
    }).then(
      () => {
        throw new Error('expected a rethrow')
      },
      (thrown: unknown) => thrown
    )
    expect(err).toBe(torn)
  })

  it('mends a ladder-seeded record with no did through the establishment arm, then re-enters', async () => {
    primeHappyPath()
    const persistence = transientSessionStores()
    const credential = CREDENTIAL
    const torn = makeFound({
      pointer: { spaceId: POINTER.spaceId, host: POINTER.host } as never
    })
    const refreshed = makeFound()
    vi.mocked(fetchTransientKeyring).mockResolvedValue(refreshed as never)
    vi.mocked(mendCredentialAnchoredAccount).mockResolvedValueOnce({
      reenter: true,
      establishment: { converged: true, outcome: 'established' }
    } as never)

    const { session } = await transientSessionFromKeyringHit({
      found: torn,
      type: 'passphrase',
      persistence,
      credential
    })

    expect(mendCredentialAnchoredAccount).toHaveBeenCalledWith(
      expect.objectContaining({
        credential,
        ladderSeed: torn.standing!.ladderSeed,
        pointer: torn.pointer,
        controller: torn.controller,
        lowEntropy: true,
        persistence
      })
    )
    // The re-entry rode the refreshed record.
    expect(fetchTransientKeyring).toHaveBeenCalledWith({
      credential,
      accountLogPinStore: persistence.logPins
    })
    expect(session).toBeTruthy()
  })

  it('maps a non-converged establishment arm onto the unpromoted-account refusal', async () => {
    // The mend catches an establishment throw into the report; the
    // composition maps it onto the typed refusal instead of letting a raw
    // ceremony error escape the login.
    const boom = new Error('the establishment died mid-run')
    const torn = makeFound({
      pointer: { spaceId: POINTER.spaceId, host: POINTER.host } as never
    })
    vi.mocked(mendCredentialAnchoredAccount).mockResolvedValueOnce({
      reenter: false,
      establishment: { converged: false, outcome: 'established', error: boom }
    } as never)
    const err = await transientSessionFromKeyringHit({
      found: torn,
      type: 'passphrase',
      persistence: transientSessionStores(),
      credential: CREDENTIAL
    }).then(
      () => {
        throw new Error('expected a refusal')
      },
      (thrown: unknown) => thrown
    )
    expect((err as TransientLoginUnavailableError).reason).toBe(
      'unpromoted-account'
    )
    expect((err as Error).cause).toBe(boom)
    expect(fetchTransientKeyring).not.toHaveBeenCalled()
  })

  it('rethrows a transport-class establishment failure unchanged', async () => {
    // A flap is not an account state: it must stay distinguishable from the
    // refusal whose copy says a retry finishes the setup.
    const offline = new WasError('the server could not be reached')
    const torn = makeFound({
      pointer: { spaceId: POINTER.spaceId, host: POINTER.host } as never
    })
    vi.mocked(mendCredentialAnchoredAccount).mockResolvedValueOnce({
      reenter: false,
      establishment: {
        converged: false,
        outcome: 'established',
        error: offline
      }
    } as never)
    const err = await transientSessionFromKeyringHit({
      found: torn,
      type: 'passphrase',
      persistence: transientSessionStores(),
      credential: CREDENTIAL
    }).then(
      () => {
        throw new Error('expected a rethrow')
      },
      (thrown: unknown) => thrown
    )
    expect(err).toBe(offline)
  })

  it('states that it holds no roster-epoch pin', async () => {
    const torn = makeFound({
      pointer: { spaceId: POINTER.spaceId, host: POINTER.host } as never
    })
    await transientSessionFromKeyringHit({
      found: torn,
      type: 'passphrase',
      persistence: transientSessionStores(),
      credential: CREDENTIAL
    }).catch(() => undefined)
    const mendCall = vi.mocked(mendCredentialAnchoredAccount).mock.calls[0]![0]
    expect(await mendCall.hasRosterEpochPin()).toBe(false)
  })

  it("carries reenterRepairShaped into the re-entry's completion arms", async () => {
    // The record-downgrade re-bind left the registry arm unfired (its root
    // window is closed for good), so the re-entry must fire the completion
    // arms under the visit's post-promotion authority.
    primeHappyPath()
    const torn = makeFound({
      pointer: { spaceId: POINTER.spaceId, host: POINTER.host } as never
    })
    vi.mocked(fetchTransientKeyring).mockResolvedValue(makeFound() as never)
    vi.mocked(mendCredentialAnchoredAccount)
      .mockResolvedValueOnce({
        reenter: true,
        reenterRepairShaped: true,
        establishment: { converged: true, outcome: 'rebound' }
      } as never)
      .mockResolvedValue({ reenter: false } as never)

    const { session } = await transientSessionFromKeyringHit({
      found: torn,
      type: 'passphrase',
      persistence: transientSessionStores(),
      credential: CREDENTIAL
    })

    expect(session).toBeTruthy()
    const reentryCall = vi.mocked(mendCredentialAnchoredAccount).mock
      .calls[1]![0]
    expect(reentryCall.repairShaped).toBe(true)
    expect(reentryCall.invocation!.capability).toBe(GENERATION_DELEGATION)
  })

  it('logs the collections a partial epoch fan-out left behind', async () => {
    primeHappyPath()
    vi.mocked(readUserKeyRoster)
      .mockResolvedValueOnce(null as never)
      .mockResolvedValue({
        descriptor: { epochs: [{ id: 'did:key:z6LSfresh' }] },
        userKey: { id: 'did:key:z6LSfresh', secret: new Uint8Array(32) },
        rotated: false,
        latestEpochId: 'did:key:z6LSfresh'
      } as never)
    vi.mocked(mendCredentialAnchoredAccount).mockResolvedValue({
      reenter: false,
      rosterEpochs: {
        converged: true,
        outcome: 'delivered',
        epochsFailed: [
          { collectionId: 'contacts', error: new Error('epoch PUT failed') }
        ]
      }
    } as never)
    const capture = captureSink()
    const removeSink = addSink(capture.sink)

    await transientSessionFromKeyringHit({
      found: makeFound(),
      type: 'passphrase',
      persistence: transientSessionStores(),
      credential: CREDENTIAL
    })

    expect(capture.events).toContainEqual(
      expect.objectContaining({
        ns: 'fw:session:transient',
        level: 'warn',
        msg: expect.stringContaining('collection epochs incomplete')
      })
    )
    removeSink()
  })

  it('still refuses an unpromoted account with no credential in hand', async () => {
    const torn = makeFound({
      pointer: { spaceId: POINTER.spaceId, host: POINTER.host } as never
    })
    await expect(
      transientSessionFromKeyringHit({
        found: torn,
        type: 'passphrase',
        persistence: transientSessionStores()
      })
    ).rejects.toMatchObject({ reason: 'unpromoted-account' })
    expect(mendCredentialAnchoredAccount).not.toHaveBeenCalled()
  })
})
