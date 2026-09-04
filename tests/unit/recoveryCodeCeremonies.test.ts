// @vitest-environment node
/**
 * Unit tests for the recovery-code ceremonies on both kinds of
 * account-ceremony session (`issueRecoveryCode` / `revokeRecoveryCode` in
 * `src/session/recovery.ts`).
 *
 * What is real here: the code's whole key set (HKDF from the code bytes, the
 * ladder seed and its VM), the bridge delegation and its proof, the unlock
 * record's EDV wrap. What is mocked is the WAS seam -- the account log's
 * entries, the roster appends, the registry record, the unlock Space -- so
 * the stage order, the pivot, and a re-run from each tear point can be
 * asserted against durable state the mocks hold.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'

const wasState = vi.hoisted(() => ({
  url: 'https://was.example.test' as string | undefined
}))

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  get WAS_SERVER_URL() {
    return wasState.url
  }
}))

/**
 * The account's durable state, as the mocked seams keep it: which parts of
 * the code's inventory the document publishes, which recipients the roster
 * escrows, the ordered trace of the stages, and the failure a test injects
 * to tear a run at a chosen stage.
 */
const account = vi.hoisted(() => ({
  published: new Set<string>(),
  escrowed: new Set<string>(),
  trace: [] as string[],
  failAt: null as string | null,
  ladderVmClaimable: true,
  registry: null as null | {
    version: 1
    webAuthnUserId: string
    methods: unknown[]
  },
  registryCapabilities: [] as (unknown | undefined)[],
  spaceDeletions: [] as unknown[],
  projections: 0,
  /** every did:web projection body PUT through the supplied store */
  projectionPuts: [] as unknown[]
}))

/**
 * The post-strike did:web projection wallet-core derives from the entry it is
 * about to publish: the code's key already gone.
 */
const POST_STRIKE_WEB_DOC = vi.hoisted(() => ({
  id: 'did:web:test',
  verificationMethod: []
}))

/**
 * Records one stage and throws when the test asked for a tear at it.
 *
 * @param stage {string}
 * @returns {void}
 */
const stage = vi.hoisted(() => (name: string): void => {
  if (account.failAt === name) {
    throw new Error(`torn at ${name}`)
  }
  account.trace.push(name)
})

vi.mock('@interop/wallet-core/recovery', async importOriginal => {
  const actual =
    await importOriginal<typeof import('@interop/wallet-core/recovery')>()
  return {
    ...actual,
    publishRecoveryKey: vi.fn(
      async ({
        part = 'all',
        recovery
      }: {
        part?: string
        recovery: { keyAgreementKeyMultibase: string }
      }) => {
        const parts = part === 'all' ? ['key', 'authority'] : [part]
        if (parts.every(one => account.published.has(one))) {
          account.trace.push(`entry:${part}:noop`)
          return { did: 'did:webvh:test', doc: {}, log: [] }
        }
        stage(`entry:${part}`)
        for (const one of parts) {
          account.published.add(one)
        }
        void recovery
        return { did: 'did:webvh:test', doc: {}, log: [] }
      }
    ),
    removeRecoveryKey: vi.fn(
      async ({
        projectionStore
      }: {
        projectionStore?: {
          putIdResource: (options: {
            resourceId: string
            content: string
            contentType: string
          }) => Promise<unknown>
        }
      }) => {
        // wallet-core PUTs the post-strike projection through the supplied
        // store immediately BEFORE the entry publishes; the stand-in
        // reproduces that placement.
        if (projectionStore) {
          await projectionStore.putIdResource({
            resourceId: 'did.json',
            content: JSON.stringify(POST_STRIKE_WEB_DOC),
            contentType: 'application/json'
          })
          account.trace.push('projection')
        }
        stage('strike')
        account.published.clear()
        return {
          did: 'did:webvh:test',
          doc: { verificationMethod: [] },
          log: []
        }
      }
    )
  }
})

vi.mock('@interop/wallet-core/unlock', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/unlock')>()),
  preflightUnlockCredentialRetirement: vi.fn(async () => {
    account.trace.push('preflight')
    if (!account.ladderVmClaimable) {
      const err = new Error('The ladder VM could not be claimed.')
      err.name = 'UnclaimedLadderVmRetirementError'
      throw err
    }
    return { struck: [], unclaimed: [] }
  })
}))

vi.mock('@interop/wallet-core/keyring', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keyring')>()),
  ensureUnlockSpace: vi.fn(async () => {}),
  putUnlockKeyring: vi.fn(async () => {
    stage('record')
  })
}))

vi.mock('@interop/wallet-core/keys', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/keys')>()),
  addUserKeyRosterRecipient: vi.fn(
    async ({ recipient }: { recipient: { id: string } }) => {
      if (account.escrowed.has(recipient.id)) {
        account.trace.push('escrow:noop')
        return
      }
      stage('escrow')
      account.escrowed.add(recipient.id)
    }
  ),
  rotateUserKeyRoster: vi.fn(async () => {
    stage('rotate')
    return { rotated: true }
  }),
  readUserKeyRoster: vi.fn(async () => null)
}))

vi.mock('@interop/wallet-core/webvh', async importOriginal => ({
  ...(await importOriginal<typeof import('@interop/wallet-core/webvh')>()),
  delegatedWebvhLogStore: vi.fn(() => ({
    getIdResourceRaw: vi.fn(async () => undefined),
    putIdResource: vi.fn(async ({ content }: { content: string }) => {
      account.projections += 1
      account.projectionPuts.push(JSON.parse(content))
    })
  })),
  ensureDidWebProjection: vi.fn(async () => {
    account.projections += 1
    account.trace.push('projection')
    return { outcome: 'unchanged' }
  }),
  verifyAccountLog: vi.fn(async () => ({
    did: 'did:webvh:test',
    doc: { verificationMethod: [] },
    log: [],
    updateKeys: [],
    nextKeyHashes: []
  }))
}))

vi.mock('@/session/verifiedLog', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/verifiedLog')>()),
  invalidateVerifiedLog: vi.fn(() => {}),
  verifiedAccountLog: vi.fn(async () => ({
    doc: { verificationMethod: [] },
    log: [],
    updateKeys: [],
    nextKeyHashes: []
  }))
}))

vi.mock('@/session/userKeyCascade', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/userKeyCascade')>()),
  cascadeCollectionsToUserKey: vi.fn(async () => ({ rotated: [], failed: [] }))
}))

vi.mock('@/lib/sessionKey', async importOriginal => ({
  ...(await importOriginal<typeof import('@/lib/sessionKey')>()),
  deleteUnlockLocalState: vi.fn(async () => {})
}))

vi.mock('@/session/unlockMethods', async importOriginal => ({
  ...(await importOriginal<typeof import('@/session/unlockMethods')>()),
  getUnlockMethods: vi.fn(async () => account.registry),
  updateUnlockMethods: vi.fn(
    async ({
      mutate,
      capability
    }: {
      mutate: (current: never) => never | null | Promise<never | null>
      capability?: unknown
    }) => {
      account.registryCapabilities.push(capability)
      account.trace.push('registry')
      const next = await mutate(account.registry as never)
      if (next !== null) {
        account.registry = next
      }
      return next ?? account.registry
    }
  ),
  deleteUnlockSpaceForEntry: vi.fn(async ({ signer }: { signer?: unknown }) => {
    account.spaceDeletions.push(signer)
    account.trace.push('space-delete')
    return 'deleted'
  })
}))

import {
  generateRecoveryCode,
  recoveryClientFromCode
} from '@interop/wallet-core/recovery'
import { ladderVmAgent } from '@interop/wallet-core/clientAnnex'
import { agentsFromSeed } from '@interop/wallet-core/identity'
import {
  issueRecoveryCode,
  remintEntriesOf,
  revokeRecoveryCode
} from '@/session/recovery'
import type { AccountCeremonyContext } from '@/session/accountCeremonyContext'
import type { RecoveryCodeUnlockMethod } from '@/session/unlockMethods'
import type { Session } from '@/types/auth'

const POINTER = {
  did: 'did:webvh:QmScidForTests:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

const GENERATION_DELEGATION = {
  id: 'urn:zcap:generation',
  controller: 'did:key:z6MkAnnex'
} as unknown as IZcap

const ACTING_LADDER_SEED = new Uint8Array(32).fill(7)

let contextKind: 'enrolled' | 'ladder' = 'ladder'

/**
 * The ceremony context under test, built for whichever kind the current test
 * exercises. Only the members the two recovery ceremonies read are real; the
 * rest are the stubs the mocked seams never look at.
 *
 * @returns {Promise<AccountCeremonyContext>}
 */
async function ceremonyContext(): Promise<AccountCeremonyContext> {
  const shared = {
    remoteStore: { webvhIdStore: () => ({}) },
    pointer: POINTER,
    controller: POINTER.did,
    idStore: {},
    rosterStore: {}
  }
  if (contextKind === 'enrolled') {
    const agents = await agentsFromSeed({ seed: new Uint8Array(32).fill(3) })
    return {
      ...shared,
      kind: 'enrolled',
      signer: {
        kind: 'client',
        updateKeys: { updateSeed: new Uint8Array(32) }
      },
      clientWebvhKeys: { updateSeed: new Uint8Array(32) },
      clientKeyAgreementKey: agents.keyAgreementKey,
      keyAgent: agents.keyAgent,
      invoker: { zcapClient: {} }
    } as unknown as AccountCeremonyContext
  }
  const agent = await ladderVmAgent({ ladderSeed: ACTING_LADDER_SEED })
  const agents = await agentsFromSeed({ seed: ACTING_LADDER_SEED })
  return {
    ...shared,
    kind: 'ladder',
    signer: { kind: 'ladder', ladderSeed: ACTING_LADDER_SEED },
    ladderSeed: ACTING_LADDER_SEED,
    delegationSigner: {},
    ladderDeleter: { zcapClient: {}, invoker: {}, controller: agent.id },
    bindRecord: async () => ({ unlockSpaceId: 'unlock-1' }),
    unlockSpaceId: 'acting-unlock-space',
    standingKeyAgreementKey: agents.keyAgreementKey,
    invoker: { zcapClient: {}, capability: GENERATION_DELEGATION },
    renew: async () => null
  } as unknown as AccountCeremonyContext
}

/**
 * A session whose profile carries exactly what the ceremonies read off it.
 *
 * @returns {Session}
 */
function sessionFixture(): Session {
  return {
    user: { id: 'did:key:z6MkTestClient' },
    registryReady: Promise.resolve(),
    isGuest: false,
    storage: {},
    profile: {
      accountPointer: POINTER,
      accountController: POINTER.did,
      userKey: { id: 'did:key:z6MkUserKey' },
      zcapClient: {},
      ...(contextKind === 'ladder'
        ? { invocationCapability: GENERATION_DELEGATION }
        : {}),
      persistence: {
        logPins: { read: async () => null, write: async () => {} },
        epochPins: {
          load: async () => undefined,
          saveFromDescriptor: async () => {}
        }
      }
    }
  } as unknown as Session
}

vi.mock('@/session/accountCeremonyContext', async importOriginal => ({
  ...(await importOriginal<
    typeof import('@/session/accountCeremonyContext')
  >()),
  accountCeremonyContext: vi.fn(async () => ceremonyContext())
}))

beforeEach(() => {
  account.published.clear()
  account.escrowed.clear()
  account.trace.length = 0
  account.failAt = null
  account.ladderVmClaimable = true
  account.registry = null
  account.registryCapabilities.length = 0
  account.spaceDeletions.length = 0
  account.projections = 0
  account.projectionPuts.length = 0
  contextKind = 'ladder'
})

describe('recovery-code issuance on the ladder branch', () => {
  it('writes the record first, then key entry, escrow, authority entry', async () => {
    const code = generateRecoveryCode()
    await issueRecoveryCode({ session: sessionFixture(), code, label: 'One' })
    expect(account.trace).toEqual([
      'record',
      'entry:key',
      'escrow',
      'entry:authority',
      'registry'
    ])
  })

  it('escrows before the entry on the enrolled branch, in one merged entry', async () => {
    contextKind = 'enrolled'
    const code = generateRecoveryCode()
    await issueRecoveryCode({ session: sessionFixture(), code, label: 'One' })
    expect(account.trace).toEqual(['record', 'escrow', 'entry:all', 'registry'])
  })

  it('leaves a code torn after the key entry unable to spend or to sign', async () => {
    const code = generateRecoveryCode()
    const session = sessionFixture()
    account.failAt = 'escrow'
    await expect(
      issueRecoveryCode({ session, code, label: 'One' })
    ).rejects.toThrow(/torn at escrow/)
    // The pivot landed and nothing else: no authority, so the code's ladder
    // VM stands in no document and its rung is uncommitted; no wrap, so it
    // decrypts nothing.
    expect([...account.published]).toEqual(['key'])
    expect(account.escrowed.size).toBe(0)
    expect(account.registry).toBeNull()
  })

  it('leaves a code torn after the escrow able to decrypt but not to spend', async () => {
    const code = generateRecoveryCode()
    const session = sessionFixture()
    account.failAt = 'entry:authority'
    await expect(
      issueRecoveryCode({ session, code, label: 'One' })
    ).rejects.toThrow(/torn at entry:authority/)
    expect([...account.published]).toEqual(['key'])
    expect(account.escrowed.size).toBe(1)
  })

  it('converges on a re-run from every tear point, publishing each part once', async () => {
    const code = generateRecoveryCode()
    for (const tear of ['record', 'entry:key', 'escrow', 'entry:authority']) {
      account.published.clear()
      account.escrowed.clear()
      account.registry = null
      const session = sessionFixture()
      account.failAt = tear
      await expect(
        issueRecoveryCode({ session, code, label: 'One' })
      ).rejects.toThrow()
      account.failAt = null
      account.trace.length = 0
      await issueRecoveryCode({ session, code, label: 'One' })
      expect([...account.published].sort()).toEqual(['authority', 'key'])
      expect(account.escrowed.size).toBe(1)
      const written = account.registry as { methods: unknown[] } | null
      expect(written?.methods).toHaveLength(1)
      // A stage the torn run already settled republishes nothing.
      const republished = account.trace.filter(one => one.endsWith(':noop'))
      const expectedNoops =
        tear === 'record' || tear === 'entry:key'
          ? 0
          : tear === 'escrow'
            ? 1
            : 2
      expect(republished).toHaveLength(expectedNoops)
    }
  })

  it("mints the bridge under the code's OWN ladder VM on both kinds", async () => {
    for (const kind of ['ladder', 'enrolled'] as const) {
      contextKind = kind
      account.published.clear()
      account.escrowed.clear()
      account.registry = null
      const code = generateRecoveryCode()
      const client = await recoveryClientFromCode({ code })
      const { entry } = await issueRecoveryCode({
        session: sessionFixture(),
        code,
        label: 'One'
      })
      // The registry records the delegation's signing key id: the code's own
      // ladder VM under the account DID, never the acting session's key.
      expect(entry.delegationKeyId).toBe(
        `${POINTER.did}#${client.ladderVmKeyMultibase}`
      )
      // The delegatee is the code's own signing did:key, what the spend
      // invokes the bridge as.
      expect(entry.recoveryClientDid).toBe(client.clientDid)
    }
  })

  it("records rung 0's multibase as the revocation's attribution anchor", async () => {
    const code = generateRecoveryCode()
    const client = await recoveryClientFromCode({ code })
    const { entry } = await issueRecoveryCode({
      session: sessionFixture(),
      code,
      label: 'One'
    })
    expect(entry.updateKeyMultibase).toBe(client.updateKeyMultibase)
  })

  it('rides the generation delegation for the registry write, and nothing on the enrolled kind', async () => {
    await issueRecoveryCode({
      session: sessionFixture(),
      code: generateRecoveryCode(),
      label: 'One'
    })
    expect(account.registryCapabilities).toEqual([GENERATION_DELEGATION])

    contextKind = 'enrolled'
    account.published.clear()
    account.escrowed.clear()
    account.registryCapabilities.length = 0
    await issueRecoveryCode({
      session: sessionFixture(),
      code: generateRecoveryCode(),
      label: 'Two'
    })
    expect(account.registryCapabilities).toEqual([undefined])
  })
})

describe('recovery-code revocation on the ladder branch', () => {
  /**
   * Issues a code and hands back its registry entry, with the trace reset so
   * the revocation's own stages are what a test reads.
   *
   * @returns {Promise<{ session: Session, entry: RecoveryCodeUnlockMethod }>}
   */
  async function issued(): Promise<{
    session: Session
    entry: RecoveryCodeUnlockMethod
  }> {
    const session = sessionFixture()
    const { entry } = await issueRecoveryCode({
      session,
      code: generateRecoveryCode(),
      label: 'One'
    })
    account.trace.length = 0
    account.registryCapabilities.length = 0
    return { session, entry }
  }

  it('runs the gate, the projection, the strike, the rotation, then the teardown', async () => {
    const { session, entry } = await issued()
    await revokeRecoveryCode({ session, entry })
    // The projection lands BEFORE the strike entry: that entry writes
    // `did.jsonl` alone, so `id/did.json` would otherwise keep publishing the
    // revoked code's key until a later visit's ensure caught it.
    expect(account.trace).toEqual([
      'preflight',
      'projection',
      'strike',
      'rotate',
      'space-delete',
      'registry'
    ])
    expect(account.projectionPuts).toEqual([POST_STRIKE_WEB_DOC])
  })

  it('refuses fail-closed, before any write, when no arm claims the ladder VM', async () => {
    const { session, entry } = await issued()
    account.ladderVmClaimable = false
    await expect(revokeRecoveryCode({ session, entry })).rejects.toMatchObject({
      name: 'UnclaimedLadderVmRetirementError'
    })
    // Nothing past the gate ran: the code still stands.
    expect(account.trace).toEqual(['preflight'])
    expect([...account.published].sort()).toEqual(['authority', 'key'])
    expect(account.registry?.methods).toHaveLength(1)
  })

  it("deletes the code's Space through the acting ladder VM's own signer", async () => {
    const { session, entry } = await issued()
    await revokeRecoveryCode({ session, entry })
    const agent = await ladderVmAgent({ ladderSeed: ACTING_LADDER_SEED })
    expect(account.spaceDeletions).toHaveLength(1)
    expect(account.spaceDeletions[0]).toMatchObject({ controller: agent.id })
    expect(account.registry?.methods).toEqual([])
  })

  it('root-signs the Space delete and republishes no projection on the enrolled kind', async () => {
    contextKind = 'enrolled'
    const { session, entry } = await issued()
    await revokeRecoveryCode({ session, entry })
    expect(account.spaceDeletions).toEqual([undefined])
    expect(account.projections).toBe(0)
    expect(account.registryCapabilities).toEqual([undefined])
  })

  it('rides the generation delegation for the registry drop', async () => {
    const { session, entry } = await issued()
    await revokeRecoveryCode({ session, entry })
    expect(account.registryCapabilities).toEqual([GENERATION_DELEGATION])
  })
})

describe('the re-mint pass and a sibling record', () => {
  it("never walks a recovery code's record, so no sibling signer is consulted", () => {
    const record = {
      version: 1 as const,
      webAuthnUserId: 'user-1',
      methods: [
        {
          type: 'recovery-code',
          label: 'Code',
          createdAt: new Date().toISOString(),
          unlockSpaceId: 'code-space',
          recoveryKid: 'kid-1',
          keyAgreementKeyMultibase: 'z6LSCode',
          updateKeyMultibase: 'z6MkRung0',
          recoveryClientDid: 'did:key:z6MkCode'
        },
        {
          type: 'passphrase',
          label: 'Passphrase',
          createdAt: new Date().toISOString(),
          unlockSpaceId: 'passphrase-space',
          unlockClientDid: 'did:key:z6MkPassphrase'
        }
      ]
    }
    const entries = remintEntriesOf({ record: record as never })
    expect(entries).toHaveLength(1)
    expect(entries[0]!.unlockSpaceId).toBe('passphrase-space')
  })

  it('completes both ceremonies with a sibling record present in the registry', async () => {
    const session = sessionFixture()
    const { entry } = await issueRecoveryCode({
      session,
      code: generateRecoveryCode(),
      label: 'One'
    })
    // A sibling standing credential, whose record neither ceremony reads.
    account.registry = {
      ...account.registry!,
      methods: [
        ...account.registry!.methods,
        {
          type: 'passphrase',
          label: 'Passphrase',
          createdAt: new Date().toISOString(),
          unlockSpaceId: 'passphrase-space',
          unlockClientDid: 'did:key:z6MkPassphrase'
        }
      ]
    }
    await revokeRecoveryCode({ session, entry })
    expect(account.spaceDeletions).toHaveLength(1)
    expect(
      (account.registry?.methods as Array<{ type: string }>).map(
        method => method.type
      )
    ).toEqual(['passphrase'])
  })
})
