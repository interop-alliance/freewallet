// @vitest-environment node
/**
 * Unit tests for the login-time completer
 * (`src/session/pendingRetirement.ts`): when a registry entry naming a
 * credential other than the one logging in is a pending retirement, when it
 * is not, what the completer writes afterwards, when a bare or absent
 * passphrase entry is rebuilt from the credential logging in, and the passkey
 * sibling that rebuilds a bare passkey entry.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { addSink, captureSink } from '@interop/logger'

const MY_KAK = 'z6LSgJbFbAEq4zhHZ7FrQKqF6ja8tcjNpVu8ZbhnxmunPkN7'
const OTHER_KAK = 'z6LStRqthDcQTuohXDkypMe9aQ2ZCLWrV7u79pB25oza2u7D'

const POINTER = {
  did: 'did:webvh:QmScid:was.example.test:space:space-123:id',
  spaceId: 'space-123',
  host: 'https://was.example.test'
}

const FRESH_USER_KEY = { id: 'did:key:z6LSFreshUserKey' }

const state = vi.hoisted(() => ({
  calls: [] as string[],
  enrolled: true,
  // Whether a registry record exists at all.
  registry: true,
  // The registry's passphrase entry, as this login reads it.
  entry: null as unknown,
  // The registry's passkey entries, as a passkey login reads them.
  passkeyEntries: [] as unknown[],
  // Whether the account document lists the LOGIN credential's VERBATIM
  // key-agreement VM -- the form a passkey publishes under.
  loginPasskeyStanding: true,
  // Whether the account document lists the LOGIN credential's commitment VM.
  loginCredentialStanding: true,
  // Whether it still lists the NAMED (pending) credential's: gone means the
  // torn run's document edit landed and only its registry write was lost.
  namedCredentialStanding: true,
  rotationThrows: false,
  // Whether the retirement refuses on the ladder-VM gate (WC-187) rather
  // than tearing on transport.
  rotationRefusesByGate: false,
  establishThrows: false,
  // The tail entries the retirement's outcome carries, which the repair
  // hands the ceremony-tail reporter.
  rotationMended: [] as Array<Record<string, unknown>>
}))

vi.mock('@/session/accountCeremonyContext', () => ({
  // The live-rides thunk: the ceremonies read the invocation capability off
  // the context each time they spread it, so the mock must expose it too.
  ceremonyRides:
    ({ context }: { context: { invoker?: { capability?: unknown } } | null }) =>
    () =>
      context?.invoker?.capability
        ? { capability: context.invoker.capability }
        : {},
  enrolledCeremonyContext: vi.fn(() =>
    state.enrolled ? { pointer: POINTER } : null
  ),
  // The repairs resolve the ceremony context rather than the enrolled one:
  // a remembered session's context root-invokes, so its invoker carries no
  // delegated capability.
  accountCeremonyContext: vi.fn(async () =>
    state.enrolled ? { kind: 'enrolled', pointer: POINTER, invoker: {} } : null
  )
}))

vi.mock('@/session/credentialRotation', () => ({
  isUnclaimedLadderVmRefusal: (err: unknown) =>
    (err as { name?: string })?.name === 'UnclaimedLadderVmRetirementError',
  rotateOffUnlockCredential: vi.fn(async () => {
    state.calls.push('rotateOffUnlockCredential')
    if (state.rotationRefusesByGate) {
      const err = new Error(
        "did:webvh: the credential's ladder VM could not be claimed."
      )
      err.name = 'UnclaimedLadderVmRetirementError'
      Object.assign(err, {
        unclaimedLadderVmIds: [`${POINTER.did}#z6MkStandingLadderVm`],
        retryableWithLadderSeed: false
      })
      throw err
    }
    if (state.rotationThrows) {
      throw new Error('log conflict')
    }
    return {
      rotated: true,
      collections: { outcomes: {}, failed: [] },
      userKey: FRESH_USER_KEY,
      mended: state.rotationMended
    }
  })
}))

vi.mock('@/session/userKeyAdoption', () => ({
  adoptRotatedUserKey: vi.fn(async () => {
    state.calls.push('adoptRotatedUserKey')
  })
}))

vi.mock('@/session/standingUnlock', () => ({
  standingFieldsOfKeyringHit: vi.fn(async () => ({
    keyAgreementKeyMultibase: MY_KAK,
    updateKeyMultibase: 'z6MkMyRung0'
  })),
  establishStandingUnlock: vi.fn(async () => {
    state.calls.push('establishStandingUnlock')
    if (state.establishThrows) {
      throw new Error('publish failed')
    }
    // The establishment publishes the login credential's commitment entry,
    // so the repair's post-establishment document read sees it standing.
    state.loginCredentialStanding = true
    return {
      unlockSpaceId: 'unlock-space-new',
      manageCapability: { id: 'urn:zcap:established-manage' },
      persistClientKeys: vi.fn(async () => {}),
      ladderSeed: new Uint8Array(32).fill(7),
      standingFields: {
        keyAgreementKeyMultibase: MY_KAK,
        updateKeyMultibase: 'z6MkEstablishedRung0'
      }
    }
  })
}))

vi.mock('@/session/verifiedLog', () => ({
  verifiedAccountLog: vi.fn(async () => {
    state.calls.push('verifiedAccountLog')
    return { doc: await accountDocument() }
  })
}))

vi.mock('@/session/unlockMethods', async importOriginal => {
  const actual =
    await importOriginal<typeof import('@/session/unlockMethods')>()
  const read = async () => {
    state.calls.push('getUnlockMethods')
    if (!state.registry) {
      return null
    }
    const methods = [
      ...(state.entry ? [state.entry] : []),
      ...state.passkeyEntries
    ]
    return { version: 1, webAuthnUserId: 'handle', methods }
  }
  return {
    getUnlockMethods: vi.fn(read),
    // The wrapper's internal fresh read is surfaced as 'getUnlockMethods' so
    // the call-order assertions keep reading like the flow they describe; a
    // landed write is 'putUnlockMethods'.
    updateUnlockMethods: vi.fn(
      async ({
        mutate
      }: {
        mutate: (current: never) => never | null | Promise<never | null>
      }) => {
        const current = (await read()) as never
        const next = await mutate(current)
        if (next === null) {
          return current
        }
        state.calls.push('putUnlockMethods')
        return next
      }
    ),
    // The real upsert, so the entry a repair actually writes -- including
    // whether it still carries the establishment marker -- is the one
    // production produces rather than a stand-in's echo.
    upsertPassphraseUnlockMethod: vi.fn(actual.upsertPassphraseUnlockMethod),
    upsertPasskeyUnlockMethod: vi.fn(({ record }: { record: never }) => record),
    // The live-profile swap the establish-first arm runs; real, since it is
    // pure session mutation.
    adoptPassphraseRebind: vi.fn(actual.adoptPassphraseRebind)
  }
})

import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import { unlockKeyVmId } from '@interop/wallet-core/unlock'
import { rotateOffUnlockCredential } from '@/session/credentialRotation'
import { adoptRotatedUserKey } from '@/session/userKeyAdoption'
import {
  upsertPassphraseUnlockMethod,
  upsertPasskeyUnlockMethod
} from '@/session/unlockMethods'
import { establishStandingUnlock } from '@/session/standingUnlock'
import {
  rebuildBarePasskeyEntry,
  repairTornPassphraseRetirement
} from '@/session/pendingRetirement'
import { MENDER_WARNINGS } from '@/session/menders/warnings'
import type { KeyringFetchResult } from '@/session/keyring'
import type { Session } from '@/types/auth'

/**
 * The account document, listing the login credential's commitment
 * verification method only when the scenario says it is standing.
 *
 * @returns {Promise<object>}
 */
async function accountDocument(): Promise<object> {
  const listed: string[] = []
  if (state.loginCredentialStanding) {
    listed.push(await commitmentVmId(MY_KAK))
  }
  if (state.namedCredentialStanding) {
    listed.push(await commitmentVmId(OTHER_KAK))
  }
  if (state.loginPasskeyStanding) {
    listed.push(
      unlockKeyVmId({
        did: POINTER.did,
        keyAgreement: { publicKeyMultibase: MY_KAK }
      })
    )
  }
  return {
    id: POINTER.did,
    verificationMethod: listed.map(id => ({ id, type: 'MultikeyCommitment' })),
    keyAgreement: listed
  }
}

/**
 * The commitment verification-method id a passphrase publishes under.
 *
 * @param keyAgreementKeyMultibase {string}
 * @returns {Promise<string>}
 */
async function commitmentVmId(
  keyAgreementKeyMultibase: string
): Promise<string> {
  return unlockKeyVmId({
    did: POINTER.did,
    keyAgreement: {
      commitment: await keyAgreementCommitment({ keyAgreementKeyMultibase })
    }
  })
}

/**
 * A registry entry recording one credential's standing configuration.
 *
 * @param options {object}
 * @param options.keyAgreementKeyMultibase {string}
 * @returns {object}
 */
function entryFor({
  keyAgreementKeyMultibase
}: {
  keyAgreementKeyMultibase: string
}): object {
  return {
    type: 'passphrase',
    createdAt: '2026-08-01T00:00:00.000Z',
    unlockSpaceId: 'unlock-space-new',
    manageCapability: { id: 'urn:zcap:stored-manage' },
    keyAgreementKeyMultibase,
    updateKeyMultibase: 'z6MkRecordedRung'
  }
}

/**
 * A passphrase entry missing its identity members -- the bare state an
 * earlier defect left behind.
 *
 * @returns {object}
 */
function bareEntry(): object {
  return {
    type: 'passphrase',
    createdAt: '2026-08-01T00:00:00.000Z',
    unlockSpaceId: 'unlock-space-new',
    manageCapability: { id: 'urn:zcap:stored-manage' }
  }
}

/**
 * The passphrase change's establishment marker, naming the credential
 * logging in at its own unlock Space -- the one shape that arms the
 * establish-first arm.
 */
const LOGIN_MARKER = {
  unlockSpaceId: 'unlock-space-new',
  keyAgreementKeyMultibase: MY_KAK
}

/**
 * The registry state a passphrase change torn between the new credential's
 * standing record and its document entry leaves: the entry still names the
 * OLD credential at the OLD unlock Space, stamped with the marker the change
 * wrote before its establishment started.
 *
 * @param [options] {object}
 * @param [options.pendingEstablishment] {object}   the marker to stamp;
 *   omitted leaves the entry unmarked
 * @returns {object}
 */
function tornChangeEntry({
  pendingEstablishment = LOGIN_MARKER
}: {
  pendingEstablishment?: object
} = {}): object {
  return {
    ...entryFor({ keyAgreementKeyMultibase: OTHER_KAK }),
    unlockSpaceId: 'unlock-space-old',
    pendingEstablishment
  }
}

/**
 * The passphrase entry the repair's registry write produced, read off the
 * real upsert's return value.
 *
 * @returns {object | undefined}
 */
function writtenPassphraseEntry(): object | undefined {
  const results = vi.mocked(upsertPassphraseUnlockMethod).mock.results
  const record = results.at(-1)?.value as
    { methods: Array<{ type: string }> } | undefined
  return record?.methods.find(method => method.type === 'passphrase')
}

function makeSession(type: 'passphrase' | 'passkey' = 'passphrase'): Session {
  return {
    user: { id: 'did:key:zClient' },
    isGuest: false,
    storage: { spaceId: POINTER.spaceId },
    profile: {
      accountPointer: POINTER,
      unlockMethod: { type, unlockSpaceId: 'unlock-space-new' }
    }
  } as unknown as Session
}

function makeFound(): KeyringFetchResult {
  return {
    unlockSpaceId: 'unlock-space-new',
    manageCapability: { id: 'urn:zcap:manage' },
    standingClient: { keyAgreementKeyMultibase: MY_KAK }
  } as unknown as KeyringFetchResult
}

beforeEach(() => {
  state.calls = []
  state.enrolled = true
  state.registry = true
  state.entry = entryFor({ keyAgreementKeyMultibase: OTHER_KAK })
  state.passkeyEntries = []
  state.loginPasskeyStanding = true
  state.loginCredentialStanding = true
  state.namedCredentialStanding = true
  state.rotationThrows = false
  state.rotationRefusesByGate = false
  state.establishThrows = false
  state.rotationMended = []
  vi.clearAllMocks()
})

describe('repairTornPassphraseRetirement', () => {
  it('retires the named credential and records its own standing configuration', async () => {
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      'rotateOffUnlockCredential',
      'adoptRotatedUserKey',
      'getUnlockMethods',
      'putUnlockMethods'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        method: expect.objectContaining({
          keyAgreementKeyMultibase: OTHER_KAK
        }),
        verb: 'finishing a passphrase change'
      })
    )
    expect(vi.mocked(adoptRotatedUserKey)).toHaveBeenCalledWith(
      expect.objectContaining({
        spaceId: POINTER.spaceId,
        userKey: FRESH_USER_KEY
      })
    )
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith({
      record: expect.anything(),
      unlockSpaceId: 'unlock-space-new',
      manageCapability: { id: 'urn:zcap:manage' },
      standing: {
        keyAgreementKeyMultibase: MY_KAK,
        updateKeyMultibase: 'z6MkMyRung0'
      }
    })
  })

  it("reports the retirement's ceremony-tail entries", async () => {
    state.rotationMended = [
      {
        invariant: 'retired-credential-leaves-no-annex-inventory',
        ceremonies: ['unlock-credential-rotation'],
        outcome: 'failed',
        errorName: 'TypeError'
      }
    ]
    const capture = captureSink()
    const remove = addSink(capture.sink)
    try {
      await repairTornPassphraseRetirement({
        session: makeSession(),
        found: makeFound()
      })
    } finally {
      remove()
    }

    const warned = capture.events.filter(
      event =>
        event.level === 'warn' &&
        (event.data as { trigger?: string } | undefined)?.trigger ===
          'ceremony-tail'
    )
    expect(warned).toHaveLength(1)
    expect(warned[0]?.msg).toBe(
      MENDER_WARNINGS['retired-credential-leaves-no-annex-inventory']
    )
    expect(warned[0]?.data).toMatchObject({
      invariant: 'retired-credential-leaves-no-annex-inventory',
      outcome: 'failed',
      errorName: 'TypeError'
    })
  })

  it('keeps the stored management zcap when this login minted none', async () => {
    const found = makeFound()
    delete (found as { manageCapability?: unknown }).manageCapability
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found
    })
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith(
      expect.objectContaining({
        manageCapability: { id: 'urn:zcap:stored-manage' }
      })
    )
  })

  it('records the standing configuration without retiring when the edit already landed', async () => {
    // The torn run's document edit landed and only its registry write was
    // lost: the roster and cascade residue is the ordinary login sweep's,
    // and a retirement here would swap the annex generation every login.
    state.namedCredentialStanding = false
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      'getUnlockMethods',
      'putUnlockMethods'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(adoptRotatedUserKey)).not.toHaveBeenCalled()
  })

  it('skips an entry already naming the credential logging in', async () => {
    state.entry = entryFor({ keyAgreementKeyMultibase: MY_KAK })
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods'])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
  })

  it('writes nothing when the login credential is not in the document', async () => {
    // The other reading of the same registry state: an OLD passphrase whose
    // unlock Space delete failed, logging in after a change that completed.
    // Retiring the entry's credential there would strip the CURRENT one.
    state.loginCredentialStanding = false
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('establishes the login credential first when the change tore before its entry', async () => {
    // The torn state: the entry still names the OLD credential at the OLD
    // unlock Space, the login credential is not in the document, and the
    // change's establishment marker names the credential logging in -- the
    // one reading under which the establishment is what failed.
    state.loginCredentialStanding = false
    state.entry = tornChangeEntry()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const session = makeSession()
    await repairTornPassphraseRetirement({
      session,
      found: makeFound(),
      credential: { secret: 'new-pass' }
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      // Establish-first: the login credential becomes standing before the
      // named credential is retired.
      'establishStandingUnlock',
      // The post-establishment re-read of the account document.
      'verifiedAccountLog',
      'rotateOffUnlockCredential',
      'adoptRotatedUserKey',
      'getUnlockMethods',
      'putUnlockMethods'
    ])
    expect(vi.mocked(establishStandingUnlock)).toHaveBeenCalledWith(
      expect.objectContaining({ secret: 'new-pass', lowEntropy: true })
    )
    // The session adopts the established record, as the change ceremony
    // does on its own establishment.
    expect(session.profile.unlockMethod).toEqual(
      expect.objectContaining({
        type: 'passphrase',
        unlockSpaceId: 'unlock-space-new',
        manageCapability: { id: 'urn:zcap:established-manage' }
      })
    )
    expect(session.profile.persistClientKeys).toBeTypeOf('function')
    expect(session.profile.ladderSeed).toBeInstanceOf(Uint8Array)
    // The entry rewrite records the establishment's standing fields, not
    // ones rebuilt from the pre-establishment keyring hit.
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith({
      record: expect.anything(),
      unlockSpaceId: 'unlock-space-new',
      manageCapability: { id: 'urn:zcap:established-manage' },
      standing: {
        keyAgreementKeyMultibase: MY_KAK,
        updateKeyMultibase: 'z6MkEstablishedRung0'
      }
    })
    warn.mockRestore()
  })

  it('drops the establishment marker from the entry it writes', async () => {
    // The change's final write is what clears the marker; when the change
    // never got there, this repair's write is. An entry left marked would
    // re-arm the arm on every later login.
    state.loginCredentialStanding = false
    state.entry = tornChangeEntry()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound(),
      credential: { secret: 'new-pass' }
    })
    expect(writtenPassphraseEntry()).toMatchObject({
      unlockSpaceId: 'unlock-space-new',
      keyAgreementKeyMultibase: MY_KAK
    })
    expect(writtenPassphraseEntry()).not.toHaveProperty('pendingEstablishment')
    warn.mockRestore()
  })

  it('refuses a stale marker whose own entry left the document', async () => {
    // The marker-armed state holds the entry's credential standing by
    // construction (the change tears before its retirement). Once that
    // credential is out of the document, establishing the marked one would
    // reinstate an abandoned passphrase over the account's current one.
    state.loginCredentialStanding = false
    state.namedCredentialStanding = false
    state.entry = tornChangeEntry()
    const capture = captureSink()
    const remove = addSink(capture.sink)

    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound(),
      credential: { secret: 'new-pass' }
    })

    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(vi.mocked(establishStandingUnlock)).not.toHaveBeenCalled()
    expect(state.calls).not.toContain('putUnlockMethods')
    expect(
      capture.events.find(
        event => event.level === 'warn' && event.msg.includes('marker is stale')
      )
    ).toBeDefined()
    remove()
  })

  it('never establishes toward an unmarked entry', async () => {
    // The forbidden direction, and the reading that shares the whole
    // registry and document state with the torn change: an OLD passphrase
    // (its unlock Space delete lost) logging in after a change that
    // completed elsewhere. The completed change dropped the marker, so the
    // arm must not fire even with the secret in hand.
    state.loginCredentialStanding = false
    state.entry = entryFor({ keyAgreementKeyMultibase: OTHER_KAK })
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound(),
      credential: { secret: 'old-pass' }
    })
    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(vi.mocked(establishStandingUnlock)).not.toHaveBeenCalled()
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('never establishes toward a marker naming another credential', async () => {
    // A later change's marker, or one this login is not the subject of: the
    // credential being established is not the one logging in.
    state.loginCredentialStanding = false
    state.entry = tornChangeEntry({
      pendingEstablishment: {
        unlockSpaceId: 'unlock-space-new',
        keyAgreementKeyMultibase: OTHER_KAK
      }
    })
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound(),
      credential: { secret: 'old-pass' }
    })
    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(vi.mocked(establishStandingUnlock)).not.toHaveBeenCalled()
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('never establishes toward a marker at another unlock Space', async () => {
    // The multibase matches but the address does not: whatever that marker
    // names, it is not the record this login just read.
    state.loginCredentialStanding = false
    state.entry = tornChangeEntry({
      pendingEstablishment: {
        unlockSpaceId: 'unlock-space-other',
        keyAgreementKeyMultibase: MY_KAK
      }
    })
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound(),
      credential: { secret: 'old-pass' }
    })
    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(vi.mocked(establishStandingUnlock)).not.toHaveBeenCalled()
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('leaves the pending state untouched when the establishment fails again', async () => {
    state.loginCredentialStanding = false
    state.entry = tornChangeEntry()
    state.establishThrows = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(
      repairTornPassphraseRetirement({
        session: makeSession(),
        found: makeFound(),
        credential: { secret: 'new-pass' }
      })
    ).resolves.toBe('noop')
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      'establishStandingUnlock'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(state.calls).not.toContain('putUnlockMethods')
    warn.mockRestore()
  })

  it('rebuilds a bare entry when the login credential is standing', async () => {
    state.entry = bareEntry()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      // The write's own fresh read inside the compare-and-swap wrapper.
      'getUnlockMethods',
      'putUnlockMethods'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith({
      record: expect.anything(),
      unlockSpaceId: 'unlock-space-new',
      manageCapability: { id: 'urn:zcap:manage' },
      standing: {
        keyAgreementKeyMultibase: MY_KAK,
        updateKeyMultibase: 'z6MkMyRung0'
      }
    })
    warn.mockRestore()
  })

  it('leaves a bare entry alone when the login credential is not standing', async () => {
    // A bare entry on a credential the document never carried is honest:
    // nothing has been established for it to record.
    state.entry = bareEntry()
    state.loginCredentialStanding = false
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('establishes and records a bare entry the change marked', async () => {
    // The same torn change on an account whose registry named no passphrase
    // members yet: nothing to retire, but the marker says the credential
    // logging in is the one the change was establishing.
    state.entry = { ...bareEntry(), ...tornChangeEntry() }
    delete (state.entry as { keyAgreementKeyMultibase?: string })
      .keyAgreementKeyMultibase
    delete (state.entry as { updateKeyMultibase?: string }).updateKeyMultibase
    state.loginCredentialStanding = false
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const session = makeSession()

    await repairTornPassphraseRetirement({
      session,
      found: makeFound(),
      credential: { secret: 'new-pass' }
    })

    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      'establishStandingUnlock',
      // The write's own fresh read inside the compare-and-swap wrapper.
      'getUnlockMethods',
      'putUnlockMethods'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    // The session adopts the established record, as the change ceremony does.
    expect(session.profile.unlockMethod).toEqual({
      type: 'passphrase',
      unlockSpaceId: 'unlock-space-new',
      manageCapability: { id: 'urn:zcap:established-manage' }
    })
    expect(session.profile.persistClientKeys).toBeTypeOf('function')
    expect(session.profile.ladderSeed).toBeInstanceOf(Uint8Array)
    // The entry records the establishment's own standing fields at its own
    // unlock Space, not ones rebuilt from the pre-establishment keyring hit.
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith({
      record: expect.anything(),
      unlockSpaceId: 'unlock-space-new',
      manageCapability: { id: 'urn:zcap:established-manage' },
      standing: {
        keyAgreementKeyMultibase: MY_KAK,
        updateKeyMultibase: 'z6MkEstablishedRung0'
      }
    })
    expect(writtenPassphraseEntry()).not.toHaveProperty('pendingEstablishment')
    warn.mockRestore()
  })

  it('leaves a marked bare entry alone with no credential in hand', async () => {
    // The marker arms the arm; the typed secret is what runs it. An
    // unattended login without one leaves the state for the next.
    state.entry = { ...bareEntry(), ...tornChangeEntry() }
    delete (state.entry as { keyAgreementKeyMultibase?: string })
      .keyAgreementKeyMultibase
    delete (state.entry as { updateKeyMultibase?: string }).updateKeyMultibase
    state.loginCredentialStanding = false

    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })

    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(vi.mocked(establishStandingUnlock)).not.toHaveBeenCalled()
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('rebuilds an absent passphrase entry the same way', async () => {
    state.entry = null
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      // The write's own fresh read inside the compare-and-swap wrapper.
      'getUnlockMethods',
      'putUnlockMethods'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    expect(vi.mocked(upsertPassphraseUnlockMethod)).toHaveBeenCalledWith(
      expect.objectContaining({
        standing: {
          keyAgreementKeyMultibase: MY_KAK,
          updateKeyMultibase: 'z6MkMyRung0'
        }
      })
    )
    warn.mockRestore()
  })

  it('writes nothing for an entry naming another credential with no rung', async () => {
    // The repair attributes the named credential's ladder by its recorded
    // rung, and rebuilding the entry from this login would silently un-name
    // a credential that may still stand.
    const entry = entryFor({ keyAgreementKeyMultibase: OTHER_KAK }) as {
      updateKeyMultibase?: string
    }
    delete entry.updateKeyMultibase
    state.entry = entry
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods'])
    expect(state.calls).not.toContain('putUnlockMethods')
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    warn.mockRestore()
  })

  it('rebuilds an entry naming THIS credential with no rung', async () => {
    const entry = entryFor({ keyAgreementKeyMultibase: MY_KAK }) as {
      updateKeyMultibase?: string
    }
    delete entry.updateKeyMultibase
    state.entry = entry
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      // The write's own fresh read inside the compare-and-swap wrapper.
      'getUnlockMethods',
      'putUnlockMethods'
    ])
    expect(vi.mocked(rotateOffUnlockCredential)).not.toHaveBeenCalled()
    warn.mockRestore()
  })

  it('writes nothing when there is no registry at all', async () => {
    // The backfill creates the record; the login after that finds an entry.
    state.registry = false
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods'])
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('skips a passkey login', async () => {
    await repairTornPassphraseRetirement({
      session: makeSession('passkey'),
      found: makeFound()
    })
    expect(state.calls).toEqual([])
  })

  it('skips a session that cannot act as an enrolled client', async () => {
    state.enrolled = false
    await repairTornPassphraseRetirement({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([])
  })

  it('logs and skips a gate refusal, leaving the entry pending', async () => {
    state.rotationRefusesByGate = true
    const capture = captureSink()
    const remove = addSink(capture.sink)

    // Unattended, on the login chain: the refusal never surfaces to the
    // login page, and it never reaches the entry rewrite below, which would
    // un-name a credential that is still standing.
    await expect(
      repairTornPassphraseRetirement({
        session: makeSession(),
        found: makeFound()
      })
    ).resolves.toBe('noop')

    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      'rotateOffUnlockCredential'
    ])
    expect(state.calls).not.toContain('putUnlockMethods')
    const warned = capture.events.find(
      event => event.level === 'warn' && event.msg.includes('stays pending')
    )
    expect(warned).toBeDefined()
    expect(warned!.data).toMatchObject({
      unclaimedLadderVmIds: [`${POINTER.did}#z6MkStandingLadderVm`],
      retryableWithLadderSeed: false
    })
    remove()
  })

  it('leaves the entry alone when the retirement throws', async () => {
    state.rotationThrows = true
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(
      repairTornPassphraseRetirement({
        session: makeSession(),
        found: makeFound()
      })
    ).rejects.toThrow('log conflict')
    expect(state.calls).not.toContain('putUnlockMethods')
    warn.mockRestore()
  })
})

/**
 * A passkey registry entry, bare unless standing members are supplied.
 *
 * @param [options] {object}
 * @param [options.keyAgreementKeyMultibase] {string}
 * @returns {object}
 */
function passkeyEntry({
  keyAgreementKeyMultibase
}: {
  keyAgreementKeyMultibase?: string
} = {}): object {
  return {
    type: 'passkey',
    label: 'Yubikey',
    createdAt: '2026-08-01T00:00:00.000Z',
    credentialId: 'Y3JlZC1vbGQ',
    transports: ['usb'],
    backupEligibility: false,
    backupState: false,
    unlockSpaceId: 'unlock-space-new',
    ...(keyAgreementKeyMultibase ? { keyAgreementKeyMultibase } : {})
  }
}

describe('rebuildBarePasskeyEntry', () => {
  beforeEach(() => {
    // A passkey login reads no passphrase entry; only its own.
    state.entry = null
  })

  it('rebuilds a bare passkey entry when the credential is standing', async () => {
    state.passkeyEntries = [passkeyEntry()]
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await rebuildBarePasskeyEntry({
      session: makeSession('passkey'),
      found: makeFound()
    })
    expect(state.calls).toEqual([
      'getUnlockMethods',
      'verifiedAccountLog',
      // The write's own fresh read inside the compare-and-swap wrapper.
      'getUnlockMethods',
      'putUnlockMethods'
    ])
    expect(vi.mocked(upsertPasskeyUnlockMethod)).toHaveBeenCalledWith({
      record: expect.anything(),
      entry: expect.objectContaining({
        type: 'passkey',
        credentialId: 'Y3JlZC1vbGQ',
        keyAgreementKeyMultibase: MY_KAK,
        updateKeyMultibase: 'z6MkMyRung0'
      })
    })
    warn.mockRestore()
  })

  it('writes nothing when the passkey is not in the document', async () => {
    // A passkey publishes its key-agreement key VERBATIM, so the commitment
    // form standing for a passphrase does not cover it.
    state.passkeyEntries = [passkeyEntry()]
    state.loginPasskeyStanding = false
    await rebuildBarePasskeyEntry({
      session: makeSession('passkey'),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods', 'verifiedAccountLog'])
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('leaves an entry that already names a credential alone', async () => {
    state.passkeyEntries = [passkeyEntry({ keyAgreementKeyMultibase: MY_KAK })]
    await rebuildBarePasskeyEntry({
      session: makeSession('passkey'),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods'])
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('writes nothing when this passkey has no entry at all', async () => {
    // Creating one needs members no keyring hit carries (the WebAuthn
    // credential id, the label, the registration flags).
    state.passkeyEntries = []
    await rebuildBarePasskeyEntry({
      session: makeSession('passkey'),
      found: makeFound()
    })
    expect(state.calls).toEqual(['getUnlockMethods'])
    expect(state.calls).not.toContain('putUnlockMethods')
  })

  it('skips a passphrase login', async () => {
    state.passkeyEntries = [passkeyEntry()]
    await rebuildBarePasskeyEntry({
      session: makeSession(),
      found: makeFound()
    })
    expect(state.calls).toEqual([])
  })
})
