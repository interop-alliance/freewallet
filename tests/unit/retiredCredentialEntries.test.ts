// @vitest-environment node
/**
 * The entry lookup a recovery spend's registry mutation runs over the
 * continuation's retirement report (`registryEntriesForCredentialVmIds` in
 * `src/session/credentialCoverage.ts`), and the session-less arm of the
 * deletion pre-flight the spend's Space deletes ride
 * (`unlockSpaceDeletionRefusal` in `src/session/unlockMethods.ts`).
 *
 * A recovery continuation strikes every pre-recovery standing credential from
 * the account document and reports their verification-method ids. The lookup
 * finds the registry entries naming them in both published forms, unspent
 * recovery codes included; the pre-flight refuses a caller holding neither a
 * session nor its own signer, which is what makes the tails' explicit-signer
 * deletes the only way in.
 */
import { describe, expect, it, vi } from 'vitest'

vi.mock('@/app.config', async importOriginal => ({
  ...(await importOriginal<typeof import('@/app.config')>()),
  WAS_SERVER_URL: 'https://was.example.test'
}))

import type { IZcap } from '@interop/data-integrity-core'
import { agentsFromSeed } from '@interop/was-client/identity'
import { keyAgreementCommitment } from '@interop/wallet-core/webvh'
import { registryEntriesForCredentialVmIds } from '@/session/credentialCoverage'
import {
  unlockSpaceDeletionRefusal,
  type UnlockMethod
} from '@/session/unlockMethods'

const DID = 'did:webvh:QmScidForTests:was.example.test:space:space-123:id'

/**
 * A real X25519 key-agreement multibase, so the commitment hash below runs
 * over decodable multikey bytes rather than a placeholder string.
 *
 * @param seedByte {number}   the fill byte of the 32-byte seed
 * @returns {Promise<string>}
 */
async function keyAgreementMultibase(seedByte: number): Promise<string> {
  const { keyAgreementKey } = await agentsFromSeed({
    seed: new Uint8Array(32).fill(seedByte)
  })
  const { publicKeyMultibase } = keyAgreementKey as unknown as {
    publicKeyMultibase: string
  }
  return publicKeyMultibase
}

describe('registryEntriesForCredentialVmIds', () => {
  it('finds the entries naming the given credentials, in either published form, codes included', async () => {
    const standingVerbatim = await keyAgreementMultibase(1)
    const standingCommitted = await keyAgreementMultibase(2)
    const goneVerbatim = await keyAgreementMultibase(3)
    const goneCommitted = await keyAgreementMultibase(4)
    const codeMultibase = await keyAgreementMultibase(5)
    const methods = [
      {
        type: 'passkey',
        label: 'a passkey the document still publishes',
        createdAt: '2026-09-01T00:00:00.000Z',
        credentialId: 'standing-passkey',
        transports: [],
        backupEligibility: false,
        backupState: false,
        unlockSpaceId: 'unlock-standing-passkey',
        keyAgreementKeyMultibase: standingVerbatim
      },
      {
        type: 'passphrase',
        createdAt: '2026-09-01T00:00:00.000Z',
        unlockSpaceId: 'unlock-standing-passphrase',
        keyAgreementKeyMultibase: standingCommitted
      },
      {
        type: 'passkey',
        label: 'a passkey the recovery struck',
        createdAt: '2026-09-01T00:00:00.000Z',
        credentialId: 'retired-passkey',
        transports: [],
        backupEligibility: false,
        backupState: false,
        unlockSpaceId: 'unlock-retired-passkey',
        keyAgreementKeyMultibase: goneVerbatim
      },
      {
        type: 'passphrase',
        createdAt: '2026-09-01T00:00:00.000Z',
        unlockSpaceId: 'unlock-retired-passphrase',
        keyAgreementKeyMultibase: goneCommitted
      },
      {
        type: 'passphrase',
        createdAt: '2026-09-01T00:00:00.000Z',
        unlockSpaceId: 'unlock-bare-passphrase'
      },
      {
        type: 'recovery-code',
        label: 'an unspent code the recovery struck',
        createdAt: '2026-09-01T00:00:00.000Z',
        unlockSpaceId: 'unlock-code',
        recoveryKid: 'kid-code',
        keyAgreementKeyMultibase: codeMultibase,
        updateKeyMultibase: 'z6MkCodeRung0'
      }
    ] as unknown as UnlockMethod[]
    // What a continuation reports: the passkey and the code under their
    // verbatim ids, the passphrase under its commitment id. The standing
    // credentials' ids, and the retired passphrase's verbatim form, are not
    // in it.
    const vmIds = [
      `${DID}#${goneVerbatim}`,
      `${DID}#${await keyAgreementCommitment({
        keyAgreementKeyMultibase: goneCommitted
      })}`,
      `${DID}#${codeMultibase}`,
      `${DID}#${goneCommitted}`
    ]

    const entries = await registryEntriesForCredentialVmIds({
      did: DID,
      registry: { methods },
      vmIds
    })

    expect(entries.map(entry => entry.unlockSpaceId)).toEqual([
      'unlock-retired-passkey',
      'unlock-retired-passphrase',
      'unlock-code'
    ])
  })

  it('finds nothing for an empty id set or an absent registry', async () => {
    expect(
      await registryEntriesForCredentialVmIds({
        did: DID,
        registry: null,
        vmIds: [`${DID}#zAnything`]
      })
    ).toEqual([])
    expect(
      await registryEntriesForCredentialVmIds({
        did: DID,
        registry: { methods: [{ type: 'passphrase', unlockSpaceId: 'x' }] },
        vmIds: []
      })
    ).toEqual([])
  })
})

describe('unlockSpaceDeletionRefusal with no session', () => {
  const entry = {
    type: 'passphrase',
    createdAt: '2026-09-01T00:00:00.000Z',
    unlockSpaceId: 'unlock-retired-passphrase',
    manageCapability: {
      id: 'urn:zcap:delegated:manage',
      controller: DID,
      invocationTarget:
        'https://was.example.test/space/unlock-retired-passphrase',
      allowedAction: ['GET', 'PUT', 'DELETE']
    } as unknown as IZcap
  } as unknown as UnlockMethod

  it('refuses a caller holding neither a session nor a signer', () => {
    expect(unlockSpaceDeletionRefusal({ entry })).toBe('foreign-controller')
  })

  it('admits the same entry once the caller states its own signer', () => {
    expect(
      unlockSpaceDeletionRefusal({
        entry,
        signer: {
          zcapClient: {} as never,
          controller: 'did:key:z6MkLadderVm'
        }
      })
    ).toBeUndefined()
  })
})
