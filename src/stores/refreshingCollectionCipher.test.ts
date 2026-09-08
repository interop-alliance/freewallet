/**
 * @vitest-environment node
 *
 * The contacts cipher's own unknown-epoch refresh: primed with the descriptor
 * in hand (so the build reads nothing), it re-reads the source once when a
 * decrypt meets an epoch that descriptor does not list, and with no source
 * the unknown epoch propagates as a plain cipher's would.
 */
import { describe, expect, it, vi } from 'vitest'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import {
  createEdvDocCipher,
  type EncryptionDescriptorSource
} from '@interop/was-client/edv'
import { isUnknownEpochError } from '@interop/was-client/sync'
import { mintRecordEncryption } from '@interop/wallet-core/keyring'
import { refreshingCollectionCipher } from './refreshingCollectionCipher'

const COLLECTION_ID = 'contacts'

/**
 * A vault key pair, two one-epoch descriptors wrapped to it (the one the
 * session holds, and the one another client rotated to), and an envelope
 * sealed under the rotated epoch.
 *
 * @returns {Promise<object>}
 */
async function fixture() {
  const key = await X25519KeyAgreementKey2020.generate({
    controller: 'did:key:z6MkRefreshController'
  })
  const keyAgreementKey = key as IKeyAgreementKey
  const keyResolver: IKeyResolver = async () => ({
    id: key.id!,
    type: key.type,
    publicKeyMultibase: key.publicKeyMultibase
  })
  const held = await mintRecordEncryption({ keyAgreementKey })
  const rotated = await mintRecordEncryption({ keyAgreementKey })
  const rotatedCipher = await createEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId: COLLECTION_ID,
    idDerivation: 'random',
    encryption: rotated
  })
  const { envelope } = await rotatedCipher.encrypt({
    data: { displayName: 'Ada' }
  })
  return { keyAgreementKey, keyResolver, held, rotated, envelope }
}

describe('refreshingCollectionCipher', () => {
  it('builds from the descriptor in hand and re-reads the source once on an unknown epoch', async () => {
    const { keyAgreementKey, keyResolver, held, rotated, envelope } =
      await fixture()
    const source: EncryptionDescriptorSource = {
      collectionEncryption: vi.fn(async () => rotated)
    }
    const writes: string[] = []
    const cipher = await refreshingCollectionCipher({
      collectionId: COLLECTION_ID,
      idDerivation: 'random',
      descriptor: held,
      keyAgreementKey,
      keyResolver,
      source,
      cache: {
        readDescriptor: async () => held,
        async writeDescriptor({ descriptor }) {
          writes.push(descriptor.currentEpoch ?? '')
        }
      }
    })
    // The build was served by the primed descriptor, not the source.
    expect(source.collectionEncryption).not.toHaveBeenCalled()

    await expect(cipher.decrypt({ envelope })).resolves.toEqual({
      displayName: 'Ada'
    })
    expect(source.collectionEncryption).toHaveBeenCalledTimes(1)
    // The refreshed descriptor reached the session's cache.
    expect(writes).toContain(rotated.currentEpoch)
  })

  it('propagates the unknown epoch when there is no source to refresh from', async () => {
    const { keyAgreementKey, keyResolver, held, envelope } = await fixture()
    const cipher = await refreshingCollectionCipher({
      collectionId: COLLECTION_ID,
      idDerivation: 'random',
      descriptor: held,
      keyAgreementKey,
      keyResolver
    })
    await expect(cipher.decrypt({ envelope })).rejects.toSatisfy(
      isUnknownEpochError
    )
  })
})
