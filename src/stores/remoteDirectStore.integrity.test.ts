/**
 * Unit tests for how the replica-less backend buckets a misbound envelope: a
 * body the host served under an id it was not sealed for. The purge on this
 * backend DELETEs the remote resource outright, so a misbound row landing in
 * the purgeable bucket would let a host present authentic data as garbage and
 * have the wallet destroy it on the server.
 *
 * @vitest-environment node
 */
import { describe, expect, it } from 'vitest'
import { IntegrityError } from '@interop/was-client'
import type { DocCipher } from '@interop/was-client/edv'
import type { Json } from '@interop/was-sync'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { RemoteDirectStore } from './remoteDirectStore'
import type { WASRemoteStore } from './wasRemoteStore'

const CREDENTIAL = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:key:z6MkIssuer',
  credentialSubject: { name: 'Alice' }
} as unknown as IVerifiableCredential

/**
 * A cipher whose every decrypt raises the binding refusal, and whose encrypt
 * still produces a well-formed fake envelope.
 *
 * @returns {DocCipher}
 */
function misboundCipher(): DocCipher {
  return {
    async encrypt({ data }: { data: Json }) {
      return {
        id: 'z6Minted',
        envelope: {
          id: 'z6Minted',
          sequence: 0,
          jwe: { ciphertext: JSON.stringify(data) }
        } as Json
      }
    },
    async decrypt({ id }: { id?: string }) {
      throw new IntegrityError(
        'Cannot decrypt this resource: the stored envelope is bound to a ' +
          `different resource id ("z6SealedFor") than the one requested ` +
          `("${id}"). The server swapped two resources' envelopes.`
      )
    }
  }
}

/**
 * A remote store holding one envelope resource per collection, recording every
 * delete so a purge that reaches the misbound row is visible.
 *
 * @param options {object}
 * @param options.resourceId {string}
 * @returns {{ remote: WASRemoteStore; deleted: string[] }}
 */
function fakeRemote({ resourceId }: { resourceId: string }): {
  remote: WASRemoteStore
  deleted: string[]
} {
  const deleted: string[] = []
  const remote = {
    async listSyncedDocuments() {
      return [
        {
          id: resourceId,
          data: {
            id: resourceId,
            sequence: 0,
            jwe: { ciphertext: JSON.stringify(CREDENTIAL) }
          } as Json
        }
      ]
    },
    async deleteSyncedResource({ resourceId: id }: { resourceId: string }) {
      deleted.push(id)
    }
  } as unknown as WASRemoteStore
  return { remote, deleted }
}

describe('RemoteDirectStore (misbound envelopes)', () => {
  it('counts a misbound credential resource apart from undecryptable and deletes nothing', async () => {
    const { remote, deleted } = fakeRemote({ resourceId: 'z6ReadUnder' })
    const store = new RemoteDirectStore({
      remoteStore: remote,
      ciphers: { privateCredentials: misboundCipher() }
    })

    expect(await store.listCredentials()).toEqual([])
    expect(store.integrityCredentials).toBe(1)
    expect(store.undecryptableCredentials).toBe(0)
    // No descriptor refresh is asked for: no refresh can change the answer.
    expect(store.unknownEpochCredentials).toBe(0)
    expect(store.noEpochKeyCredentials).toBe(0)

    expect(await store.purgeUndecryptableCredentials()).toBe(0)
    expect(deleted).toEqual([])
  })

  it('counts a misbound app-key resource apart from undecryptable and deletes nothing', async () => {
    const { remote, deleted } = fakeRemote({ resourceId: 'z6AppReadUnder' })
    const store = new RemoteDirectStore({
      remoteStore: remote,
      ciphers: { appConnections: misboundCipher() }
    })

    expect(await store.listAppKeys()).toEqual([])
    expect(store.integrityAppKeys).toBe(1)
    expect(store.undecryptableAppKeys).toBe(0)
    expect(store.unknownEpochAppKeys).toBe(0)
    expect(store.noEpochKeyAppKeys).toBe(0)

    expect(await store.purgeUndecryptableAppKeys()).toBe(0)
    expect(deleted).toEqual([])
  })
})
