// @vitest-environment node
/**
 * Unit tests for the session vault envelope (`src/session/vault.ts`):
 * wrapping the vault KAK under a fresh non-extractable AES-GCM key at full
 * login and unwrapping it back into a live KAK on restore. The persistence
 * helpers in `@/lib/sessionKey` are stubbed with an in-memory record pair so
 * these tests exercise vault.ts's own crypto and fail-closed logic. Node's
 * global `crypto.subtle` supplies AES-GCM; the vault KAK is a real
 * `X25519KeyAgreementKey2020`.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'

const CONTROLLER = 'did:key:z6MkTestControllerAAAAAAAAAAAAAAAAAAAAAAAAAA'

/**
 * Builds an in-memory stand-in for the vault-envelope persistence helpers in
 * `@/lib/sessionKey`, mirroring their save/load/delete semantics against a
 * single mutable record pair (an envelope is only "present" when both halves
 * are set, matching the real `loadVaultEnvelope`).
 *
 * @returns {object} the mock functions plus the backing `store`
 */
function createSessionKeyMock() {
  const store: { wrappingKey?: CryptoKey; envelope?: unknown } = {}
  const saveVaultEnvelope = vi.fn(
    async ({
      wrappingKey,
      envelope
    }: {
      wrappingKey: CryptoKey
      envelope: unknown
    }) => {
      store.wrappingKey = wrappingKey
      store.envelope = envelope
    }
  )
  const loadVaultEnvelope = vi.fn(async () => {
    if (
      !store.wrappingKey ||
      store.envelope === undefined ||
      store.envelope === null
    ) {
      return null
    }
    return { wrappingKey: store.wrappingKey, envelope: store.envelope }
  })
  const deleteVaultEnvelope = vi.fn(async () => {
    store.wrappingKey = undefined
    store.envelope = undefined
  })
  return { store, saveVaultEnvelope, loadVaultEnvelope, deleteVaultEnvelope }
}

/**
 * Loads a fresh `@/session/vault` module with the app.config and sessionKey
 * mocks applied. The config values are read at vault.ts import time, so each
 * test resets the module registry and re-imports to vary them.
 *
 * @param options {object}
 * @param [options.config] {Record<string, unknown>}   app.config overrides
 * @param options.sessionKeyMock {ReturnType<typeof createSessionKeyMock>}
 * @returns {Promise<typeof import('@/session/vault')>}
 */
async function loadVault({
  config = {},
  sessionKeyMock
}: {
  config?: Record<string, unknown>
  sessionKeyMock: ReturnType<typeof createSessionKeyMock>
}): Promise<typeof import('@/session/vault')> {
  vi.resetModules()
  vi.doMock('@/app.config', async importOriginal => ({
    ...(await importOriginal<typeof import('@/app.config')>()),
    ...config
  }))
  vi.doMock('@/lib/sessionKey', () => ({
    saveVaultEnvelope: sessionKeyMock.saveVaultEnvelope,
    loadVaultEnvelope: sessionKeyMock.loadVaultEnvelope,
    deleteVaultEnvelope: sessionKeyMock.deleteVaultEnvelope
  }))
  return await import('@/session/vault')
}

afterEach(() => {
  vi.resetModules()
  vi.doUnmock('@/app.config')
  vi.doUnmock('@/lib/sessionKey')
  vi.restoreAllMocks()
})

describe('persistVaultEnvelope / unwrapVaultEnvelope round trip', () => {
  it('unwraps back into a working KAK and a scoped key resolver', async () => {
    const mock = createSessionKeyMock()
    const { persistVaultEnvelope, unwrapVaultEnvelope } = await loadVault({
      sessionKeyMock: mock
    })
    const kak = await X25519KeyAgreementKey2020.generate({
      controller: CONTROLLER
    })

    await persistVaultEnvelope({
      keyAgreementKey: kak as IKeyAgreementKey,
      controller: CONTROLLER
    })
    expect(mock.saveVaultEnvelope).toHaveBeenCalledOnce()

    const result = await unwrapVaultEnvelope({ controller: CONTROLLER })
    expect(result).not.toBeNull()
    const recovered = result!.keyAgreementKey as X25519KeyAgreementKey2020
    expect(recovered.id).toBe(kak.id)
    expect(recovered.publicKeyMultibase).toBe(kak.publicKeyMultibase)

    // The private key material round-tripped: ECDH with the same peer yields
    // the identical shared secret from the original and the recovered KAK.
    const peer = await X25519KeyAgreementKey2020.generate({
      controller: CONTROLLER
    })
    const fromOriginal = await kak.deriveSecret({ publicKey: peer })
    const fromRecovered = await recovered.deriveSecret({ publicKey: peer })
    expect(Array.from(fromRecovered)).toEqual(Array.from(fromOriginal))

    // The resolver resolves the KAK's own id to its public form and rejects
    // any other id.
    const resolver: IKeyResolver = result!.keyResolver
    await expect(resolver({ id: kak.id })).resolves.toMatchObject({
      id: kak.id,
      type: kak.type,
      publicKeyMultibase: kak.publicKeyMultibase
    })
    await expect(resolver({ id: 'did:key:zUnknown' })).rejects.toThrow(
      /Unknown key id/
    )
  })
})

describe('unwrapVaultEnvelope fail-closed behavior', () => {
  it('returns null when nothing is persisted', async () => {
    const mock = createSessionKeyMock()
    const { unwrapVaultEnvelope } = await loadVault({ sessionKeyMock: mock })

    expect(await unwrapVaultEnvelope({ controller: CONTROLLER })).toBeNull()
  })

  it('returns null and deletes the envelope when it is expired', async () => {
    const mock = createSessionKeyMock()
    const { persistVaultEnvelope, unwrapVaultEnvelope } = await loadVault({
      config: { SESSION_VAULT_TTL_MS: -1000 },
      sessionKeyMock: mock
    })
    const kak = await X25519KeyAgreementKey2020.generate({
      controller: CONTROLLER
    })

    await persistVaultEnvelope({
      keyAgreementKey: kak as IKeyAgreementKey,
      controller: CONTROLLER
    })
    expect(mock.store.envelope).toBeDefined()

    expect(await unwrapVaultEnvelope({ controller: CONTROLLER })).toBeNull()
    expect(mock.deleteVaultEnvelope).toHaveBeenCalled()
    expect(mock.store.envelope).toBeUndefined()
  })

  it('returns null and deletes the envelope on a controller mismatch', async () => {
    const mock = createSessionKeyMock()
    const { persistVaultEnvelope, unwrapVaultEnvelope } = await loadVault({
      sessionKeyMock: mock
    })
    const kak = await X25519KeyAgreementKey2020.generate({
      controller: CONTROLLER
    })

    await persistVaultEnvelope({
      keyAgreementKey: kak as IKeyAgreementKey,
      controller: CONTROLLER
    })

    expect(
      await unwrapVaultEnvelope({ controller: 'did:key:z6MkDifferentIdentity' })
    ).toBeNull()
    expect(mock.deleteVaultEnvelope).toHaveBeenCalled()
    expect(mock.store.envelope).toBeUndefined()
  })

  it('returns null and deletes the envelope when the ciphertext is tampered', async () => {
    const mock = createSessionKeyMock()
    const { persistVaultEnvelope, unwrapVaultEnvelope } = await loadVault({
      sessionKeyMock: mock
    })
    const kak = await X25519KeyAgreementKey2020.generate({
      controller: CONTROLLER
    })

    await persistVaultEnvelope({
      keyAgreementKey: kak as IKeyAgreementKey,
      controller: CONTROLLER
    })

    // Flip a byte of the stored ciphertext so AES-GCM authentication fails.
    const envelope = mock.store.envelope as {
      version: number
      iv: Uint8Array
      ciphertext: ArrayBuffer
    }
    const bytes = new Uint8Array(envelope.ciphertext.slice(0))
    bytes[0] ^= 0xff
    mock.store.envelope = { ...envelope, ciphertext: bytes.buffer }

    expect(await unwrapVaultEnvelope({ controller: CONTROLLER })).toBeNull()
    expect(mock.deleteVaultEnvelope).toHaveBeenCalled()
    expect(mock.store.envelope).toBeUndefined()
  })

  it('returns null and deletes the envelope on an unrecognized version', async () => {
    const mock = createSessionKeyMock()
    const { persistVaultEnvelope, unwrapVaultEnvelope } = await loadVault({
      sessionKeyMock: mock
    })
    const kak = await X25519KeyAgreementKey2020.generate({
      controller: CONTROLLER
    })

    await persistVaultEnvelope({
      keyAgreementKey: kak as IKeyAgreementKey,
      controller: CONTROLLER
    })
    const envelope = mock.store.envelope as { version: number }
    mock.store.envelope = { ...envelope, version: 2 }

    expect(await unwrapVaultEnvelope({ controller: CONTROLLER })).toBeNull()
    expect(mock.deleteVaultEnvelope).toHaveBeenCalled()
    expect(mock.store.envelope).toBeUndefined()
  })

  it('returns null and deletes when the stored envelope is garbage', async () => {
    const mock = createSessionKeyMock()
    const { unwrapVaultEnvelope } = await loadVault({ sessionKeyMock: mock })

    // A wrapping key present but an envelope of the wrong shape.
    mock.store.wrappingKey = (await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )) as CryptoKey
    mock.store.envelope = { not: 'an envelope' }

    expect(await unwrapVaultEnvelope({ controller: CONTROLLER })).toBeNull()
    expect(mock.deleteVaultEnvelope).toHaveBeenCalled()
  })
})

describe('persistVaultEnvelope input validation', () => {
  it('throws when the key agreement key is not exportable', async () => {
    const mock = createSessionKeyMock()
    const { persistVaultEnvelope } = await loadVault({ sessionKeyMock: mock })
    const notExportable = {
      id: `${CONTROLLER}#z6LSnotExportable`,
      async deriveSecret() {
        return new Uint8Array()
      }
    } as unknown as IKeyAgreementKey

    await expect(
      persistVaultEnvelope({
        keyAgreementKey: notExportable,
        controller: CONTROLLER
      })
    ).rejects.toThrow(/not exportable/)
    expect(mock.saveVaultEnvelope).not.toHaveBeenCalled()
  })
})

describe('REQUIRE_PASSPHRASE_FOR_VAULT opt-out', () => {
  it('persist deletes any existing envelope and stores nothing', async () => {
    const mock = createSessionKeyMock()
    const { persistVaultEnvelope } = await loadVault({
      config: { REQUIRE_PASSPHRASE_FOR_VAULT: true },
      sessionKeyMock: mock
    })
    const kak = await X25519KeyAgreementKey2020.generate({
      controller: CONTROLLER
    })

    await persistVaultEnvelope({
      keyAgreementKey: kak as IKeyAgreementKey,
      controller: CONTROLLER
    })

    expect(mock.deleteVaultEnvelope).toHaveBeenCalled()
    expect(mock.saveVaultEnvelope).not.toHaveBeenCalled()
  })

  it('unwrap returns null without reading the store', async () => {
    const mock = createSessionKeyMock()
    const { unwrapVaultEnvelope } = await loadVault({
      config: { REQUIRE_PASSPHRASE_FOR_VAULT: true },
      sessionKeyMock: mock
    })

    expect(await unwrapVaultEnvelope({ controller: CONTROLLER })).toBeNull()
    expect(mock.loadVaultEnvelope).not.toHaveBeenCalled()
  })
})
