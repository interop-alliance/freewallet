// @vitest-environment node
import { createTar } from 'nanotar'
import { describe, it, expect } from 'vitest'
import { parseImportTarFile } from '../../src/lib/import'
import {
  CredentialJsonFileError,
  CredentialJsonFileTooLargeError
} from '../../src/lib/resolveCredentialJsonFiles'
import { MAX_CREDENTIAL_JSON_FILE_BYTES } from '../../src/app.config'

const minimalVc = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  issuanceDate: '2020-01-01T00:00:00Z',
  credentialSubject: { id: 'did:example:subject' }
}

function tarFile(
  name: string,
  entries: { name: string; data?: string | Uint8Array }[]
): File {
  const data = createTar(
    entries.map(entry => ({
      name: entry.name,
      ...(entry.data !== undefined ? { data: entry.data } : {})
    }))
  )
  return new File([Uint8Array.from(data)], name, { type: 'application/x-tar' })
}

describe('parseImportTarFile', () => {
  it('detects space-only archives', async () => {
    const file = tarFile('space-only.tar', [
      { name: 'space/manifest.json', data: '{}' }
    ])

    await expect(parseImportTarFile(file)).resolves.toEqual({
      hasSpace: true,
      hasCredentials: false,
      credentials: []
    })
  })

  it('extracts credentials from top-level credentials/*.json files', async () => {
    const file = tarFile('credentials-only.tar', [
      {
        name: 'credentials/b.json',
        data: JSON.stringify({
          ...minimalVc,
          credentialSubject: { id: 'did:example:b' }
        })
      },
      { name: 'credentials/a.json', data: JSON.stringify(minimalVc) }
    ])

    const result = await parseImportTarFile(file)

    expect(result).toEqual({
      hasSpace: false,
      hasCredentials: true,
      credentials: [
        expect.objectContaining({
          credentialSubject: { id: 'did:example:subject' }
        }),
        expect.objectContaining({
          credentialSubject: { id: 'did:example:b' }
        })
      ]
    })
  })

  it('handles archives with both space data and credentials', async () => {
    const file = tarFile('full-export.tar', [
      { name: 'space/manifest.json', data: '{}' },
      { name: 'credentials/cred.json', data: JSON.stringify(minimalVc) }
    ])

    const result = await parseImportTarFile(file)

    expect(result.hasSpace).toBe(true)
    expect(result.hasCredentials).toBe(true)
    expect(result.credentials).toHaveLength(1)
  })

  it('returns no recognized layout for unrelated archives', async () => {
    const file = tarFile('empty.tar', [{ name: 'readme.txt', data: 'hello' }])

    await expect(parseImportTarFile(file)).resolves.toEqual({
      hasSpace: false,
      hasCredentials: false,
      credentials: []
    })
  })

  it('ignores nested credential json files', async () => {
    const file = tarFile('nested-credentials.tar', [
      {
        name: 'credentials/nested/deep.json',
        data: JSON.stringify(minimalVc)
      },
      { name: 'credentials/top.json', data: JSON.stringify(minimalVc) }
    ])

    const result = await parseImportTarFile(file)

    expect(result.hasCredentials).toBe(true)
    expect(result.credentials).toHaveLength(1)
    expect(result.credentials[0]).toEqual(
      expect.objectContaining({
        credentialSubject: { id: 'did:example:subject' }
      })
    )
  })

  it('ignores non-json files under credentials/', async () => {
    const file = tarFile('mixed-credentials.tar', [
      { name: 'credentials/readme.txt', data: 'not json' },
      { name: 'credentials/cred.json', data: JSON.stringify(minimalVc) }
    ])

    const result = await parseImportTarFile(file)

    expect(result.credentials).toHaveLength(1)
  })

  it('extracts credentials from verifiable presentations', async () => {
    const file = tarFile('vp.tar', [
      {
        name: 'credentials/presentation.json',
        data: JSON.stringify({
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiablePresentation'],
          verifiableCredential: [
            minimalVc,
            {
              ...minimalVc,
              credentialSubject: { id: 'did:example:second' }
            }
          ]
        })
      }
    ])

    const result = await parseImportTarFile(file)

    expect(result.credentials).toHaveLength(2)
  })

  it('rejects credential files above the size limit', async () => {
    const oversized = 'x'.repeat(MAX_CREDENTIAL_JSON_FILE_BYTES + 1)
    const file = tarFile('oversized.tar', [
      { name: 'credentials/huge.json', data: oversized }
    ])

    await expect(parseImportTarFile(file)).rejects.toBeInstanceOf(
      CredentialJsonFileTooLargeError
    )
  })

  it('wraps invalid credential json in CredentialJsonFileError', async () => {
    const file = tarFile('invalid-json.tar', [
      { name: 'credentials/broken.json', data: '{not json' }
    ])

    await expect(parseImportTarFile(file)).rejects.toBeInstanceOf(
      CredentialJsonFileError
    )
  })

  it('wraps non-credential json in CredentialJsonFileError', async () => {
    const file = tarFile('not-a-vc.tar', [
      { name: 'credentials/object.json', data: JSON.stringify({ foo: 'bar' }) }
    ])

    await expect(parseImportTarFile(file)).rejects.toBeInstanceOf(
      CredentialJsonFileError
    )
  })
})
