// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'
import {
  CredentialJsonFileTooLargeError,
  isJsonCredentialFile,
  resolveCredentialsFromJsonFiles
} from '../src/lib/resolveCredentialJsonFiles'
import { ResolveCredentialsInputError } from '../src/lib/resolveCredentialsInput'
import { MAX_CREDENTIAL_JSON_FILE_BYTES } from '../src/app.config'

const minimalVc = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  issuanceDate: '2020-01-01T00:00:00Z',
  credentialSubject: { id: 'did:example:subject' }
}

function jsonFile(name: string, content: unknown): File {
  return new File([JSON.stringify(content)], name, {
    type: 'application/json'
  })
}

describe('isJsonCredentialFile', () => {
  it('accepts .json extension', () => {
    expect(isJsonCredentialFile(new File(['{}'], 'cred.json'))).toBe(true)
  })

  it('accepts application/json mime type', () => {
    expect(
      isJsonCredentialFile(
        new File(['{}'], 'credential', { type: 'application/json' })
      )
    ).toBe(true)
  })

  it('rejects non-json files', () => {
    expect(
      isJsonCredentialFile(
        new File(['hello'], 'readme.txt', { type: 'text/plain' })
      )
    ).toBe(false)
  })
})

describe('resolveCredentialsFromJsonFiles', () => {
  it('resolves credentials from multiple json files', async () => {
    const files = [
      jsonFile('a.json', minimalVc),
      jsonFile('b.json', { ...minimalVc, credentialSubject: { id: 'b' } })
    ]
    const result = await resolveCredentialsFromJsonFiles(files)
    expect(result).toHaveLength(2)
  })

  it('uses resolveCredentialsInput for each file', async () => {
    const resolveModule = await import('../src/lib/resolveCredentialsInput')
    const spy = vi
      .spyOn(resolveModule, 'resolveCredentialsInput')
      .mockResolvedValue([minimalVc as never])

    await resolveCredentialsFromJsonFiles([jsonFile('one.json', minimalVc)])

    expect(spy).toHaveBeenCalledWith(JSON.stringify(minimalVc))
    spy.mockRestore()
  })

  it('throws invalid_input when no json files are provided', async () => {
    await expect(
      resolveCredentialsFromJsonFiles([
        new File(['x'], 'notes.txt', { type: 'text/plain' })
      ])
    ).rejects.toBeInstanceOf(ResolveCredentialsInputError)
  })

  it('rejects files above the size limit', async () => {
    const file = jsonFile('huge.json', minimalVc)
    Object.defineProperty(file, 'size', {
      value: MAX_CREDENTIAL_JSON_FILE_BYTES + 1
    })

    await expect(
      resolveCredentialsFromJsonFiles([file])
    ).rejects.toBeInstanceOf(CredentialJsonFileTooLargeError)
  })
})
