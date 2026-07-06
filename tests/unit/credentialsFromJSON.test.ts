// @vitest-environment node
/**
 * Unit tests for `src/lib/credentialsFromJSON.ts`: decoding one or more
 * Verifiable Credentials from a JSON string. Covers a single VC object, an
 * array of VCs (with non-credential entries filtered out), a Verifiable
 * Presentation wrapping one or many credentials, and the rejection paths for
 * malformed JSON and non-credential input.
 */
import { describe, expect, it } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { credentialsFromJSON } from '@/lib/credentialsFromJSON'

const minimalVc: IVerifiableCredential = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  issuanceDate: '2020-01-01T00:00:00Z',
  credentialSubject: { id: 'did:example:subject' }
}

function secondVc(): IVerifiableCredential {
  return {
    ...minimalVc,
    credentialSubject: { id: 'did:example:second' }
  }
}

function presentationOf(
  verifiableCredential: IVerifiableCredential | IVerifiableCredential[]
): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    verifiableCredential
  }
}

describe('credentialsFromJSON', () => {
  it('returns a single VC object wrapped in an array', () => {
    const result = credentialsFromJSON(JSON.stringify(minimalVc))

    expect(result).toHaveLength(1)
    expect(result[0]).toEqual(minimalVc)
  })

  it('returns an array of VCs unchanged', () => {
    const credentials = [minimalVc, secondVc()]
    const result = credentialsFromJSON(JSON.stringify(credentials))

    expect(result).toHaveLength(2)
    expect(result).toEqual(credentials)
  })

  it('filters non-credential entries out of an array', () => {
    const input = [minimalVc, { type: ['SomethingElse'] }, { foo: 'bar' }]
    const result = credentialsFromJSON(JSON.stringify(input))

    expect(result).toHaveLength(1)
    expect(result[0]).toEqual(minimalVc)
  })

  it('unwraps a single VC from a Verifiable Presentation', () => {
    const result = credentialsFromJSON(
      JSON.stringify(presentationOf(minimalVc))
    )

    expect(result).toHaveLength(1)
    expect(result[0]).toEqual(minimalVc)
  })

  it('unwraps an array of VCs from a Verifiable Presentation', () => {
    const result = credentialsFromJSON(
      JSON.stringify(presentationOf([minimalVc, secondVc()]))
    )

    expect(result).toHaveLength(2)
    expect(result[0]).toEqual(minimalVc)
    expect(result[1]).toEqual(secondVc())
  })

  it('throws when an array contains no Verifiable Credentials', () => {
    const input = [{ type: ['SomethingElse'] }, { foo: 'bar' }]

    expect(() => credentialsFromJSON(JSON.stringify(input))).toThrow(
      'Array did not contain any Verifiable Credentials.'
    )
  })

  it('throws when the JSON is a plain object that is not a credential', () => {
    expect(() => credentialsFromJSON(JSON.stringify({ foo: 'bar' }))).toThrow(
      'Could not decode Verifiable Credential(s) from the JSON.'
    )
  })

  it('throws when the credential type is a bare string rather than an array', () => {
    // `hasType` only recognizes an array-valued `type`, so a string type is
    // treated as a non-credential and rejected.
    const stringType = { ...minimalVc, type: 'VerifiableCredential' }

    expect(() => credentialsFromJSON(JSON.stringify(stringType))).toThrow(
      'Could not decode Verifiable Credential(s) from the JSON.'
    )
  })

  it('throws on malformed JSON input', () => {
    expect(() => credentialsFromJSON('{not valid json')).toThrow()
  })

  it('throws on a JSON null literal', () => {
    expect(() => credentialsFromJSON('null')).toThrow(
      'Could not decode Verifiable Credential(s) from the JSON.'
    )
  })

  it('rejects a presentation that lacks the VerifiablePresentation type', () => {
    // Without the `VerifiablePresentation` type the wrapper is not recognized;
    // the object itself is not a credential either, so it is rejected.
    const untypedWrapper = {
      type: ['SomeWrapper'],
      verifiableCredential: minimalVc
    }

    expect(() => credentialsFromJSON(JSON.stringify(untypedWrapper))).toThrow(
      'Could not decode Verifiable Credential(s) from the JSON.'
    )
  })
})
