import { describe, it, expect } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { importOutcome, importRefusal } from './import'

const credential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:subject' }
} as IVerifiableCredential

const summary = {
  collectionsCreated: 1,
  collectionsSkipped: 0,
  resourcesCreated: 2,
  resourcesSkipped: 0
}

describe('importRefusal', () => {
  it('refuses an archive with neither Space data nor credentials', () => {
    const archive = { hasSpace: false, hasCredentials: false, credentials: [] }
    expect(importRefusal({ archive, hasRemoteStorage: true })).toBe(
      'unrecognized-archive'
    )
  })

  it('refuses Space data on a session with no remote storage', () => {
    const archive = { hasSpace: true, hasCredentials: false, credentials: [] }
    expect(importRefusal({ archive, hasRemoteStorage: false })).toBe(
      'space-needs-remote'
    )
  })

  it('lets a credentials-only archive through with no remote storage', () => {
    const archive = {
      hasSpace: false,
      hasCredentials: true,
      credentials: [credential]
    }
    expect(importRefusal({ archive, hasRemoteStorage: false })).toBeUndefined()
  })

  it('lets Space data through on a session with remote storage', () => {
    const archive = { hasSpace: true, hasCredentials: true, credentials: [] }
    expect(importRefusal({ archive, hasRemoteStorage: true })).toBeUndefined()
  })
})

describe('importOutcome', () => {
  it('sends parsed credentials to the accept page, with the Space summary', () => {
    const archive = {
      hasSpace: true,
      hasCredentials: true,
      credentials: [credential]
    }
    expect(importOutcome({ archive, spaceSummary: summary })).toEqual({
      kind: 'accept-credentials',
      credentials: [credential],
      spaceSummary: summary
    })
  })

  it('sends parsed credentials to the accept page with no Space summary', () => {
    const archive = {
      hasSpace: false,
      hasCredentials: true,
      credentials: [credential]
    }
    expect(importOutcome({ archive })).toEqual({
      kind: 'accept-credentials',
      credentials: [credential],
      spaceSummary: undefined
    })
  })

  it('reports a Space import with no credentials directory as Space only', () => {
    const archive = { hasSpace: true, hasCredentials: false, credentials: [] }
    expect(importOutcome({ archive, spaceSummary: summary })).toEqual({
      kind: 'space-imported',
      spaceSummary: summary,
      hasCredentials: false
    })
  })

  it('counts a credentials directory that parsed nothing on a Space import', () => {
    const archive = { hasSpace: true, hasCredentials: true, credentials: [] }
    expect(importOutcome({ archive, spaceSummary: summary })).toEqual({
      kind: 'space-imported',
      spaceSummary: summary,
      hasCredentials: true
    })
  })

  it('reports a credentials directory that parsed nothing as credentials only', () => {
    const archive = { hasSpace: false, hasCredentials: true, credentials: [] }
    expect(importOutcome({ archive })).toEqual({ kind: 'credentials-only' })
  })
})
