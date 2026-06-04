import { describe, expect, it } from 'vitest'
import {
  getRegistryNames,
  issuerRegistryInfoFromVerifyPayload,
  isRecognizedIssuer
} from '@/lib/viewMappers/issuerRegistryInfo'

describe('issuerRegistryInfo', () => {
  it('derives registry names from matching issuers', () => {
    expect(
      getRegistryNames([
        {
          registry: {
            federation_entity: { organization_name: 'DCC Member Registry' }
          }
        },
        {
          registry: {
            federation_entity: { organization_name: 'DCC Community Registry' }
          }
        }
      ])
    ).toEqual(['DCC Member Registry', 'DCC Community Registry'])
  })

  it('extracts issuer registry info from verifier-core payload shape', () => {
    const info = issuerRegistryInfoFromVerifyPayload({
      log: [
        {
          id: 'registered_issuer',
          valid: true,
          matchingIssuers: [
            {
              registry: {
                federation_entity: { organization_name: 'DCC Member Registry' }
              },
              issuer: {
                federation_entity: {
                  organization_name: 'Digital Credentials Consortium',
                  homepage_uri: 'https://digitalcredentials.mit.edu/'
                }
              }
            },
            {
              registry: {
                federation_entity: {
                  organization_name: 'DCC Community Registry'
                }
              }
            }
          ]
        }
      ]
    })

    expect(info?.matchingIssuers).toHaveLength(2)
    expect(getRegistryNames(info?.matchingIssuers ?? [])).toEqual([
      'DCC Member Registry',
      'DCC Community Registry'
    ])
    expect(isRecognizedIssuer(info)).toBe(true)
  })

  it('treats empty matchingIssuers as unrecognized', () => {
    const info = issuerRegistryInfoFromVerifyPayload({
      log: [{ id: 'registered_issuer', valid: false, matchingIssuers: [] }]
    })

    expect(getRegistryNames(info?.matchingIssuers ?? [])).toEqual([])
    expect(isRecognizedIssuer(info)).toBe(false)
  })
})
