import { getVerifyLogFromPayload } from '@/lib/viewMappers/verifyLog'

export interface MatchingIssuerEntry {
  registry?: {
    federation_entity?: {
      organization_name?: string
      policy_uri?: string
    }
  }
  issuer?: {
    federation_entity?: {
      organization_name?: string
      homepage_uri?: string
      logo_uri?: string | { id?: string }
    }
    institution_additional_information?: {
      legal_name?: string
    }
    credential_registry_entity?: {
      ce_url?: string
    }
  }
}

export interface IssuerRegistryInfo {
  matchingIssuers: MatchingIssuerEntry[]
}

export function getRegistryNames(matchingIssuers: MatchingIssuerEntry[]): string[] {
  const names = matchingIssuers
    .map(
      entry => entry.registry?.federation_entity?.organization_name?.trim() ?? ''
    )
    .filter(Boolean)

  return [...new Set(names)]
}

/** Extracts issuer registry matches from a raw `verifyCredential` payload. */
export function issuerRegistryInfoFromVerifyPayload(
  raw: Record<string, unknown> | null | undefined
): IssuerRegistryInfo | null {
  if (!raw) {
    return null
  }

  const registeredIssuer = getVerifyLogFromPayload(raw).find(
    entry => entry.id === 'registered_issuer'
  ) as { matchingIssuers?: MatchingIssuerEntry[] } | undefined

  if (!registeredIssuer) {
    return null
  }

  return {
    matchingIssuers: registeredIssuer.matchingIssuers ?? []
  }
}

export function isRecognizedIssuer(
  registryInfo: IssuerRegistryInfo | null | undefined
): boolean {
  return (registryInfo?.matchingIssuers.length ?? 0) > 0
}
