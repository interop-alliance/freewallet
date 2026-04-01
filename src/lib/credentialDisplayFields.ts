import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import type { AlignmentItem, CredentialDisplayFields } from '@/types/credential'

export function getIssuanceDate(vc: IVerifiableCredential): string {
  return (vc as any).validFrom ?? (vc as any).issuanceDate ?? ''
}

export function getExpirationDate(vc: IVerifiableCredential): string {
  return (vc as any).validUntil ?? (vc as any).expirationDate ?? ''
}

function subject(vc: IVerifiableCredential): any {
  const s = vc.credentialSubject
  return Array.isArray(s) ? s[0] : s
}

function extractIssuedTo(vc: IVerifiableCredential): string {
  const s = subject(vc)
  if (!s) {
    return ''
  }
  if (s.name) {
    return s.name
  }

  if (Array.isArray(s.identifier)) {
    const nameEntry = s.identifier.find(
      (id: any) => id.identityType === 'name' || id.type === 'name'
    )
    if (nameEntry?.identityHash) {
      return nameEntry.identityHash
    }
  }

  return (vc as any).name ?? ''
}

const isOBv3 = (vc: IVerifiableCredential): boolean =>
  Array.isArray(vc.type) &&
  (vc.type.includes('OpenBadgeCredential') ||
    vc.type.includes('AchievementCredential'))

export function getDisplayFields(
  vc: IVerifiableCredential
): CredentialDisplayFields {
  const common = {
    issuedTo: extractIssuedTo(vc),
    issuanceDate: getIssuanceDate(vc),
    expirationDate: getExpirationDate(vc)
  }

  const s = subject(vc)

  if (isOBv3(vc)) {
    const achievement = s?.achievement
    return {
      ...common,
      credentialName:
        achievement?.name ?? (vc as any).name ?? 'Verifiable Credential',
      credentialDescription: achievement?.description ?? '',
      criteria: achievement?.criteria?.narrative ?? '',
      achievementImage: achievement?.image?.id ?? '',
      achievementType: achievement?.achievementType ?? '',
      alignments: normalizeAlignments(achievement?.alignment)
    }
  }

  const hasCredential = s?.hasCredential
  return {
    ...common,
    credentialName:
      hasCredential?.name ?? (vc as any).name ?? 'Verifiable Credential',
    credentialDescription: hasCredential?.description ?? s?.description ?? '',
    criteria: hasCredential?.competencyRequired ?? '',
    achievementImage: '',
    achievementType: '',
    alignments: []
  }
}

function normalizeAlignments(raw: unknown): AlignmentItem[] {
  if (!raw) {
    return []
  }
  const arr = Array.isArray(raw) ? raw : [raw]
  return arr
    .map((a: any) => ({
      targetName: (a?.targetName ?? '').trim(),
      targetUrl: (a?.targetUrl ?? '').trim(),
      targetDescription: (a?.targetDescription ?? '').trim()
    }))
    .filter((a: AlignmentItem) => !!a.targetName)
}

export type { AlignmentItem } from '@/types/credential'
