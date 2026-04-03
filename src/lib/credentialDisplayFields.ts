import type { IVerifiableCredential, IAlignment } from '@digitalcredentials/ssi'
import type { CredentialDisplayFields } from '@/types/credential'
import { getCredentialSubject } from '@/lib/getCredentialSubject'
import { getExpirationDateIso } from '@/lib/formatDate'

function extractIssuedTo(vc: IVerifiableCredential): string {
  const sbj = getCredentialSubject(vc)
  if (!sbj) {
    return ''
  }
  if (sbj.name) {
    return sbj.name
  }

  if (Array.isArray(sbj.identifier)) {
    const nameEntry = sbj.identifier.find(
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
    expirationDate: getExpirationDateIso(vc) ?? ''
  }

  const sbj = getCredentialSubject(vc)

  if (isOBv3(vc)) {
    const achievement = sbj?.achievement
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

  const hasCredential = sbj?.hasCredential
  return {
    ...common,
    credentialName:
      hasCredential?.name ?? (vc as any).name ?? 'Verifiable Credential',
    credentialDescription: hasCredential?.description ?? sbj?.description ?? '',
    criteria: hasCredential?.competencyRequired ?? '',
    achievementImage: '',
    achievementType: '',
    alignments: []
  }
}

function normalizeAlignments(raw: unknown): IAlignment[] {
  if (!raw) {
    return []
  }
  const arr = Array.isArray(raw) ? raw : [raw]
  return arr
    .map((field: any) => ({
      targetName: (field?.targetName ?? '').trim(),
      targetUrl: (field?.targetUrl ?? '').trim(),
      targetDescription: (field?.targetDescription ?? '').trim()
    }))
    .filter((field: IAlignment) => !!field?.targetName)
}
