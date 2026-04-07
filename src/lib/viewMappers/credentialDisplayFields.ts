import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import type { CredentialDisplayFields } from '@/types/credential'
import { getExpirationDateIso } from '@/lib/viewMappers/formatDate'
import { getSubject } from '@/lib/viewMappers/getSubject'
import {
  asRecord,
  extractIssuedTo,
  achievementsList,
  type AchievementRecord,
  normalizeAlignments,
  getAchievementImage,
  getAchievementType,
  buildCredentialDescription,
  buildCriteria,
  credentialNameFrom
} from '@/lib/viewMappers/displayFieldsHelpers'
export function getDisplayFields(
  verifiableCredential: IVerifiableCredential
): CredentialDisplayFields {
  const commonFields = {
    issuedTo: extractIssuedTo(verifiableCredential),
    expirationDate: getExpirationDateIso(verifiableCredential) ?? ''
  }

  const subject = asRecord(getSubject(verifiableCredential))
  if (!subject) {
    return {
      ...commonFields,
      credentialName: credentialNameFrom(verifiableCredential, {}),
      credentialDescription: '',
      criteria: '',
      achievementImage: '',
      achievementType: '',
      alignments: []
    }
  }

  const achievements = achievementsList(subject)
  const primaryAchievement = achievements[0] as AchievementRecord | undefined
  const alignments = achievements.flatMap(achievement =>
    normalizeAlignments((achievement as { alignment?: unknown }).alignment)
  )

  return {
    ...commonFields,
    credentialName: credentialNameFrom(verifiableCredential, subject),
    credentialDescription: buildCredentialDescription(subject, achievements),
    criteria: buildCriteria(subject, achievements),
    achievementImage: getAchievementImage(primaryAchievement),
    achievementType: getAchievementType(primaryAchievement),
    alignments
  }
}
