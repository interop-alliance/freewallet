import type {
  IVerifiableCredential,
  IAlignment,
  IAchievement
} from '@interop/data-integrity-core'
import { getSubject } from '@/lib/viewMappers/getSubject'
import { typeArray } from '@/lib/vcShape'

export type SubjectRecord = Record<string, unknown>

export function asRecord(value: unknown): SubjectRecord | undefined {
  if (!value || typeof value !== 'object') {
    return undefined
  }
  return value as SubjectRecord
}

export function getTrimmedString(value: unknown): string {
  if (typeof value !== 'string') {
    return ''
  }
  return value.trim()
}

/**
 * Resolves a display name from a subject's person/contact structure.
 * Shared between `extractIssuedTo` (credential detail) and
 * `contactFromSubject` (resume preview mapper).
 */
export function resolvePersonFullName(subject: SubjectRecord): string {
  const person = asRecord(subject.person)
  const contact = asRecord(person?.contact)

  const contactFullName = getTrimmedString(contact?.fullName)
  if (contactFullName) {
    return contactFullName
  }

  const personName = getTrimmedString(person?.name)
  if (personName) {
    return personName
  }

  const personNameRecord = asRecord(person?.name)
  if (personNameRecord) {
    const formattedName = getTrimmedString(personNameRecord.formattedName)
    if (formattedName) {
      return formattedName
    }

    const fallbackPersonName = getTrimmedString(personNameRecord.name)
    if (fallbackPersonName) {
      return fallbackPersonName
    }
  }

  return getTrimmedString(subject.name)
}

export function achievementsList(subject: SubjectRecord): SubjectRecord[] {
  const achievementRaw = subject.achievement
  if (achievementRaw == null) {
    return []
  }
  if (Array.isArray(achievementRaw)) {
    return achievementRaw as SubjectRecord[]
  }
  return [achievementRaw as SubjectRecord]
}

export function skillsList(subject: SubjectRecord): SubjectRecord[] {
  const skillRaw = subject.skill
  if (skillRaw == null) {
    return []
  }
  if (Array.isArray(skillRaw)) {
    return skillRaw as SubjectRecord[]
  }
  return [skillRaw as SubjectRecord]
}

export function getSkillImage(skills: SubjectRecord[]): string {
  if (!skills.length) {
    return ''
  }
  const image = asRecord(skills[0].image)
  if (image) {
    return getTrimmedString(image.id)
  }
  return getTrimmedString(skills[0].image as string)
}

const IMAGE_EXTENSION_RE = /\.(jpe?g|png|gif|webp|svg|avif)(\?|$)/i

export function getEvidenceImage(evidence: unknown[]): string {
  for (const ev of evidence) {
    const item = asRecord(ev)
    if (!item) {
      continue
    }
    const id = getTrimmedString(item.id)
    const name = getTrimmedString(item.name)
    if (id && (IMAGE_EXTENSION_RE.test(id) || IMAGE_EXTENSION_RE.test(name))) {
      return id
    }
  }
  return ''
}

export function extractIssuedTo(
  verifiableCredential: IVerifiableCredential
): string {
  const subject = asRecord(getSubject(verifiableCredential))
  if (!subject) {
    return getTrimmedString((verifiableCredential as { name?: string }).name)
  }

  const resolvedName = resolvePersonFullName(subject)
  if (resolvedName) {
    return resolvedName
  }

  if (Array.isArray(subject.identifier)) {
    const nameEntry = subject.identifier.find(
      (identifier: {
        identityType?: string
        type?: string
        identityHash?: string
      }) => identifier?.identityType === 'name' || identifier?.type === 'name'
    ) as { identityHash?: string } | undefined
    if (nameEntry?.identityHash) {
      return nameEntry.identityHash
    }
  }

  return getTrimmedString((verifiableCredential as { name?: string }).name)
}

export function credentialNameFrom(
  verifiableCredential: IVerifiableCredential,
  subject: SubjectRecord
): string {
  const topLevelName = getTrimmedString(
    (verifiableCredential as { name?: string }).name
  )
  if (topLevelName) {
    return topLevelName
  }

  const achievements = achievementsList(subject)
  const achievementNames = achievements
    .map(achievement => getTrimmedString(achievement.name))
    .filter((name): name is string => Boolean(name))
  if (achievementNames.length > 1) {
    return achievementNames.join(' · ')
  }
  if (achievementNames.length === 1) {
    return achievementNames[0]
  }

  const skills = skillsList(subject)
  const skillNames = skills
    .map(skill => getTrimmedString(skill.name))
    .filter((name): name is string => Boolean(name))
  if (skillNames.length > 1) {
    return skillNames.join(' · ')
  }
  if (skillNames.length === 1) {
    return skillNames[0]
  }

  const resumeFullName = resolvePersonFullName(subject)
  if (resumeFullName) {
    return resumeFullName
  }

  const hasCredential = asRecord(subject.hasCredential)
  const hasCredentialName = getTrimmedString(hasCredential?.name)
  if (hasCredentialName) {
    return hasCredentialName
  }

  const vcTypes = typeArray(verifiableCredential.type)
  if (vcTypes.includes('SkillClaimCredential')) {
    return 'Skill Claim'
  }

  return 'Verifiable Credential'
}

export function buildCredentialDescription(
  subject: SubjectRecord,
  achievements: SubjectRecord[]
): string {
  const descriptionParts: string[] = []

  for (const achievement of achievements) {
    const achievementDescription = getTrimmedString(achievement.description)
    if (achievementDescription) {
      descriptionParts.push(achievementDescription)
    }
  }

  for (const skill of skillsList(subject)) {
    const narrative = getTrimmedString(skill.narrative)
    if (narrative) {
      descriptionParts.push(narrative)
    }
    const duration = getTrimmedString(skill.durationPerformed)
    if (duration) {
      descriptionParts.push(`Duration: ${duration}`)
    }
  }

  const subjectNarrative = getTrimmedString(subject.narrative)
  if (subjectNarrative) {
    descriptionParts.push(subjectNarrative)
  }

  const evidenceDescription = getTrimmedString(subject.evidenceDescription)
  if (evidenceDescription) {
    descriptionParts.push(evidenceDescription)
  }

  const duration = getTrimmedString(subject.duration)
  if (duration) {
    descriptionParts.push(`Duration: ${duration}`)
  }

  const evidenceLink = getTrimmedString(subject.evidenceLink)
  if (evidenceLink) {
    descriptionParts.push(`Evidence: ${evidenceLink}`)
  }

  const subjectDescription = getTrimmedString(subject.description)
  if (subjectDescription) {
    descriptionParts.push(subjectDescription)
  }

  const hasCredential = asRecord(subject.hasCredential)
  const hasCredentialDescription = getTrimmedString(hasCredential?.description)
  if (hasCredentialDescription) {
    descriptionParts.push(hasCredentialDescription)
  }

  return descriptionParts.join('\n\n')
}

export function buildCriteria(
  subject: SubjectRecord,
  achievements: SubjectRecord[]
): string {
  const criteriaBlocks = achievements
    .map(achievement => {
      const criteria = asRecord(achievement.criteria)
      const narrative = getTrimmedString(criteria?.narrative)
      if (!narrative) {
        return ''
      }

      const achievementName = getTrimmedString(achievement.name)
      if (achievements.length > 1 && achievementName) {
        return `**${achievementName}**\n\n${narrative}`
      }
      return narrative
    })
    .filter((criteriaBlock): criteriaBlock is string => Boolean(criteriaBlock))
  const criteriaText = criteriaBlocks.join('\n\n')
  if (criteriaText) {
    return criteriaText
  }

  const hasCredential = asRecord(subject.hasCredential)
  return getTrimmedString(hasCredential?.competencyRequired)
}

export function getAchievementImage(primaryAchievement?: IAchievement): string {
  if (!primaryAchievement?.image) {
    return ''
  }
  if (typeof primaryAchievement.image === 'string') {
    return primaryAchievement.image
  }
  return primaryAchievement.image.id ?? ''
}

export function getAchievementType(primaryAchievement?: IAchievement): string {
  if (typeof primaryAchievement?.achievementType === 'string') {
    return primaryAchievement.achievementType
  }
  return ''
}

export function normalizeAlignments(rawAlignments: unknown): IAlignment[] {
  if (!rawAlignments) {
    return []
  }

  const alignmentArray: unknown[] = Array.isArray(rawAlignments)
    ? rawAlignments
    : [rawAlignments]

  return alignmentArray
    .map((alignmentField: unknown) => {
      const normalizedField = asRecord(alignmentField) ?? {}
      return {
        targetName: String(normalizedField.targetName ?? '').trim(),
        targetUrl: String(normalizedField.targetUrl ?? '').trim(),
        targetDescription: String(
          normalizedField.targetDescription ?? ''
        ).trim()
      }
    })
    .filter((alignmentField: IAlignment) => Boolean(alignmentField.targetName))
}
