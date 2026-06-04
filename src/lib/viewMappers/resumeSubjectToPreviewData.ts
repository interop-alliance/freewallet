import { getSubject } from '@/lib/viewMappers/getSubject'
import { htmlToPlainText } from '@/lib/viewMappers/htmlToPlainText'
import {
  asRecord,
  getTrimmedString,
  resolvePersonFullName,
  type SubjectRecord
} from '@/lib/viewMappers/displayFieldsHelpers'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type {
  ResumeAffiliationRow,
  ResumeEducationRow,
  ResumeExperienceRow,
  ResumePreviewModel
} from '@/types/resume'

function pickStr(obj: unknown, keys: string[]): string | undefined {
  if (!obj || typeof obj !== 'object') {
    return undefined
  }
  const record = obj as Record<string, unknown>
  for (const key of keys) {
    const value = record[key]
    if (typeof value === 'string' && value.trim()) {
      return value.trim()
    }
  }
  return undefined
}

function summaryFromProfessionalSummary(professionalSummary: unknown): string {
  if (professionalSummary == null) {
    return ''
  }
  if (typeof professionalSummary === 'string') {
    return htmlToPlainText(professionalSummary)
  }
  if (typeof professionalSummary !== 'object') {
    return ''
  }
  const record = professionalSummary as Record<string, unknown>
  const credentialSubject = record.credentialSubject as
    | Record<string, unknown>
    | undefined
  if (typeof credentialSubject?.narrative === 'string') {
    return htmlToPlainText(credentialSubject.narrative)
  }
  if (typeof record.narrative === 'string') {
    return htmlToPlainText(record.narrative)
  }
  return ''
}

function formatRange(start?: string, end?: string): string | undefined {
  if (!start && !end) {
    return undefined
  }
  const endLabel = end?.trim() || 'Present'
  if (start?.trim()) {
    return `${start.trim()} — ${endLabel}`
  }
  return endLabel
}

function mapExperience(raw: unknown, index: number): ResumeExperienceRow {
  const title =
    pickStr(raw, ['position', 'title', 'role', 'jobTitle', 'name']) ?? 'Role'
  const company = pickStr(raw, [
    'company',
    'organization',
    'organizationName',
    'employer'
  ])
  const duration =
    pickStr(raw, ['duration']) ??
    formatRange(
      pickStr(raw, ['startDate', 'start', 'from']),
      pickStr(raw, ['endDate', 'end', 'to'])
    )
  const rawDescription = pickStr(raw, ['description', 'summary', 'narrative'])
  const descriptionCleaned = rawDescription
    ? htmlToPlainText(rawDescription)
    : ''
  const description =
    descriptionCleaned.length > 0 ? descriptionCleaned : undefined
  const id = pickStr(raw, ['id']) ?? `exp-${index}`
  return { id, title, company, duration, description }
}

function mapEducation(raw: unknown, index: number): ResumeEducationRow {
  const type = pickStr(raw, ['type', 'degree', 'level'])
  const program = pickStr(raw, ['programName', 'program', 'fieldOfStudy'])
  let title: string
  if (type && program) {
    title = `${type} in ${program}`
  } else {
    const byName = pickStr(raw, ['name', 'title'])
    if (type) {
      title = type
    } else if (program) {
      title = program
    } else if (byName) {
      title = byName
    } else {
      title = 'Education'
    }
  }
  const institution = pickStr(raw, ['institution', 'school', 'organization'])
  if (institution && !title.includes(institution)) {
    title = `${title}, ${institution}`
  }
  const dates = formatRange(
    pickStr(raw, ['startDate', 'start']),
    pickStr(raw, ['endDate', 'end'])
  )
  const rawEducationDescription = pickStr(raw, ['description', 'narrative'])
  const educationDescriptionCleaned = rawEducationDescription
    ? htmlToPlainText(rawEducationDescription)
    : ''
  const description =
    educationDescriptionCleaned.length > 0
      ? educationDescriptionCleaned
      : undefined
  const id = pickStr(raw, ['id']) ?? `edu-${index}`
  return { id, title, dates, description }
}

function mapSkill(raw: unknown): string | undefined {
  if (typeof raw === 'string') {
    const cleaned = htmlToPlainText(raw)
    return cleaned.length > 0 ? cleaned : undefined
  }
  if (!raw || typeof raw !== 'object') {
    return undefined
  }
  const record = raw as Record<string, unknown>
  if (typeof record.skills === 'string' && record.skills.trim()) {
    const cleaned = htmlToPlainText(record.skills)
    return cleaned.length > 0 ? cleaned : undefined
  }
  if (typeof record.name === 'string' && record.name.trim()) {
    const cleaned = htmlToPlainText(record.name)
    return cleaned.length > 0 ? cleaned : undefined
  }
  return undefined
}

function mapAffiliation(raw: unknown, index: number): ResumeAffiliationRow {
  const name = pickStr(raw, ['name', 'role', 'title']) ?? 'Affiliation'
  const org = pickStr(raw, ['organization', 'org', 'institution'])
  const title = org ? `${name} of the ${org}` : name
  const duration =
    pickStr(raw, ['duration']) ??
    formatRange(
      pickStr(raw, ['startDate', 'start']),
      pickStr(raw, ['endDate', 'end'])
    )
  const id = pickStr(raw, ['id']) ?? `aff-${index}`
  return { id, title, duration }
}

function contactFromSubject(subject: SubjectRecord): {
  fullName: string
  city?: string
  email?: string
  phone?: string
} {
  const fullName = resolvePersonFullName(subject) || 'Resume'

  const person = asRecord(subject.person)
  const contact = asRecord(person?.contact)
  const location = asRecord(contact?.location)

  const city = getTrimmedString(location?.city) || undefined
  const email = getTrimmedString(contact?.email) || undefined
  const phone = getTrimmedString(contact?.phone) || undefined

  return { fullName, city, email, phone }
}

export function resumeSubjectToPreviewData(
  vc: IVerifiableCredential
): ResumePreviewModel {
  const raw = getSubject(vc)
  let subject: Record<string, unknown> = {}
  if (raw && typeof raw === 'object') {
    subject = raw as Record<string, unknown>
  }
  const contact = contactFromSubject(subject)
  const summary = summaryFromProfessionalSummary(subject.professionalSummary)

  let employmentRaw: unknown[] = []
  if (Array.isArray(subject.employmentHistory)) {
    employmentRaw = subject.employmentHistory
  }
  const experience = employmentRaw
    .filter(Boolean)
    .map((item, index) => mapExperience(item, index))

  let educationRaw: unknown[] = []
  if (Array.isArray(subject.educationAndLearning)) {
    educationRaw = subject.educationAndLearning
  }
  const education = educationRaw
    .filter(Boolean)
    .map((item, index) => mapEducation(item, index))

  let skillsRaw: unknown[] = []
  if (Array.isArray(subject.skills)) {
    skillsRaw = subject.skills
  }
  const skills = skillsRaw
    .map(mapSkill)
    .filter((skill): skill is string => !!skill)

  let affiliationsRaw: unknown[] = []
  if (Array.isArray(subject.professionalAffiliations)) {
    affiliationsRaw = subject.professionalAffiliations
  }
  const affiliations = affiliationsRaw
    .filter(Boolean)
    .map((item, index) => mapAffiliation(item, index))

  return {
    ...contact,
    summary,
    experience,
    education,
    skills,
    affiliations
  }
}
