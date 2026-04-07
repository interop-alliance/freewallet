export type ResumeExperienceRow = {
  id: string
  title: string
  company?: string
  duration?: string
  description?: string
}

export type ResumeAffiliationRow = {
  id: string
  title: string
  duration?: string
}

export type ResumeEducationRow = {
  id: string
  title: string
  dates?: string
  description?: string
}

export type ResumePreviewModel = {
  fullName: string
  city?: string
  email?: string
  phone?: string
  summary: string
  experience: ResumeExperienceRow[]
  education: ResumeEducationRow[]
  skills: string[]
  affiliations: ResumeAffiliationRow[]
}
