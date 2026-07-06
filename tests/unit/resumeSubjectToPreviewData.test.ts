import { describe, expect, it } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { resumeSubjectToPreviewData } from '@/lib/viewMappers/resumeSubjectToPreviewData'

function resumeCredential(
  subject: Record<string, unknown>
): IVerifiableCredential {
  return {
    type: ['VerifiableCredential', 'LERRSCredential'],
    credentialSubject: subject
  } as unknown as IVerifiableCredential
}

describe('resumeSubjectToPreviewData', () => {
  it('maps contact, summary, experience, education, skills, and affiliations', () => {
    const vc = resumeCredential({
      person: {
        contact: {
          fullName: 'Ada Lovelace',
          email: 'ada@example.com',
          phone: '555-0100',
          location: { city: 'London' }
        }
      },
      professionalSummary: '<p>Analytical engine pioneer</p>',
      employmentHistory: [
        {
          position: 'Mathematician',
          company: 'Analytical Society',
          startDate: '1842',
          endDate: '1843',
          description: '<b>Wrote the first algorithm</b>'
        }
      ],
      educationAndLearning: [
        {
          degree: 'BSc',
          programName: 'Mathematics',
          institution: 'Home Tutoring',
          startDate: '1830',
          endDate: '1835'
        }
      ],
      skills: ['Mathematics', { name: 'Logic' }, { skills: 'Programming' }],
      professionalAffiliations: [
        { name: 'Fellow', organization: 'Royal Society' }
      ]
    })

    const model = resumeSubjectToPreviewData(vc)

    expect(model.fullName).toBe('Ada Lovelace')
    expect(model.email).toBe('ada@example.com')
    expect(model.phone).toBe('555-0100')
    expect(model.city).toBe('London')
    expect(model.summary).toBe('Analytical engine pioneer')

    expect(model.experience).toEqual([
      {
        id: 'exp-0',
        title: 'Mathematician',
        company: 'Analytical Society',
        duration: '1842 — 1843',
        description: 'Wrote the first algorithm'
      }
    ])

    expect(model.education).toEqual([
      {
        id: 'edu-0',
        title: 'BSc in Mathematics, Home Tutoring',
        dates: '1830 — 1835',
        description: undefined
      }
    ])

    expect(model.skills).toEqual(['Mathematics', 'Logic', 'Programming'])

    expect(model.affiliations).toEqual([
      { id: 'aff-0', title: 'Fellow of the Royal Society', duration: undefined }
    ])
  })

  it('uses fallbacks when the subject is empty', () => {
    const model = resumeSubjectToPreviewData(resumeCredential({}))
    expect(model).toEqual({
      fullName: 'Resume',
      city: undefined,
      email: undefined,
      phone: undefined,
      summary: '',
      experience: [],
      education: [],
      skills: [],
      affiliations: []
    })
  })

  it('reads the summary narrative from a nested credentialSubject', () => {
    const vc = resumeCredential({
      professionalSummary: {
        credentialSubject: { narrative: '<p>Nested narrative</p>' }
      }
    })
    expect(resumeSubjectToPreviewData(vc).summary).toBe('Nested narrative')
  })

  it('labels an open-ended experience range as Present and uses default titles', () => {
    const vc = resumeCredential({
      employmentHistory: [{ startDate: '2020' }]
    })
    expect(resumeSubjectToPreviewData(vc).experience).toEqual([
      {
        id: 'exp-0',
        title: 'Role',
        company: undefined,
        duration: '2020 — Present',
        description: undefined
      }
    ])
  })
})
