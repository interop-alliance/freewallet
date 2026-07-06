import { describe, expect, it } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import {
  asRecord,
  getTrimmedString,
  resolvePersonFullName,
  achievementsList,
  skillsList,
  getSkillImage,
  getEvidenceImage,
  extractIssuedTo,
  credentialNameFrom,
  buildCredentialDescription,
  buildCriteria,
  getAchievementImage,
  getAchievementType,
  normalizeAlignments
} from '@/lib/viewMappers/displayFieldsHelpers'

describe('asRecord', () => {
  it('returns the value for a plain object', () => {
    const value = { a: 1 }
    expect(asRecord(value)).toBe(value)
  })

  it('returns undefined for null, primitives, and missing values', () => {
    expect(asRecord(null)).toBeUndefined()
    expect(asRecord(undefined)).toBeUndefined()
    expect(asRecord('string')).toBeUndefined()
    expect(asRecord(42)).toBeUndefined()
  })
})

describe('getTrimmedString', () => {
  it('trims a string value', () => {
    expect(getTrimmedString('  hi  ')).toBe('hi')
  })

  it('returns an empty string for non-string values', () => {
    expect(getTrimmedString(42)).toBe('')
    expect(getTrimmedString(undefined)).toBe('')
    expect(getTrimmedString({})).toBe('')
  })
})

describe('resolvePersonFullName', () => {
  it('prefers the nested contact fullName', () => {
    const subject = {
      person: { contact: { fullName: 'Ada Lovelace' }, name: 'ignored' }
    }
    expect(resolvePersonFullName(subject)).toBe('Ada Lovelace')
  })

  it('falls back to a string person name', () => {
    expect(resolvePersonFullName({ person: { name: 'Grace Hopper' } })).toBe(
      'Grace Hopper'
    )
  })

  it('reads formattedName from an object person name', () => {
    const subject = { person: { name: { formattedName: 'Alan Turing' } } }
    expect(resolvePersonFullName(subject)).toBe('Alan Turing')
  })

  it('falls back to the subject name when there is no person', () => {
    expect(resolvePersonFullName({ name: 'Katherine Johnson' })).toBe(
      'Katherine Johnson'
    )
  })

  it('returns an empty string when no name is present', () => {
    expect(resolvePersonFullName({})).toBe('')
  })
})

describe('achievementsList', () => {
  it('wraps a single achievement object in an array', () => {
    expect(achievementsList({ achievement: { name: 'Badge' } })).toEqual([
      { name: 'Badge' }
    ])
  })

  it('returns an achievement array unchanged', () => {
    const list = [{ name: 'One' }, { name: 'Two' }]
    expect(achievementsList({ achievement: list })).toEqual(list)
  })

  it('returns an empty array when there is no achievement', () => {
    expect(achievementsList({})).toEqual([])
  })
})

describe('skillsList', () => {
  it('wraps a single skill object in an array', () => {
    expect(skillsList({ skill: { name: 'Welding' } })).toEqual([
      { name: 'Welding' }
    ])
  })

  it('returns an empty array when there is no skill', () => {
    expect(skillsList({})).toEqual([])
  })
})

describe('getSkillImage', () => {
  it('reads the id from an object image on the first skill', () => {
    expect(getSkillImage([{ image: { id: 'https://img/skill.png' } }])).toBe(
      'https://img/skill.png'
    )
  })

  it('reads a string image on the first skill', () => {
    expect(getSkillImage([{ image: 'https://img/skill.png' }])).toBe(
      'https://img/skill.png'
    )
  })

  it('returns an empty string for an empty skill list', () => {
    expect(getSkillImage([])).toBe('')
  })
})

describe('getEvidenceImage', () => {
  it('returns the id of the first evidence item that looks like an image', () => {
    const evidence = [
      { id: 'https://example.com/doc', name: 'A document' },
      { id: 'https://example.com/photo.png', name: 'A photo' }
    ]
    expect(getEvidenceImage(evidence)).toBe('https://example.com/photo.png')
  })

  it('matches on an image-like name even when the id has no extension', () => {
    const evidence = [{ id: 'https://example.com/x', name: 'shot.jpg' }]
    expect(getEvidenceImage(evidence)).toBe('https://example.com/x')
  })

  it('returns an empty string when no evidence looks like an image', () => {
    expect(getEvidenceImage([{ id: 'https://example.com/doc' }])).toBe('')
  })
})

describe('extractIssuedTo', () => {
  it('resolves the recipient full name from the subject person', () => {
    const vc = {
      credentialSubject: { person: { contact: { fullName: 'Ada Lovelace' } } }
    } as unknown as IVerifiableCredential
    expect(extractIssuedTo(vc)).toBe('Ada Lovelace')
  })

  it('reads a name identity hash entry when no person name exists', () => {
    const vc = {
      credentialSubject: {
        identifier: [
          { identityType: 'email', identityHash: 'a@b.co' },
          { identityType: 'name', identityHash: 'Grace Hopper' }
        ]
      }
    } as unknown as IVerifiableCredential
    expect(extractIssuedTo(vc)).toBe('Grace Hopper')
  })

  it('falls back to the top-level credential name when there is no subject', () => {
    const vc = {
      name: 'A Credential',
      credentialSubject: undefined
    } as unknown as IVerifiableCredential
    expect(extractIssuedTo(vc)).toBe('A Credential')
  })
})

describe('credentialNameFrom', () => {
  it('prefers the top-level credential name', () => {
    const vc = { name: 'Top Name' } as unknown as IVerifiableCredential
    expect(credentialNameFrom(vc, { achievement: { name: 'Badge' } })).toBe(
      'Top Name'
    )
  })

  it('joins multiple achievement names with a separator', () => {
    const vc = {} as IVerifiableCredential
    const subject = { achievement: [{ name: 'One' }, { name: 'Two' }] }
    expect(credentialNameFrom(vc, subject)).toBe('One · Two')
  })

  it('uses a single achievement name', () => {
    const vc = {} as IVerifiableCredential
    expect(
      credentialNameFrom(vc, { achievement: { name: 'Solo Badge' } })
    ).toBe('Solo Badge')
  })

  it('labels a SkillClaimCredential when nothing else names it', () => {
    const vc = {
      type: ['VerifiableCredential', 'SkillClaimCredential']
    } as unknown as IVerifiableCredential
    expect(credentialNameFrom(vc, {})).toBe('Skill Claim')
  })

  it('falls back to a generic name', () => {
    const vc = { type: ['VerifiableCredential'] } as IVerifiableCredential
    expect(credentialNameFrom(vc, {})).toBe('Verifiable Credential')
  })
})

describe('buildCredentialDescription', () => {
  it('joins achievement, skill, and subject descriptions into paragraphs', () => {
    const subject = {
      skill: { narrative: 'Skilled worker', durationPerformed: '2 years' },
      description: 'Subject description'
    }
    const achievements = [{ description: 'Achievement description' }]
    expect(buildCredentialDescription(subject, achievements)).toBe(
      'Achievement description\n\nSkilled worker\n\nDuration: 2 years\n\nSubject description'
    )
  })

  it('returns an empty string when there is nothing to describe', () => {
    expect(buildCredentialDescription({}, [])).toBe('')
  })
})

describe('buildCriteria', () => {
  it('returns a single achievement criteria narrative unlabeled', () => {
    const achievements = [{ criteria: { narrative: 'Complete the course' } }]
    expect(buildCriteria({}, achievements)).toBe('Complete the course')
  })

  it('labels criteria blocks when there are multiple achievements', () => {
    const achievements = [
      { name: 'First', criteria: { narrative: 'Do A' } },
      { name: 'Second', criteria: { narrative: 'Do B' } }
    ]
    expect(buildCriteria({}, achievements)).toBe(
      '**First**\n\nDo A\n\n**Second**\n\nDo B'
    )
  })

  it('falls back to hasCredential competencyRequired', () => {
    const subject = { hasCredential: { competencyRequired: 'Pass the exam' } }
    expect(buildCriteria(subject, [])).toBe('Pass the exam')
  })
})

describe('getAchievementImage', () => {
  it('returns a string image directly', () => {
    expect(
      getAchievementImage({ image: 'https://img/badge.png' } as never)
    ).toBe('https://img/badge.png')
  })

  it('reads the id from an object image', () => {
    expect(
      getAchievementImage({ image: { id: 'https://img/badge.png' } } as never)
    ).toBe('https://img/badge.png')
  })

  it('returns an empty string when there is no image', () => {
    expect(getAchievementImage(undefined)).toBe('')
  })
})

describe('getAchievementType', () => {
  it('returns a string achievement type', () => {
    expect(getAchievementType({ achievementType: 'Badge' } as never)).toBe(
      'Badge'
    )
  })

  it('returns an empty string when the type is missing', () => {
    expect(getAchievementType(undefined)).toBe('')
  })
})

describe('normalizeAlignments', () => {
  it('normalizes a single alignment object into an array', () => {
    expect(
      normalizeAlignments({
        targetName: '  CCSS  ',
        targetUrl: 'https://a.co',
        targetDescription: 'desc'
      })
    ).toEqual([
      {
        targetName: 'CCSS',
        targetUrl: 'https://a.co',
        targetDescription: 'desc'
      }
    ])
  })

  it('drops alignments without a target name', () => {
    expect(
      normalizeAlignments([{ targetName: '' }, { targetName: 'HTML' }])
    ).toEqual([{ targetName: 'HTML', targetUrl: '', targetDescription: '' }])
  })

  it('returns an empty array for falsy input', () => {
    expect(normalizeAlignments(undefined)).toEqual([])
  })
})
