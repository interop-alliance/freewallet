import type { IVerifiableCredential } from '@digitalcredentials/ssi'
import { getSubject } from '@/lib/viewMappers/getSubject'

export function isResumeCredential(vc: IVerifiableCredential): boolean {
  const subject = getSubject(vc)
  return subject.type === 'Resume'
}
