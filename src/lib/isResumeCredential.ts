import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { getSubject } from '@/lib/viewMappers/getSubject'

export function isResumeCredential(vc: IVerifiableCredential): boolean {
  const subject = getSubject(vc)
  return subject.type === 'Resume'
}
