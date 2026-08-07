/**
 * Small shape helpers for reading the loosely-typed fields of a Verifiable
 * Credential (its `type`, `issuer`, and `credentialSubject.id`). The readers
 * moved to `@interop/data-integrity-core` (shared by the wallet-request and
 * display layers) and are re-exported here so existing `@/lib/vcShape`
 * importers are unaffected; the two predicates below are the wallet-side
 * conventions every self-issued-credential store shares.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { issuerId, subjectId } from '@interop/data-integrity-core/guards'
import type { StoredCredential } from '@/types/credential'

export {
  typeArray,
  issuerId,
  subjectId
} from '@interop/data-integrity-core/guards'

/**
 * Whether a credential is self-issued: it names an issuer, and that issuer is
 * its own subject. The shape every wallet-minted credential (an app key, a
 * Login Credential) has and every planted one must not be allowed to fake.
 *
 * @param credential {IVerifiableCredential}
 * @returns {boolean}
 */
export function isSelfIssued(credential: IVerifiableCredential): boolean {
  const issuer = issuerId(credential.issuer)
  return !!issuer && issuer === subjectId(credential)
}

/**
 * Sort comparator ordering stored credentials latest-first by the
 * `issuanceDate` they state (missing dates sort last).
 *
 * @param first {StoredCredential}
 * @param second {StoredCredential}
 * @returns {number}
 */
export function byIssuanceDateDesc(
  first: StoredCredential,
  second: StoredCredential
): number {
  const firstDate = (first.vc.issuanceDate as string) ?? ''
  const secondDate = (second.vc.issuanceDate as string) ?? ''
  return secondDate.localeCompare(firstDate)
}
