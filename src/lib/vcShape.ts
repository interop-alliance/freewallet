/**
 * Small shape helpers for reading the loosely-typed fields of a Verifiable
 * Credential (its `type`, `issuer`, and `credentialSubject.id`). These moved to
 * `@interop/data-integrity-core` (shared by the wallet-request and display
 * layers); re-exported here so existing `@/lib/vcShape` importers are
 * unaffected.
 */
export {
  typeArray,
  issuerId,
  subjectId
} from '@interop/data-integrity-core/guards'
