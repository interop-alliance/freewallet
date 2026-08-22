/**
 * VC display-field helpers moved to `@interop/vc-display` (reconciled
 * with DCW's implementation). Re-exported here so existing
 * `@/lib/viewMappers/displayFieldsHelpers` importers are unaffected.
 */
export {
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
} from '@interop/vc-display'
