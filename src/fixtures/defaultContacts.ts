/**
 * The contacts every new wallet seeds itself with.
 *
 * These live here rather than in `@interop/social-core` on purpose: the
 * package is team-neutral, and "Interop Alliance Team" is this product's seed,
 * not a property of the contacts data model. The generic half -- `selfContact`,
 * which carries whatever DIDs and email the caller minted -- does come from
 * social-core.
 *
 * The duplication with the mobile wallet is deliberate and load-bearing.
 * Convergence-critical: every replica seeds these contacts under its own fresh
 * random id, so a wallet linking into an established space pulls the space's
 * copies alongside its own, and the pull path recognizes a pulled seed by its
 * EXACT display name. The two wallets must therefore hold these strings
 * byte-for-byte identically -- 'Interop Alliance Team' and
 * 'did:web:interopalliance.org'. A drift of one character duplicates both
 * seeds on every install, forever.
 */
import {
  SELF_CONTACT_NAME,
  normalizeContact,
  type ContactData
} from '@interop/social-core'

const INTEROP_ALLIANCE_TEAM_NAME = 'Interop Alliance Team'

/**
 * Runs a seed literal through `normalizeContact`, so the stored contact has the
 * exact shape every other write path produces (e.g. `phoneNumbers` /
 * `emailAddresses` always present as `[]`) -- a consumer must never meet a
 * looser shape on this contact than on any imported or hand-entered one, and an
 * unchanged save (or a merge from the other replica) must not rewrite the
 * contact and churn a revision.
 *
 * @param contact {ContactData}
 * @returns {ContactData}
 */
function normalizedSeed(contact: ContactData): ContactData {
  const normalized = normalizeContact(contact)
  if (normalized === null) {
    throw new Error(
      `Default contact "${contact.displayName}" failed normalization.`
    )
  }
  return normalized
}

/**
 * Seeded into every new wallet's contacts collection at signup, alongside the
 * self-contact. Static since the Interop Alliance Team's DID does not depend
 * on the user signing up.
 */
export const interopAllianceTeamContact: ContactData = normalizedSeed({
  displayName: INTEROP_ALLIANCE_TEAM_NAME,
  urlAddresses: [{ label: 'did', url: 'did:web:interopalliance.org' }]
})

/**
 * The display names of the contacts this wallet seeds itself with -- the
 * `seedNames` argument social-core's `isUnlinkedSeedTwin` matches on. A
 * migrated contact carrying one of these names is the bundle's copy of a seed
 * the new account already planted, so it is skipped rather than landing beside
 * it (unless the local contact has been customized, which disqualifies the
 * match).
 */
export const SEED_CONTACT_NAMES: string[] = [
  INTEROP_ALLIANCE_TEAM_NAME,
  SELF_CONTACT_NAME
]
