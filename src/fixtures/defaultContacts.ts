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
 * Convergence-critical: every replica seeds these rows under its own fresh
 * random id, so a wallet linking into an established space pulls the space's
 * copies alongside its own, and the pull path recognizes a pulled seed by its
 * EXACT display name. The two wallets must therefore hold these strings
 * byte-for-byte identically -- 'Interop Alliance Team' and
 * 'did:web:interopalliance.org'. A drift of one character duplicates both
 * seeds on every install, forever. The self seed's name is the one that does
 * NOT need retyping: it belongs to the generic `selfContact`, so social-core
 * exports it and this list references it.
 */
import {
  normalizeContact,
  SELF_CONTACT_NAME,
  type ContactData
} from '@interop/social-core'

const INTEROP_ALLIANCE_TEAM_NAME = 'Interop Alliance Team'

/**
 * The display names of the default contacts, in seeding order -- the strings a
 * pull path matches on to absorb another replica's copy of a seed instead of
 * inserting a duplicate.
 */
export const DEFAULT_CONTACT_NAMES: string[] = [
  INTEROP_ALLIANCE_TEAM_NAME,
  SELF_CONTACT_NAME
]

/**
 * Runs a seed literal through `normalizeContact`, so the stored row has the
 * exact shape every other write path produces (e.g. `phoneNumbers` /
 * `emailAddresses` always present as `[]`) -- a consumer must never meet a
 * looser shape on this row than on any imported or hand-entered one, and an
 * unchanged save (or a merge from the other replica) must not rewrite the row
 * and churn a revision.
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
