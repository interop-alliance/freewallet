import type { ContactData } from '@interop/social-core'

/**
 * Seeded into every new wallet's contacts collection at signup, alongside
 * {@link selfContact}. Static since the Interop Alliance Team's DID does not
 * depend on the signing-up user.
 */
export const interopAllianceTeamContact: ContactData = {
  displayName: 'Interop Alliance Team',
  phoneNumbers: [],
  emailAddresses: [],
  urlAddresses: [{ label: 'did', url: 'did:web:interopalliance.org' }]
}

/**
 * A self-contact seeded at signup, carrying the did:web / did:webvh DIDs
 * `ensureUserCollections` just minted for this user, plus the email entered
 * on the signup email step, when there is one. The DIDs are omitted for
 * guests, without a KMS/WAS server, or when provisioning failed; the email is
 * omitted for guests (whose session email is an internal placeholder, never
 * user-entered) and whenever the user left the signup email step blank.
 */
export function selfContact({
  didWeb,
  didWebvh,
  email
}: {
  didWeb?: string
  didWebvh?: string
  email?: string
}): ContactData {
  const urlAddresses = [
    ...(didWeb ? [{ label: 'did', url: didWeb }] : []),
    ...(didWebvh ? [{ label: 'did', url: didWebvh }] : [])
  ]
  return {
    displayName: 'You (this user)',
    phoneNumbers: [],
    emailAddresses: email ? [{ label: '', email }] : [],
    urlAddresses: urlAddresses.length > 0 ? urlAddresses : undefined
  }
}
