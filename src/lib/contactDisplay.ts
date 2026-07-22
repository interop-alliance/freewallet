/**
 * Display helpers shared by the contacts list/detail pages.
 */
import type { ContactData } from '@interop/social-core'

/**
 * Builds up-to-two-letter initials from a display name (contact photos are not
 * stored).
 */
export function initialsFor(displayName: string): string {
  const parts = displayName.trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) {
    return '?'
  }
  if (parts.length === 1) {
    return parts[0].charAt(0).toUpperCase()
  }
  return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase()
}

/**
 * The single line shown under the name: organization, else first phone/email.
 */
export function secondaryLineFor(contact: ContactData): string {
  if (contact.organization) {
    return contact.organization
  }
  if (contact.phoneNumbers.length > 0) {
    return contact.phoneNumbers[0].number
  }
  if (contact.emailAddresses.length > 0) {
    return contact.emailAddresses[0].email
  }
  return ''
}
