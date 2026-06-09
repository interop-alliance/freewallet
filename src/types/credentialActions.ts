/**
 * Public-link controls passed from the credential detail page into the
 * presentation component.
 */
export interface CredentialShareActions {
  isShared: boolean
  publicLink: string | null
  busy: boolean
  toggle: () => void
}

/**
 * Optional page-level actions for a credential detail view (delete + share).
 */
export interface CredentialDetailActions {
  onDelete?: () => void
  share?: CredentialShareActions
}
