import type React from 'react'

export const authStyles = {
  page: {
    minHeight: '100dvh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    px: 2
  },
  pageColumn: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: 4,
    width: '100%'
  },
  /**
   * Top of auth column; language + theme switchers aligned end (right in LTR).
   */
  languageBar: {
    display: 'flex',
    justifyContent: 'flex-end',
    alignItems: 'center',
    gap: 1.5,
    width: '100%',
    mb: 1
  },
  content: {
    width: '100%',
    maxWidth: 480,
    display: 'flex',
    flexDirection: 'column',
    gap: 2.5
  },
  wideContent: {
    width: '100%',
    display: 'flex',
    flexDirection: 'column',
    gap: 2.5,
    alignItems: 'center'
  },
  cardsRow: {
    display: 'flex',
    flexDirection: { xs: 'column', md: 'row' },
    gap: 3,
    width: '100%',
    maxWidth: 900,
    justifyContent: 'center',
    alignSelf: 'center'
  },
  authCard: {
    flex: 1,
    maxWidth: 420
  },
  authCardContent: {
    display: 'flex',
    flexDirection: 'column',
    gap: 2.5,
    p: 4
  },
  authCardForm: {
    display: 'flex',
    flexDirection: 'column',
    gap: 2.5
  },
  passkeyCard: {
    flex: 1,
    maxWidth: 420,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center'
  },
  passkeyCardContent: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: 2,
    p: 4
  },
  passkeyButton: {
    width: 240,
    textTransform: 'none',
    py: 1,
    alignSelf: 'center'
  },
  authFooterText: {
    textAlign: 'center'
  },
  title: {
    textAlign: 'center',
    fontWeight: 500,
    mb: 1
  },
  input: {
    width: '100%',
    maxWidth: 360,
    alignSelf: 'center'
  },
  label: {
    width: '100%',
    maxWidth: 360,
    alignSelf: 'center',
    fontSize: '1rem'
  },
  userMessage: {
    width: '100%',
    maxWidth: 360,
    alignSelf: 'center'
  },
  actionButton: {
    width: 180,
    textTransform: 'none',
    py: 1,
    alignSelf: 'center'
  },
  signupStepperWrap: {
    width: '100%',
    maxWidth: 360,
    alignSelf: 'center'
  },
  signupStepper: {
    '& .MuiStepLabel-label': { typography: 'body2' }
  },
  signupWizardActions: {
    width: '100%',
    maxWidth: 360,
    alignSelf: 'center',
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    gap: 2
  },
  signupBackButton: {
    width: 'auto',
    minWidth: 100,
    textTransform: 'none',
    py: 1,
    alignSelf: 'center'
  },
  guestIcon: {
    mr: 1.5
  }
} as const

export const dashboardStyles = {
  container: {
    display: 'flex',
    minHeight: '100dvh'
  },
  drawer: {
    width: 280,
    flexShrink: 0,
    '& .MuiDrawer-paper': {
      width: 280,
      boxSizing: 'border-box',
      borderRight: 1,
      borderColor: 'divider'
    }
  },
  navHeader: {
    px: 3,
    py: 3,
    borderBottom: 1,
    borderColor: 'divider'
  },
  navList: {
    px: 1.5,
    py: 1.5,
    gap: 0.5
  },
  navItem: {
    borderRadius: 2,
    color: 'text.primary',
    '&.Mui-selected': {
      bgcolor: 'action.selected',
      fontWeight: 600
    },
    '&.Mui-selected:hover': {
      bgcolor: 'action.selected'
    }
  },
  navItemText: {
    '& .MuiTypography-root': {
      fontWeight: 500
    }
  },
  navSectionTitle: {
    '& .MuiTypography-root': {
      fontWeight: 600
    }
  },
  navSectionTitleButton: {
    mt: 1.5,
    borderRadius: 2,
    color: 'text.primary',
    '&.Mui-selected': {
      bgcolor: 'action.selected'
    },
    '&.Mui-selected:hover': {
      bgcolor: 'action.selected'
    }
  },
  navSubList: {
    px: 0
  },
  navSubItem: {
    borderRadius: 2,
    color: 'text.primary',
    pl: 4,
    '&.Mui-selected': {
      bgcolor: 'action.selected',
      fontWeight: 600
    },
    '&.Mui-selected:hover': {
      bgcolor: 'action.selected'
    }
  },
  walletIcon: {
    width: 28,
    height: 28
  },
  main: {
    flexGrow: 1,
    p: { xs: 3, md: 6 }
  },
  title: {
    fontWeight: 500
  },
  settingsRow: {
    flexDirection: 'row',
    mt: 4,
    alignItems: 'center',
    gap: 3
  },
  deleteAccountButton: {
    textTransform: 'none',
    px: 4,
    py: 1.5,
    borderRadius: 2,
    backgroundColor: '#d79393',
    color: '#1f1f1f',
    border: '2px solid #2f2f2f',
    '&:hover': {
      backgroundColor: '#ce8686'
    }
  },
  deleteAccountDescription: {
    color: 'text.primary'
  },
  /**
   * Dashboard page — Credentials block
   */
  credentialsSection: {
    mt: 4
  },
  credentialsHeadingRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 2
  },
  credentialsHeading: {
    fontWeight: 600
  },
  syncButton: {
    textTransform: 'none',
    borderRadius: 2,
    px: 1.5,
    py: 0.5
  },
  syncIcon: (syncing: boolean) =>
    ({
      transition: 'transform 0.6s linear',
      transform: syncing ? 'rotate(360deg)' : 'rotate(0deg)'
    }) as React.CSSProperties,
  credentialsGrid: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 2,
    mt: 2
  },
  /**
   * Sidebar brand row (icon + title)
   */
  navHeaderStack: {
    flexDirection: 'row',
    gap: 1.5
  },
  navBrandTitle: {
    fontWeight: 600,
    ml: 1
  },
  /**
   * Main area: page title + actions
   */
  mainToolbarStack: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  dashboardCredentialActions: {
    mt: 3,
    flexWrap: 'wrap'
  },
  addCredentialLink: {
    textTransform: 'none',
    borderRadius: 2,
    px: 2.5,
    py: 1
  },
  addCredentialForm: {
    mt: 4,
    display: 'flex',
    flexDirection: 'column',
    gap: 2,
    maxWidth: 520
  },
  addCredentialButton: {
    alignSelf: 'flex-start',
    textTransform: 'none',
    px: 4,
    py: 1,
    borderRadius: 2
  },
  acceptCredentialsList: {
    mt: 3,
    gap: 2,
    maxWidth: 520
  },
  appBarBrandLink: {
    display: 'flex',
    alignItems: 'center',
    textDecoration: 'none',
    color: 'inherit',
    flexGrow: 1,
    gap: 1.5
  }
} as const

export const credentialCardStyles = {
  title: {
    fontWeight: 700
  },
  card: {
    width: 220,
    minHeight: 160,
    display: 'flex',
    flexDirection: 'column',
    // ButtonBase centers its children; undo that so the content fills the card
    alignItems: 'stretch',
    justifyContent: 'flex-start',
    borderRadius: 3
  },
  cardContent: {
    flexGrow: 1,
    position: 'relative',
    pb: '16px !important',
    display: 'flex',
    flexDirection: 'column'
  },
  description: {
    overflow: 'hidden',
    display: '-webkit-box',
    WebkitLineClamp: 3,
    WebkitBoxOrient: 'vertical'
  },
  cardStatusBadge: {
    mt: 'auto',
    pt: 1
  },
  badge: {
    position: 'absolute',
    bottom: 12,
    right: 12,
    color: 'text.disabled'
  }
} as const

export const loadingSpinnerStyles = {
  display: 'flex',
  justifyContent: 'center',
  py: 6
} as const

export const passwordStrengthStyles = {
  wrap: {
    width: '100%'
  },
  segments: {
    gap: 0.5,
    width: '100%'
  },
  segment: {
    flex: 1,
    height: 4,
    borderRadius: 1,
    transition: 'background-color 0.2s ease'
  },
  label: {
    mt: 0.5,
    textAlign: 'right',
    minHeight: '1.25rem'
  }
} as const

export const chapiStyles = {
  page: {
    minHeight: '100dvh',
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'center',
    px: 2,
    pt: 4
  },
  card: {
    width: '100%',
    maxWidth: 480,
    display: 'flex',
    flexDirection: 'column',
    gap: 2
  },
  originChip: {
    display: 'inline-block',
    bgcolor: 'action.hover',
    px: 1,
    py: 0.25,
    borderRadius: 1,
    fontSize: '0.8rem',
    wordBreak: 'break-all' as const,
    fontFamily: 'monospace'
  },
  credentialList: {
    display: 'flex',
    flexDirection: 'column',
    gap: 1
  },
  credentialRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 1,
    p: 1.5,
    border: 1,
    borderColor: 'divider',
    borderRadius: 2
  },
  credentialInfo: {
    display: 'flex',
    flexDirection: 'column',
    gap: 0.25
  },
  credentialSummary: {
    p: 2,
    border: 1,
    borderColor: 'divider',
    borderRadius: 2
  },
  doneMessage: {
    display: 'flex',
    alignItems: 'center',
    gap: 1.5
  }
} as const

export const docsStyles = {
  content: {
    maxWidth: 780,
    mt: 2,
    '& table': { borderCollapse: 'collapse', width: '100%', my: 2 },
    '& th, & td': {
      border: '1px solid',
      borderColor: 'divider',
      px: 2,
      py: 1,
      textAlign: 'left'
    },
    '& th': { fontWeight: 600, bgcolor: 'action.hover' }
  }
} as const

export const infoBoxStyles = {
  paper: {
    borderRadius: 3
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    px: 3,
    pt: 2,
    pb: 0,
    minHeight: 48
  },
  title: {
    fontWeight: 600,
    flexGrow: 1
  },
  spacer: {
    flexGrow: 1
  },
  content: {
    px: 3,
    pt: 1,
    pb: 3
  }
} as const

export const historyStyles = {
  timestampRow: {
    mt: 0.5,
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'center',
    gap: 1
  },
  viewSourceButton: {
    textTransform: 'none' as const,
    minWidth: 'auto',
    px: 1
  }
} as const

export const storageStyles = {
  /**
   * Top toolbar showing the connected remote space and export action.
   */
  storageToolbar: {
    mt: 3,
    p: 2.5,
    borderRadius: 3
  },
  connectedRow: {
    alignItems: { md: 'center' }
  },
  connectedLabel: {
    fontWeight: 600
  },
  connectedLink: {
    fontSize: 16,
    wordBreak: 'break-all',
    color: 'text.secondary'
  },

  quotaCard: {
    mt: 3,
    p: 2.5,
    borderRadius: 3
  },
  quotaCardHeader: {
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 2
  },
  quotaTitleIcon: {
    display: 'flex',
    alignItems: 'center',
    lineHeight: 0,
    color: 'text.secondary'
  },
  quotaDivider: {
    my: 2,
    borderColor: 'divider'
  },
  quotaBackendLabel: {
    display: 'block',
    color: 'text.secondary',
    fontWeight: 600,
    letterSpacing: '0.06em',
    textTransform: 'uppercase',
    fontSize: '0.6875rem'
  },
  quotaHeroAmountRow: {
    alignItems: 'baseline',
    gap: 1,
    mt: 0.5
  },
  quotaHeroAmount: {
    fontSize: '2.25rem',
    fontWeight: 700,
    lineHeight: 1,
    letterSpacing: '-0.03em',
    fontVariantNumeric: 'tabular-nums'
  },
  quotaHeroMeta: {
    color: 'text.secondary',
    fontSize: '0.9375rem',
    fontWeight: 400
  },
  quotaLimitedSummary: {
    fontVariantNumeric: 'tabular-nums'
  },
  quotaStatusBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 0.5,
    px: 1.25,
    py: 0.375,
    borderRadius: 999,
    border: '1px solid',
    flexShrink: 0
  },
  quotaStatusBadgeLabel: {
    fontWeight: 700,
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
    lineHeight: 1.2
  },
  quotaBadgeOk: {
    color: 'success.main',
    borderColor: 'success.main'
  },
  quotaBadgeWarning: {
    color: 'warning.main',
    borderColor: 'warning.main'
  },
  quotaBadgeError: {
    color: 'error.main',
    borderColor: 'error.main'
  },
  quotaBadgeUnlimited: {
    color: 'success.main',
    borderColor: 'success.main'
  },
  quotaUnlimitedSymbol: {
    fontWeight: 700,
    fontSize: '0.875rem',
    lineHeight: 1
  },
  quotaBar: {
    height: 6,
    borderRadius: 999,
    backgroundColor: 'action.hover'
  },
  quotaCollectionList: {
    pt: 0.25
  },
  quotaCollectionRow: {
    alignItems: 'center',
    gap: 1.25,
    minHeight: 28
  },
  quotaCollectionIcon: {
    display: 'flex',
    alignItems: 'center',
    lineHeight: 0,
    color: 'text.secondary',
    flexShrink: 0
  },
  quotaCollectionName: {
    color: 'text.secondary',
    flex: '0 1 auto',
    minWidth: 0,
    fontSize: '0.8125rem',
    maxWidth: '46%'
  },
  quotaCollectionValueWrap: {
    flex: 1,
    minWidth: 0,
    display: 'flex',
    alignItems: 'baseline',
    justifyContent: 'flex-end',
    gap: 0.375,
    fontVariantNumeric: 'tabular-nums',
    whiteSpace: 'nowrap'
  },
  quotaCollectionValueAmount: {
    fontWeight: 700,
    fontSize: '1.125rem',
    lineHeight: 1,
    letterSpacing: '-0.02em',
    color: 'text.primary'
  },
  quotaCollectionValueUnit: {
    fontWeight: 600,
    fontSize: '0.875rem',
    color: 'text.secondary'
  },
  quotaCollectionValueOf: {
    mx: 0.25,
    fontSize: '0.8125rem',
    color: 'text.disabled'
  },
  quotaCollectionValueCapacity: {
    fontWeight: 500,
    fontSize: '0.875rem',
    color: 'text.secondary'
  },
  quotaMeasuredRow: {
    alignItems: 'center',
    pt: 0.5
  },
  quotaMeasuredIcon: {
    display: 'flex',
    alignItems: 'center',
    lineHeight: 0,
    color: 'text.disabled'
  },

  /**
   * Section header (e.g. "Collections") + secondary description line.
   */
  sectionHeader: {
    mt: 6
  },
  sectionHeading: {
    fontWeight: 600
  },
  sectionDescription: {
    mt: 0.5,
    color: 'text.secondary'
  },

  /**
   * Reusable button sizing tokens, kept here to standardize toolbar actions.
   */
  buttonTextLeft: {
    textTransform: 'none',
    justifyContent: 'flex-start',
    textAlign: 'left'
  },
  buttonSize: {
    topAction: { minWidth: 132, height: 42, px: 2 }
  },

  /**
   * Collections overview — vertical list of folder rows (Finder-like).
   */
  collectionsWrap: {
    mt: 3,
    maxWidth: 1200
  },
  collectionsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: 1,
    width: '100%'
  },
  folderCard: {
    borderRadius: 2,
    transition: 'border-color 120ms ease, box-shadow 120ms ease',
    '&:hover': {
      borderColor: 'text.primary'
    }
  },
  folderCardAction: {
    px: 2,
    py: 1.5,
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'center',
    gap: 2,
    width: '100%',
    justifyContent: 'flex-start'
  },
  folderCardHeader: {
    alignItems: 'center',
    flex: 1,
    minWidth: 0
  },
  folderCardBody: {
    minWidth: 0,
    flexGrow: 1
  },
  folderIcon: {
    fontSize: 28,
    color: '#f4b400',
    display: 'flex',
    alignItems: 'center',
    flexShrink: 0
  },
  publicAccessMeta: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 0.25,
    color: 'success.main',
    verticalAlign: 'middle'
  },
  publicAccessMetaIcon: {
    display: 'flex',
    alignItems: 'center',
    lineHeight: 0
  },
  publicAccessMetaLabel: {
    fontSize: '0.8rem',
    fontWeight: 600,
    color: 'inherit'
  },
  folderMetaPublic: {
    display: 'inline',
    whiteSpace: 'nowrap'
  },
  encryptedAccessMeta: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 0.25,
    color: 'info.main',
    verticalAlign: 'middle'
  },
  encryptedAccessMetaIcon: {
    display: 'flex',
    alignItems: 'center',
    lineHeight: 0
  },
  encryptedAccessMetaLabel: {
    fontSize: '0.8rem',
    fontWeight: 600,
    color: 'inherit'
  },
  folderMetaEncrypted: {
    display: 'inline',
    whiteSpace: 'nowrap'
  },
  folderName: {
    fontWeight: 600,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap'
  },
  folderMeta: {
    color: 'text.secondary'
  },
  folderCount: {
    color: 'text.secondary',
    flexShrink: 0,
    ml: 'auto'
  },

  /**
   * Collection contents page — header + file table.
   */
  contentsWrap: {
    mt: 3,
    maxWidth: 1200,
    display: 'flex',
    flexDirection: 'column',
    gap: 2
  },
  backToStorageButton: {
    alignSelf: 'flex-start',
    textTransform: 'none',
    px: 0,
    minHeight: 0
  },
  contentsTitleRow: {
    alignItems: 'center'
  },
  contentsTitleIcon: {
    fontSize: 32,
    color: '#f4b400',
    display: 'flex',
    alignItems: 'center'
  },
  contentsTitle: {
    fontWeight: 600,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap'
  },
  contentsSubtitle: {
    color: 'text.secondary'
  },
  contentsBody: {
    mt: 1
  },

  /**
   * File/resource table.
   */
  resourceTableContainer: {
    border: 1,
    borderColor: 'divider',
    borderRadius: 2,
    overflow: 'hidden'
  },
  resourceTable: {
    minWidth: 540
  },
  resourceHeaderCell: {
    fontWeight: 600,
    color: 'text.secondary',
    bgcolor: 'action.hover'
  },
  resourceRow: {
    cursor: 'default'
  },
  resourceNameCell: {
    maxWidth: 480
  },
  resourceNameInner: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: 1.25,
    minWidth: 0
  },
  resourceNameBlock: {
    display: 'flex',
    flexDirection: 'column',
    gap: 0.25,
    minWidth: 0
  },
  resourceFileIcon: {
    fontSize: 22,
    color: 'text.secondary',
    display: 'flex',
    alignItems: 'center',
    flexShrink: 0
  },
  resourceNameText: {
    fontWeight: 500,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    minWidth: 0
  },
  resourceTypeCell: {
    whiteSpace: 'nowrap'
  },
  resourceTypeChip: {
    fontWeight: 500
  },
  resourceModifiedCell: {
    whiteSpace: 'nowrap'
  },

  /**
   * Reusable empty state surface.
   */
  emptyState: {
    py: 5,
    px: 3,
    textAlign: 'center',
    border: '1px dashed',
    borderColor: 'divider',
    borderRadius: 2,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: 0.5
  },
  emptyStateIcon: {
    fontSize: 48,
    color: 'text.disabled',
    display: 'flex',
    alignItems: 'center'
  },
  emptyStateTitle: {
    fontWeight: 600
  },
  emptyStateDescription: {
    color: 'text.secondary',
    maxWidth: 420
  },

  /**
   * Inline loading/error text.
   */
  statusText: {
    color: 'text.secondary'
  },
  errorText: {
    color: 'error.main'
  },

  /**
   * Verifiable Credential resource detail (collection file view).
   */
  resourceDetailWrap: {
    mt: 3,
    maxWidth: 1200,
    display: 'flex',
    flexDirection: 'column',
    gap: 2
  },
  resourceDetailId: {
    fontWeight: 600,
    fontFamily: 'monospace',
    fontSize: { xs: '0.95rem', sm: '1.1rem' },
    wordBreak: 'break-all',
    lineHeight: 1.35
  },
  vcPreviewCard: {
    borderRadius: 2,
    overflow: 'hidden'
  },
  vcPreviewCardInner: {
    p: { xs: 2, sm: 2.5 },
    alignItems: { sm: 'flex-start' }
  },
  vcPreviewMain: {
    flex: 1,
    minWidth: 0
  },
  vcPreviewTitle: {
    fontWeight: 600,
    mb: 0.5
  },
  vcPreviewPublicMeta: {
    mb: 0.5
  },
  vcPreviewDescription: {
    whiteSpace: 'pre-wrap',
    lineHeight: 1.5
  },
  vcPreviewActions: {
    flexShrink: 0,
    flexWrap: 'wrap',
    justifyContent: { xs: 'flex-start', sm: 'flex-end' }
  },
  vcPreviewActionButton: {
    textTransform: 'none',
    whiteSpace: 'nowrap'
  }
} as const

export const contactDetailStyles = {
  card: {
    mt: 3,
    maxWidth: 560,
    borderRadius: 3
  },
  cardContent: {
    p: 3
  },
  headerRow: {
    alignItems: 'center'
  },
  avatar: {
    width: 64,
    height: 64,
    fontSize: '1.25rem',
    fontWeight: 600
  },
  name: {
    fontWeight: 600
  },
  actions: {
    mt: 3
  },
  actionButton: {
    textTransform: 'none'
  }
} as const

export const notFoundStyles = {
  page: {
    minHeight: '100dvh',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 2,
    px: 2
  }
} as const
