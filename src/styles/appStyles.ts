import type React from 'react'
import { credentialDetailStyles } from './credentialStyles'

// Shared folder accent color (used by folder and collection icons)
const folderAccentColor = '#f4b400'

export const authStyles = {
  page: {
    minHeight: '100dvh',
    display: 'flex',
    flexDirection: 'column'
  },
  /**
   * Content area below the app bar: top-aligned, horizontally centered.
   */
  pageContent: {
    flex: 1,
    width: '100%',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: 3,
    px: 2,
    pt: { xs: 4, sm: 6 },
    pb: 6
  },
  content: {
    width: '100%',
    maxWidth: 480,
    display: 'flex',
    flexDirection: 'column',
    gap: 2.5
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
    fontWeight: 500
  },
  navSectionTitle: {
    fontWeight: 600
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
  /**
   * App bar: labeled language/theme controls
   */
  navControlGroup: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 0.75
  },
  navControlLabel: {
    color: 'text.secondary',
    fontSize: '0.6875rem',
    whiteSpace: 'nowrap'
  },
  main: {
    flexGrow: 1,
    p: { xs: 3, md: 6 }
  },
  title: {
    fontWeight: 600
  },
  settingsRow: {
    flexDirection: 'row',
    mt: 4,
    alignItems: 'center',
    gap: 3
  },
  deleteAccountDescription: {
    color: 'text.primary'
  },
  sharedRecipientDid: {
    fontFamily: 'monospace',
    wordBreak: 'break-all' as const
  },
  applicationsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: 1
  },
  applicationsAppCard: {
    flexDirection: { xs: 'column', sm: 'row' },
    alignItems: { xs: 'flex-start', sm: 'center' },
    justifyContent: 'space-between',
    gap: 1,
    p: 1.5,
    border: 1,
    borderColor: 'divider',
    borderRadius: 2
  },
  applicationsRowChevron: {
    display: 'flex',
    alignItems: 'center',
    fontSize: 22,
    color: 'text.secondary',
    flexShrink: 0,
    ml: 'auto'
  },
  applicationsAppMeta: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 2,
    flexWrap: 'wrap' as const,
    flexShrink: 0
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
    fontFamily: 'monospace',
    height: 'auto',
    '& .MuiChip-label': {
      whiteSpace: 'normal',
      wordBreak: 'break-all' as const,
      py: 0.375
    }
  },
  credentialList: {
    display: 'flex',
    flexDirection: 'column',
    gap: 1
  },
  credentialRow: {
    border: 1,
    borderColor: 'divider',
    borderRadius: 2
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
  },
  sourceToggle: {
    color: 'text.secondary',
    px: 0,
    minWidth: 0,
    justifyContent: 'flex-start'
  },
  sourceCodeBlock: {
    ...credentialDetailStyles.codeBlock,
    mt: 1,
    p: 1.5,
    fontSize: 12,
    maxHeight: '40vh'
  }
} as const

export const docsStyles = {
  content: {
    maxWidth: 780,
    mt: 2,
    '& table': { borderCollapse: 'collapse', width: '100%', my: 2 },
    '& th, & td': {
      border: 1,
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
  toolbar: {
    mt: 3,
    display: 'flex',
    flexDirection: { xs: 'column', sm: 'row' },
    alignItems: { sm: 'center' },
    justifyContent: 'space-between',
    gap: 2
  },
  tabs: {
    minHeight: 'auto'
  },
  searchField: {
    width: { xs: '100%', sm: 260 }
  },
  timestampRow: {
    mt: 0.5,
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'center',
    gap: 1
  },
  viewSourceButton: {
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
    width: '100%',
    display: 'flex',
    flexDirection: 'column',
    gap: 1
  },
  collectionGroupHeading: {
    fontWeight: 600,
    mb: 1
  },
  collectionGroupHeadingMuted: {
    fontWeight: 600,
    mb: 1,
    color: 'text.secondary'
  },
  collectionGroupNote: {
    color: 'text.secondary',
    mt: -0.5,
    mb: 1
  },
  folderCard: {
    px: 2,
    py: 1.5,
    gap: 2,
    border: 1,
    borderColor: 'divider',
    borderRadius: 2
  },
  systemFolderCard: {
    px: 2,
    py: 1.5,
    gap: 2,
    border: 1,
    borderColor: 'divider',
    borderRadius: 2,
    bgcolor: 'action.hover',
    // resting bg already sits on action.hover, so the default hover tint
    // would be invisible on these rows
    '&:hover': {
      bgcolor: 'action.selected'
    }
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
    position: 'relative',
    fontSize: 28,
    color: folderAccentColor,
    display: 'flex',
    alignItems: 'center',
    flexShrink: 0
  },
  // small gear badge overlaid on the folder icon of system collection cards
  systemFolderIconBadge: {
    position: 'absolute',
    right: -4,
    bottom: 0,
    display: 'flex',
    fontSize: 14,
    color: 'text.secondary',
    backgroundColor: 'background.paper',
    borderRadius: '50%'
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
  folderId: {
    fontFamily: 'monospace',
    fontSize: '0.8em',
    fontWeight: 400,
    color: 'text.secondary'
  },
  folderMeta: {
    color: 'text.secondary'
  },
  folderCount: {
    color: 'text.secondary',
    flexShrink: 0,
    ml: 'auto'
  },
  folderChevron: {
    display: 'flex',
    alignItems: 'center',
    fontSize: 22,
    color: 'text.secondary',
    flexShrink: 0
  },
  folderUsage: {
    color: 'text.secondary',
    flexShrink: 0,
    minWidth: 64,
    textAlign: 'right',
    fontVariantNumeric: 'tabular-nums'
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
    px: 0,
    minHeight: 0
  },
  contentsTitleRow: {
    alignItems: 'center'
  },
  contentsTitleIcon: {
    fontSize: 32,
    color: folderAccentColor,
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
  didList: {
    listStyle: 'none',
    m: 0,
    p: 0,
    mt: 0.5,
    display: 'flex',
    flexDirection: 'column',
    gap: 1
  },
  didListItem: {
    alignItems: 'flex-start',
    gap: 1,
    p: 1,
    border: 1,
    borderColor: 'divider',
    borderRadius: 2
  },
  didListIndex: {
    fontWeight: 600,
    color: 'text.secondary',
    flexShrink: 0
  },
  didListValue: {
    fontFamily: 'monospace',
    wordBreak: 'break-all' as const,
    flexGrow: 1
  }
} as const

export const contactFormStyles = {
  form: {
    mt: 3,
    display: 'flex',
    flexDirection: 'column',
    gap: 2,
    maxWidth: 520
  },
  rowsSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: 1
  },
  rowGroup: {
    alignItems: 'center'
  },
  labelInput: {
    width: 140,
    flexShrink: 0
  },
  addRowButton: {
    alignSelf: 'flex-start',
    textTransform: 'none'
  },
  saveButton: {
    textTransform: 'none',
    px: 4,
    py: 1,
    borderRadius: 2
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
