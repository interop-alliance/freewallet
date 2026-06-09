export const credentialDetailStyles = {
  wrapper: {
    mt: 3,
    width: '100%',
    maxWidth: { xs: '100%', md: 820 }
  },
  codeBlock: {
    p: { xs: 1.5, sm: 2, md: 2.5 },
    borderRadius: 2,
    backgroundColor: '#111',
    color: '#e5e7eb',
    overflowX: 'auto',
    fontSize: { xs: 12, sm: 13, md: 14 },
    lineHeight: 1.6,
    whiteSpace: 'pre-wrap' as const,
    wordBreak: 'break-all' as const,
    maxHeight: { xs: '60vh', md: '70vh' },
    overflowY: 'auto',
    m: 0
  }
} as const

export const credentialDetailCardStyles = {
  card: {
    position: 'relative',
    borderRadius: '10px',
    boxShadow: '0px 15px 30px rgba(6,16,36,0.13)',
    overflow: 'hidden'
  },
  cardActions: {
    justifyContent: 'flex-end',
    flexGrow: 1,
    width: { xs: '100%', md: 'auto' },
    minWidth: 0,
    maxWidth: '100%'
  },
  actionsRow: {
    width: '100%',
    minWidth: 0,
    mb: 1
  },
  actionsCluster: {
    display: 'flex',
    flexDirection: { xs: 'column', md: 'row' },
    alignItems: { xs: 'stretch', md: 'center' },
    justifyContent: 'flex-end',
    gap: 1,
    width: { xs: '100%', md: 'auto' },
    minWidth: 0,
    maxWidth: '100%'
  },
  actionButtonsRow: {
    display: 'flex',
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'flex-end',
    gap: 1,
    flexShrink: 0,
    order: { md: 2 }
  },
  publicLinkOrder: {
    order: { md: 1 }
  },
  shareButton: {
    textTransform: 'none' as const,
    whiteSpace: 'nowrap' as const,
    color: 'text.secondary',
    borderColor: 'divider',
    '&:hover': {
      color: 'primary.main',
      borderColor: 'primary.main',
      backgroundColor: 'action.hover'
    }
  },
  shareActiveButton: {
    textTransform: 'none' as const,
    whiteSpace: 'nowrap' as const,
    color: 'primary.main',
    borderColor: 'primary.main',
    '&:hover': {
      color: 'warning.main',
      borderColor: 'warning.main',
      backgroundColor: 'action.hover'
    }
  },
  deleteButton: {
    textTransform: 'none' as const,
    whiteSpace: 'nowrap' as const,
    color: 'text.secondary',
    borderColor: 'divider',
    '&:hover': {
      color: 'error.main',
      borderColor: 'error.main',
      backgroundColor: 'action.hover'
    }
  },
  publicLinkBox: {
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'center',
    gap: 0.75,
    width: { xs: '100%', sm: 'auto' },
    maxWidth: '100%',
    minWidth: 0,
    flexShrink: 1,
    px: { xs: 1, sm: 1.25 },
    py: 0.5,
    borderRadius: 1.5,
    backgroundColor: 'action.hover',
    border: 1,
    borderColor: 'divider'
  },
  publicLinkIcon: {
    color: 'success.main',
    display: 'flex',
    flexShrink: 0,
    lineHeight: 0
  },
  publicLinkLabel: {
    flexShrink: 0,
    fontSize: '0.75rem',
    color: 'text.secondary',
    whiteSpace: 'nowrap' as const
  },
  publicLinkUrl: {
    flex: 1,
    minWidth: 0,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
    fontSize: '0.75rem',
    color: 'primary.main'
  },
  topCard: {
    px: { xs: 2, md: 3 },
    py: 3,
    borderBottom: 1,
    borderColor: 'divider'
  },
  achievementRow: {
    display: 'flex',
    flexDirection: 'row',
    gap: 2,
    alignItems: 'flex-start'
  },
  achievementImage: {
    maxHeight: 36,
    maxWidth: 36,
    height: 'auto',
    width: 'auto',
    flexShrink: 0
  },
  credentialName: {
    fontWeight: 700,
    fontSize: { xs: '1.3rem', md: '1.55rem' },
    lineHeight: 1.3
  },
  achievementType: {
    mt: 0.5
  },
  mainCard: {
    display: 'flex',
    flexDirection: { xs: 'column', md: 'row' }
  },
  secondaryColumn: {
    width: { xs: '100%', md: 300 },
    flexShrink: 0,
    px: { xs: 2, md: 3 },
    py: 3
  },
  primaryColumn: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: 3,
    px: { xs: 2, md: 3 },
    py: 3
  },
  dividerVertical: {
    display: { xs: 'none', md: 'block' }
  },
  dividerHorizontal: {
    display: { xs: 'block', md: 'none' }
  },
  markdownBody: {
    fontSize: '0.875rem',
    '& p': { mt: 0, mb: 1 },
    '& h1,& h2,& h3,& h4,& h5,& h6': { mt: 0, mb: 0.5 },
    '& ul, & ol': { pl: 3 },
    '& a': { color: 'primary.main' }
  },
  rawToggleWrapper: {
    px: 2,
    py: 1
  },
  rawToggle: {
    textTransform: 'none' as const,
    color: 'text.secondary'
  },
  alignmentName: {
    fontWeight: 600
  },
  verificationPanel: {
    mt: 0
  },
  verificationLoadingRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 1.25,
    py: 0.5
  },
  verificationSpinner: {
    flexShrink: 0
  },
  verificationRow: {
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 1.25
  },
  verificationIconSuccess: {
    color: 'success.main',
    lineHeight: 0,
    flexShrink: 0,
    pt: 0.125
  },
  verificationIconError: {
    color: 'error.main',
    lineHeight: 0,
    flexShrink: 0,
    pt: 0.125
  },
  verificationIconWarning: {
    color: 'warning.main',
    lineHeight: 0,
    flexShrink: 0,
    pt: 0.125
  },
  verificationText: {
    minWidth: 0,
    flex: 1
  },
  verificationLabel: {
    fontWeight: 600
  },
  /**
   * VerifierPlus-style status pill (card 1)
   */
  vpStatusBadge: {
    display: 'inline-flex',
    flexDirection: 'row',
    alignItems: 'center',
    gap: 0.375,
    px: 0.75,
    py: 0.125,
    borderRadius: 999,
    backgroundColor: 'action.hover'
  },
  vpStatusBadgeOk: {
    backgroundColor: 'success.light',
    color: 'success.dark',
    '& .MuiTypography-root': { color: 'success.dark' }
  },
  vpStatusBadgeError: {
    backgroundColor: 'error.light',
    color: 'error.dark',
    '& .MuiTypography-root': { color: 'black' }
  },
  vpStatusBadgeWarning: {
    backgroundColor: 'warning.light',
    color: 'warning.dark',
    '& .MuiTypography-root': { color: 'warning.dark' }
  },
  vpStatusSpinner: {
    flexShrink: 0
  },
  vpStatusIconWrap: {
    display: 'flex',
    lineHeight: 0
  },
  vpStatusBadgeLabel: {
    fontWeight: 700,
    fontSize: '0.625rem'
  },
  /**
   * VerifierPlus verification card (card 2)
   */
  vpCard: {
    px: { xs: 2, md: 3 },
    py: { xs: 2, md: 2.5 }
  },
  vpCardColumns: {
    display: 'flex',
    flexDirection: { xs: 'column', md: 'row' },
    gap: { xs: 2, md: 3 },
    alignItems: { xs: 'stretch', md: 'stretch' }
  },
  vpGrayBox: {
    flex: { md: '1 1 55%' },
    minWidth: 0,
    p: 2,
    borderRadius: 2,
    // Uses theme-aware surface (grey.100 is always light; breaks contrast in dark mode)
    backgroundColor: 'action.hover',
    border: 1,
    borderColor: 'divider'
  },
  vpGrayTitle: {
    fontWeight: 700,
    fontSize: '0.7rem',
    letterSpacing: '0.06em',
    textTransform: 'uppercase',
    color: 'text.secondary',
    display: 'block',
    mb: 1.5
  },
  vpHeadline: {
    fontWeight: 700,
    fontSize: '1rem',
    lineHeight: 1.4,
    mb: 1
  },
  vpBody: {
    lineHeight: 1.5
  },
  vpLastChecked: {
    display: 'block',
    mt: 2,
    pt: 1.5,
    borderTop: 1,
    borderColor: 'divider'
  },
  vpChecklistRow: {
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 0.75
  },
  vpSummaryColumn: {
    flex: { md: '1 1 40%' },
    minWidth: 0,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    px: { xs: 0, md: 2 },
    py: { xs: 1, md: 0 }
  },
  vpSummaryText: {
    textAlign: { xs: 'left', md: 'center' },
    maxWidth: 320
  },
  credentialStack: {
    width: '100%'
  },
  badgeRow: {
    display: 'flex',
    flexDirection: 'row',
    alignItems: { xs: 'flex-start', sm: 'center' },
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: { xs: 1.5, sm: 1 },
    mb: 2
  }
} as const

export const sectionHeaderStyles = {
  fontWeight: 700,
  fontSize: '0.7rem',
  mb: 0.25,
  display: 'block'
} as const

export const infoBlockValue = {
  wordBreak: 'break-word' as const
} as const

export const infoBlockRoot = {
  flex: 1,
  minWidth: 0
} as const

export const issuerInfoStyles = {
  header: {
    fontWeight: 700,
    fontSize: '0.7rem',
    display: 'block',
    mb: 0.5
  },
  row: {
    display: 'flex',
    flexDirection: 'row',
    gap: 1.5,
    alignItems: 'flex-start',
    mt: 0.5
  },
  avatar: {
    width: 36,
    height: 36,
    fontSize: '0.85rem',
    flexShrink: 0
  },
  infoWrapper: {
    minWidth: 0,
    overflow: 'hidden'
  },
  name: {
    fontWeight: 600
  },
  urlLink: {
    display: 'block'
  },
  registryStatus: {
    display: 'block',
    mt: 0.5
  },
  detailButton: {
    mt: 1,
    textTransform: 'none'
  }
} as const

export const issuerDetailStyles = {
  wrapper: {
    maxWidth: 720
  },
  sectionHeader: {
    fontWeight: 700,
    fontSize: '0.7rem',
    display: 'block'
  },
  registryBlock: {
    border: 1,
    borderColor: 'divider',
    borderRadius: 2,
    p: 2.5
  },
  registryTitle: {
    fontWeight: 600,
    mb: 2
  },
  registryAvatar: {
    width: 56,
    height: 56,
    mb: 2
  },
  fieldLabel: {
    display: 'block',
    fontWeight: 600,
    mb: 0.25
  }
} as const
