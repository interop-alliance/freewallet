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
  cardDeleteIcon: {
    position: 'absolute',
    top: 25,
    right: 25,
    zIndex: 1,
    padding: 0.5,
    color: 'text.secondary',
    '&:hover': {
      color: 'error.main',
      backgroundColor: 'action.hover'
    }
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
  verificationText: {
    minWidth: 0,
    flex: 1
  },
  verificationLabel: {
    fontWeight: 600
  },
  /** VerifierPlus-style status pill (card 1) */
  vpStatusBadge: {
    display: 'inline-flex',
    flexDirection: 'row',
    alignItems: 'center',
    gap: 0.75,
    px: 1.5,
    py: 0.5,
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
  vpStatusSpinner: {
    flexShrink: 0
  },
  vpStatusIconWrap: {
    display: 'flex',
    lineHeight: 0
  },
  vpStatusBadgeLabel: {
    fontWeight: 700,
    fontSize: '0.8125rem'
  },
  /** VerifierPlus verification card (card 2) */
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
    backgroundColor: 'grey.100',
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
    alignItems: 'center',
    justifyContent: 'flex-start',
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
  }
} as const
