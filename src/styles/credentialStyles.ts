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
    borderRadius: '10px',
    boxShadow: '0px 15px 30px rgba(6,16,36,0.13)',
    overflow: 'hidden'
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
