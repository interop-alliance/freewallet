export const authStyles = {
  page: {
    minHeight: '100dvh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    px: 2
  },
  content: {
    width: '100%',
    maxWidth: 480,
    display: 'flex',
    flexDirection: 'column',
    gap: 2.5
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
  deleteCredentialButton: {
    mt: 3,
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
  /** Dashboard page — Credentials block */
  credentialsSection: {
    mt: 4
  },
  credentialsHeading: {
    fontWeight: 600
  },
  credentialsGrid: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 2,
    mt: 2
  },
  /** Sidebar brand row (icon + title) */
  navHeaderStack: {
    flexDirection: 'row',
    gap: 1.5
  },
  navBrandTitle: {
    fontWeight: 600
  },
  /** Main area: page title + actions */
  mainToolbarStack: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  addCredentialLink: {
    mt: 3,
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
  }
} as const

export const credentialDetailStyles = {
  wrapper: {
    mt: 3,
    width: '100%',
    maxWidth: { xs: '100%', md: 820 }
  },
  title: {
    fontWeight: 600,
    fontSize: { xs: '1.35rem', sm: '1.6rem', md: '2rem' },
    wordBreak: 'break-word' as const,
    mb: 2
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

export const credentialCardStyles = {
  title: {
    fontWeight: 700
  },
  card: {
    width: 220,
    minHeight: 160,
    display: 'flex',
    flexDirection: 'column',
    borderRadius: 3
  },
  cardContent: {
    flexGrow: 1,
    position: 'relative',
    pb: '16px !important'
  },
  description: {
    overflow: 'hidden',
    display: '-webkit-box',
    WebkitLineClamp: 3,
    WebkitBoxOrient: 'vertical'
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
