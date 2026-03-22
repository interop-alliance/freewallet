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
    maxWidth: 360
  },
  actionButton: {
    width: 180,
    textTransform: 'none',
    py: 1
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
  }
} as const
