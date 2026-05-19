import type { Theme } from '@mui/material/styles'

export const credentialJsonUploadStyles = {
  panel: (dragOver: boolean, disabled: boolean) => ({
    p: { xs: 3, sm: 4 },
    minHeight: 200,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: 3,
    border: '2px dashed',
    borderColor: dragOver ? 'primary.main' : 'divider',
    bgcolor: dragOver ? 'action.hover' : 'background.paper',
    cursor: disabled ? 'not-allowed' : 'pointer',
    opacity: disabled ? 0.6 : 1,
    transition: (theme: Theme) =>
      theme.transitions.create(['border-color', 'background-color', 'box-shadow'], {
        duration: theme.transitions.duration.short
      }),
    boxShadow: dragOver ? 2 : 0,
    '&:focus-visible': {
      outline: '2px solid',
      outlineColor: 'primary.main',
      outlineOffset: 2
    }
  }),
  panelContent: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: 1.5,
    textAlign: 'center',
    pointerEvents: 'none',
    '& button': {
      pointerEvents: 'auto'
    }
  },
  iconWrap: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: 72,
    height: 72,
    borderRadius: '50%',
    bgcolor: 'action.selected',
    color: 'primary.main'
  },
  browseButton: {
    mt: 0.5,
    textTransform: 'none',
    fontWeight: 600,
    px: 4,
    borderRadius: 2
  },
  orUploadDivider: {
    display: 'flex',
    alignItems: 'center',
    gap: 2,
    color: 'text.secondary',
    '&::before, &::after': {
      content: '""',
      flex: 1,
      borderBottom: '1px solid',
      borderColor: 'divider'
    }
  }
}
