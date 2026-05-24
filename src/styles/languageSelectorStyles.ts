import type { SxProps, Theme } from '@mui/material/styles'

/**
 * Extra-dense select (smaller than MUI `size="small"` alone).
 */
const compactForm: SxProps<Theme> = {
  minWidth: 132,
  maxWidth: 200,
  '& .MuiOutlinedInput-root': {
    fontSize: '0.6875rem',
    lineHeight: 1.2,
    minHeight: 26,
    '& .MuiOutlinedInput-input': {
      py: '3px',
      px: 0.75,
      minHeight: 0,
    },
    '& .MuiOutlinedInput-notchedOutline': {
      '& legend': { fontSize: '0.6em' },
    },
  },
  '& .MuiInputLabel-root': {
    fontSize: '0.6875rem',
    lineHeight: 1.2,
  },
  '& .MuiSelect-icon': {
    fontSize: '0.95rem',
    right: 2,
  },
}

const compactMenuPaper: SxProps<Theme> = {
  '& .MuiMenuItem-root': {
    fontSize: '0.6875rem',
    minHeight: 28,
    py: 0.25,
  },
}

export const languageSelectorStyles = {
  compactForm,
  compactMenuPaper,
}
