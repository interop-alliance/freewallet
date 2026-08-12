/**
 * The wallet's one search box: a small text field with a magnifier
 * adornment, shared by every page that filters an in-memory list
 * (credentials, history, contacts, ...) so the three of them cannot drift
 * apart visually.
 */
import Box from '@mui/material/Box'
import TextField from '@mui/material/TextField'
import type { SxProps, Theme } from '@mui/material/styles'
import { MdSearch } from 'react-icons/md'
import { searchFieldStyles } from '@/styles/appStyles'

/**
 * @param options {object}
 * @param options.value {string} - The current query text.
 * @param options.onChange {(value: string) => void} - Receives the new query
 *   text (not the DOM event).
 * @param options.placeholder {string} - Already-translated placeholder.
 * @param [options.sx] {SxProps<Theme>} - Extra styles, merged over the
 *   shared base.
 */
export function SearchField({
  value,
  onChange,
  placeholder,
  sx
}: {
  value: string
  onChange: (value: string) => void
  placeholder: string
  sx?: SxProps<Theme>
}) {
  return (
    <TextField
      size="small"
      value={value}
      onChange={event => onChange(event.target.value)}
      placeholder={placeholder}
      sx={[searchFieldStyles, ...(Array.isArray(sx) ? sx : [sx])]}
      slotProps={{
        input: {
          startAdornment: (
            <Box
              component="span"
              sx={{ display: 'flex', color: 'text.secondary', mr: 1 }}
            >
              <MdSearch />
            </Box>
          )
        }
      }}
    />
  )
}
