/**
 * The decrypted / stored-envelope source switch shown over an encrypted
 * resource's code block, shared by the collection contents page's snippet
 * dialog and the single-resource page.
 */
import ToggleButton from '@mui/material/ToggleButton'
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup'
import type { SxProps, Theme } from '@mui/material/styles'
import { useTranslation } from 'react-i18next'

/**
 * Renders the two-way source-view toggle.
 *
 * @param options {object}
 * @param options.value {'decrypted' | 'envelope'}   the shown source
 * @param options.onChange {Function}   called with the newly picked source
 * @param [options.sx] {SxProps<Theme>}   layout overrides for the group
 * @returns {JSX.Element}
 */
export function SourceViewToggle({
  value,
  onChange,
  sx
}: {
  value: 'decrypted' | 'envelope'
  onChange: (view: 'decrypted' | 'envelope') => void
  sx?: SxProps<Theme>
}) {
  const { t } = useTranslation()

  return (
    <ToggleButtonGroup
      size="small"
      exclusive
      value={value}
      onChange={(_event, view: 'decrypted' | 'envelope' | null) => {
        if (view) {
          onChange(view)
        }
      }}
      sx={sx}
    >
      <ToggleButton value="decrypted">
        {t('storage.viewDecrypted')}
      </ToggleButton>
      <ToggleButton value="envelope">{t('storage.viewEnvelope')}</ToggleButton>
    </ToggleButtonGroup>
  )
}
