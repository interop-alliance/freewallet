import FormControl from '@mui/material/FormControl'
import InputLabel from '@mui/material/InputLabel'
import MenuItem from '@mui/material/MenuItem'
import Select from '@mui/material/Select'
import { useId } from 'react'
import { useTranslation } from 'react-i18next'
import { useAppTheme } from '@/context/appThemeContext'
import { APP_THEME_IDS, type AppThemeId } from '@/themes/appTheme'
import { languageSelectorStyles } from '@/styles/languageSelectorStyles'

function themeOptionLabel(
  themeId: AppThemeId,
  t: (key: string) => string
): string {
  return t(`common.themes.${themeId}`)
}

export function ThemePicker({
  showLabel = true
}: {
  /**
   * Use a section heading in the parent instead of the floating label.
   */
  showLabel?: boolean
}) {
  const { themeId, setThemeId } = useAppTheme()
  const reactId = useId()
  const labelId = `${reactId}-theme-label`
  const selectId = `${reactId}-theme-select`
  const { t } = useTranslation()
  const label = t('common.theme')

  return (
    <FormControl size="small" sx={languageSelectorStyles.compactForm}>
      {showLabel ? <InputLabel id={labelId}>{label}</InputLabel> : null}
      <Select<AppThemeId>
        labelId={showLabel ? labelId : undefined}
        id={selectId}
        {...(showLabel ? { label } : {})}
        value={themeId}
        renderValue={(value: AppThemeId) => themeOptionLabel(value, t)}
        onChange={event => setThemeId(event.target.value as AppThemeId)}
        inputProps={showLabel ? undefined : { 'aria-label': label }}
        MenuProps={{
          slotProps: {
            paper: { sx: languageSelectorStyles.compactMenuPaper },
            list: { dense: true }
          }
        }}
      >
        {APP_THEME_IDS.map(id => (
          <MenuItem dense key={id} value={id}>
            {themeOptionLabel(id, t)}
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  )
}
