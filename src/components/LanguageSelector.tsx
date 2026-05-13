import FormControl from '@mui/material/FormControl'
import InputLabel from '@mui/material/InputLabel'
import MenuItem from '@mui/material/MenuItem'
import Select from '@mui/material/Select'
import { useId } from 'react'
import { useTranslation } from 'react-i18next'
import { UI_LANGUAGES, languageOptionLabel, normalizeToUiLanguageCode, type UiLanguageCode } from '@/i18n/uiLanguages'
import { languageSelectorStyles } from '@/styles/languageSelectorStyles'

type LanguageSelectorProps = {
  /** Use a section heading in the parent instead of the floating label. */
  showLabel?: boolean
}

export function LanguageSelector({ showLabel = true }: LanguageSelectorProps) {
  const reactId = useId()
  const labelId = `${reactId}-language-label`
  const selectId = `${reactId}-language-select`
  const { t, i18n } = useTranslation()
  const label = t('common.language')

  return (
    <FormControl size="small" sx={languageSelectorStyles.compactForm}>
      {showLabel ? <InputLabel id={labelId}>{label}</InputLabel> : null}
      <Select<UiLanguageCode>
        labelId={showLabel ? labelId : undefined}
        id={selectId}
        {...(showLabel ? { label } : {})}
        value={normalizeToUiLanguageCode(i18n.language)}
        renderValue={(value: UiLanguageCode) => languageOptionLabel(value)}
        onChange={e => void i18n.changeLanguage(e.target.value)}
        inputProps={showLabel ? undefined : { 'aria-label': label }}
        MenuProps={{
          slotProps: {
            paper: { sx: languageSelectorStyles.compactMenuPaper },
            list: { dense: true },
          },
        }}
      >
        {UI_LANGUAGES.map(({ code }) => (
          <MenuItem dense key={code} value={code}>
            {languageOptionLabel(code)}
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  )
}
