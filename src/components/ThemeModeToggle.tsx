import IconButton from '@mui/material/IconButton'
import Tooltip from '@mui/material/Tooltip'
import { MdDarkMode, MdLightMode } from 'react-icons/md'
import { useTranslation } from 'react-i18next'
import { useAppTheme } from '@/context/appThemeContext'

/**
 * Icon button that toggles the active theme between light and dark mode.
 */
export function ThemeModeToggle() {
  const { mode, toggleMode } = useAppTheme()
  const { t } = useTranslation()
  const label =
    mode === 'dark'
      ? t('common.switchToLightMode')
      : t('common.switchToDarkMode')

  return (
    <Tooltip title={label}>
      <IconButton size="small" onClick={toggleMode} aria-label={label}>
        {mode === 'dark' ? <MdLightMode size={18} /> : <MdDarkMode size={18} />}
      </IconButton>
    </Tooltip>
  )
}
