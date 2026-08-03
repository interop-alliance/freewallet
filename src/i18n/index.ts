import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import en from './locales/en.json'
import es from './locales/es.json'
import {
  detectUiLanguage,
  readStoredUiLanguage,
  supportedUiLanguageCodes
} from './uiLanguages'

// An explicit choice from the language selector (persisted in localStorage)
// always wins; only a first-ever visit falls through to browser detection.
const initialLanguage =
  readStoredUiLanguage() ?? detectUiLanguage(navigator.languages)

void i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    es: { translation: es }
  },
  lng: initialLanguage,
  fallbackLng: 'en',
  supportedLngs: supportedUiLanguageCodes(),
  interpolation: {
    escapeValue: false
  }
})

export default i18n
