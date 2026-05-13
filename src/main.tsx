import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { HashRouter } from 'react-router'
import { InfoBoxProvider } from '@/context/InfoBoxProvider'
import { FreewalletThemeProvider } from '@/components/FreewalletThemeProvider'
import './index.css'
import App from './App'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <FreewalletThemeProvider>
      <HashRouter>
        <InfoBoxProvider>
          <App />
        </InfoBoxProvider>
      </HashRouter>
    </FreewalletThemeProvider>
  </StrictMode>
)
