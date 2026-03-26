import { Route, Routes } from 'react-router'
import { DashboardPage } from '@/pages/dashboard/DashboardPage'
import { GuestLoginPage } from '@/pages/auth/GuestLoginPage'
import { LandingPage } from '@/pages/LandingPage'
import { LoginPage } from '@/pages/auth/LoginPage'
import { SignupPage } from '@/pages/auth/SignupPage'
import { ProtectedRoute } from '@/components/ProtectedRoute'
import { HistoryPage } from '@/pages/dashboard/HistoryPage'
import { SettingsPage } from '@/pages/dashboard/SettingsPage'
import { CredentialDetailPage } from '@/pages/dashboard/CredentialDetailPage'
import { NotFoundPage } from '@/pages/NotFoundPage'

function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/signup" element={<SignupPage />} />
      <Route path="/guest-login" element={<GuestLoginPage />} />

      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/credential/:cid" element={<CredentialDetailPage />} />
      </Route>

      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}

export default App
