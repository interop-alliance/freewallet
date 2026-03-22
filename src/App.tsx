import { Route, Routes } from 'react-router'
import { DashboardPage } from '@/pages/DashboardPage.tsx'
import { GuestLoginPage } from '@/pages/GuestLoginPage.tsx'
import { LandingPage } from '@/pages/LandingPage.tsx'
import { LoginPage } from '@/pages/LoginPage.tsx'
import { SignupPage } from '@/pages/SignupPage.tsx'
import { ProtectedRoute } from '@/components/ProtectedRoute.tsx'

function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/signup" element={<SignupPage />} />
      <Route path="/guest-login" element={<GuestLoginPage />} />

      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={<DashboardPage />} />
      </Route>
    </Routes>
  )
}

export default App
